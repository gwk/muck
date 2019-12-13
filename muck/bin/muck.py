# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck build tool.
This file was separated from __main__.py to make stack traces more consistent during testing.
'''

import shlex
from argparse import ArgumentParser, Namespace
from glob import has_magic as is_glob_pattern, iglob as walk_glob
from os import environ
from sys import argv
from typing import Any, Callable, Dict, Optional, Set

from ..constants import muck_tmp_ext
from ..ctx import Ctx
from ..db import DB
from ..logging import note
from ..paths import is_target_product
from ..pithy.ansi import RST, TXT_B, TXT_G, TXT_R
from ..pithy.filestatus import is_link, is_sticky
from ..pithy.fs import (change_dir, copy_path, is_dir, make_dirs, move_file, norm_path, path_dir, path_exists, path_ext,
  path_join, remove_path, walk_dirs, walk_paths)
from ..pithy.interactive import ExitOnKeyboardInterrupt
from ..pithy.io import errL, errSL, errZ, outL, outLL
from ..pithy.path import current_dir, path_stem, split_stem_ext
from ..pithy.path_encode import path_for_url
from ..pithy.task import runC
from ..paths import set_prod_perms
from ..server import serve_project
from ..update import ext_tools, fake_update, pat_dependencies, update_or_exit


db_name = '_muck.db'
fifo_name = '_muck.fifo'


def main() -> None:

  reserved_names = { 'muck', }
  reserved_prefixes = ('_fetch', '_muck')

  # Argument parser setup.
  # Argparse's subparser feature does not allow for a default command.
  # To work around this, we build an argument parser for each command, as well as the main one,
  # and dispatch manually based on the first argument.

  parsers:Dict[str, ArgumentParser] = {}

  def add_parser(cmd:str, fn:Callable[..., None], builds:bool, targets_dflt:Optional[bool]=None, takes_ctx:bool=True,
   **kwargs) -> ArgumentParser:
    reserved_names.add(cmd)
    parser = ArgumentParser(prog='muck ' + cmd, **kwargs)
    parser.set_defaults(cmd=cmd, fn=fn, builds=builds, targets_dflt=targets_dflt, takes_ctx=takes_ctx)
    parser.add_argument('-cd', help='change to this working directory before taking any further action.')
    parser.add_argument('-dbg', action='store_true', help='log lots of details to stderr.')
    if builds:
      parser.add_argument('-no-times', action='store_true', help='do not report process times.')
      parser.add_argument('-force', action='store_true', help='rebuild specified targets even if they are up to date.')
      parser.add_argument('-dbg-child', action='store_true',
        help='set an environment variables so that child processes log muck communication details to stderr.')
      parser.add_argument('-dbg-child-lldb', action='store_true', help='run child processes in LLDB.')
    if targets_dflt is not None:
      default = ['index.html'] if targets_dflt else None
      help_msg = f'target file names' + ("; defaults to 'index.html'." if targets_dflt else '.')
      parser.add_argument('targets', nargs='*', default=default, help=help_msg)
    parsers[cmd] = parser
    return parser

  add_parser('check-client-env', muck_client_env, builds=False, takes_ctx=False,
    description='invoke `muck check-client-env` from within a client script to check that the environment is set up correctly.')

  add_parser('clean-all', muck_clean_all, builds=False, takes_ctx=False,
    description='clean the entire project, including the build database.')

  add_parser('clean', muck_clean, builds=False, targets_dflt=False,
    description='clean the specified targets.')

  add_parser('dependents', muck_dependents, builds=False, targets_dflt=False,
    description='print the set of targets that directly depend on the specified target.')

  add_parser('deps', muck_deps, builds=True, targets_dflt=True,
    description='print targets and their dependencies as a visual hierarchy.')

  add_parser('deps-list', muck_deps_list, builds=True, targets_dflt=True,
    description='print targets and their dependencies as a list.')

  add_parser('prod-list', muck_prod_list, builds=True, targets_dflt=True,
    description='print products as a list.')

  add_parser('fake', muck_fake, builds=False, targets_dflt=False,
    description='fake the update of a dependency (use to avoid an expensive update for a trivial change).')

  create_patch = add_parser('create-patch', muck_create_patch, builds=True,
    description="create a patch; creates a new '.pat' source.",
    epilog='This command creates an empty patch called [modified].pat, and copies [original] to _build/[modified].')
  create_patch.add_argument('original', help='the target to be patched.')
  create_patch.add_argument('modified', help='the target to be produced by patching the original.')

  update_patch = add_parser('update-patch', muck_update_patch, builds=True,
    description="update a '.pat' patch.",
    epilog='The patch file will be updated with the diff between the original referenced by the patch, and _build/[modified].')
  update_patch.add_argument('patch', help='the patch to update.')

  move_to_fetched_url_parser = add_parser('move-to-fetched-url', muck_move_to_fetched_url, builds=False, takes_ctx=False,
    description="move a manually downloaded file to the '_fetch' folder.")
  move_to_fetched_url_parser.add_argument('path', help='the local file to be moved')
  move_to_fetched_url_parser.add_argument('url', help='the url from which the file was downloaded')

  publish_parser = add_parser('publish', muck_publish, builds=True, targets_dflt=True,
    description='build the specified targets, then copy to the directory specified with `-to`.')
  publish_parser.add_argument('-files', nargs='*', default=[], help='glob patterns specifying additional files to publish.')
  publish_parser.add_argument('-to', required=True, help='directory to copy files to.')

  # add `build` last so that we can describe other commands in its epilog.
  cmds_str = ', '.join(parsers)
  build_parser = add_parser('build', muck_build, builds=True, targets_dflt=True,
    description='build the specified targets.',
    epilog=f'`build` is the default subcommand; other available commands are:\n{cmds_str}.`')
  build_parser.add_argument('-serve', action='store_true',
    help='serve contents of build directory via local HTTP, and open the specified target in the browser.')


  # command dispatch.

  if len(argv) >= 2 and argv[1] in parsers:
    cmd = argv[1]
    cmd_args = argv[2:]
  else:
    cmd = 'build'
    cmd_args = argv[1:]
  parser = parsers[cmd]

  args = parser.parse_args(cmd_args)
  db_path = db_name

  if args.dbg:
    def dbg(path:str, *items:Any) -> None:
      errL('muck dbg: ', path, ': ', *items)
  else:
    def dbg(path:str, *items:Any) -> None: pass

  # Handle directory change first.
  if args.cd: change_dir(args.cd)

  proj_dir = current_dir()

  with ExitOnKeyboardInterrupt(dbg=args.dbg):

    if not args.takes_ctx:
      args.fn(args)
      return

    ctx = Ctx(
      args=args,
      db=DB(path=db_path),
      proj_dir=proj_dir,
      fifo_path=fifo_name,
      fifo_path_abs=path_join(proj_dir, fifo_name),
      reserved_names=frozenset(reserved_names),
      reserved_prefixes=reserved_prefixes,
      dbg=dbg,
      dbg_child=getattr(args, 'dbg_child', False),
      dbg_child_lldb=getattr(args, 'dbg_child_lldb', True))

    args.fn(ctx)
    #^ Fail for missing target args. We call the comamnd first, so that it can fail with a custom message.
    if args.targets_dflt is False and not args.targets:
      exit(f'muck {args.cmd}: no targets specified.')


# Commands.


def muck_client_env(args:Namespace) -> None:
  '`muck check-client-env` command.'

  if 'DYLD_INSERT_LIBRARIES' in environ:
    errL('muck check-client-env: ok.')
    exit(0)

  errZ('muck check-client-env failed: ')
  if 'MUCK_DYLD_INSERT_LIBRARIES' in environ:
    exit('DYLD_INSERT_LIBRARIES was stripped by macOS; perhaps the invoked interpreter is protected by SIP?')
  else:
    exit('the environment was not passed.')


def muck_build(ctx:Ctx) -> None:
  '`muck build` (default) command: update each specified target.'

  for target in ctx.targets:
    if not is_target_product(target):
      stem, ext = split_stem_ext(target)
      if ext in ext_tools:
        note(target, f'specified target is a source and not a product; building {stem!r}...')
        target = stem
      else:
        note(target, 'specified target is a source and not a product.')
    update_or_exit(ctx, target)
  if ctx.args.serve:
    serve_project(ctx, main_target=ctx.targets[0])


def muck_clean_all(args:Namespace) -> None:
  '`muck clean-all` command.'
  remove_path(db_name)
  for path in walk_paths('.'):
    if is_sticky(path, follow=False):
      remove_path(path)


def muck_clean(ctx:Ctx) -> None:
  '`muck clean` command.'
  targets = ctx.targets
  if not targets:
    exit('muck clean: no targets specified; did you mean `muck clean-all`?')
  for target in targets:
    if not ctx.db.contains_record(target=target):
      errL(f'muck clean note: {target}: skipping unknown target.')
      continue
    if is_sticky(target, follow=False):
      remove_path(target)
    ctx.db.delete_record(target=target)


def muck_dependents(ctx:Ctx) -> None:
  '`muck dependents command.'
  s = set()
  for target in ctx.targets:
    s.update(ctx.db.get_dependents(target))
  for t in sorted(s):
    outL(t)


def muck_deps(ctx:Ctx) -> None:
  '`muck deps` command.'
  targets = ctx.targets
  for target in targets:
    update_or_exit(ctx, target)

  roots = set(targets)
  roots.update(t for t, dpdts in ctx.dependents.items() if len(dpdts) > 1)

  visited_roots: Set[str] = set()

  def visit(target:str, *indents:str, sub:str='  ', color='') -> None:
    record = ctx.db.get_record(target)
    assert record is not None
    dependents = ctx.dependents[target]
    src = record.src
    observed_deps = record.dyn_deps
    inferred_deps = record.deps
    #some = bool(src) or bool(observed_deps) or bool(inferred_deps)
    if not indents and len(dependents) > 0:
      dpdt_names = ', '.join(f'{dependent_colors[d.kind]}{d.target}{RST}' for d in sorted(dependents, key=lambda d: d.target))
      suffix = f' (⇠ {dpdt_names})'
    elif len(dependents) > 1: suffix = (arrow_up if target in visited_roots else arrow_down)
    else: suffix = ''
    outL(*indents, color, target, RST, suffix)
    if indents and len(dependents) > 1: return
    sub_indents = indents and indents[:-1] + (sub,)
    if src is not None:
      visit(src, *sub_indents, ('┡╸' if observed_deps else '┗╸'), sub=('│ ' if observed_deps else '  '), color=TXT_G)
    for i, dep in enumerate(observed_deps):
      above = i < len(observed_deps) - 1
      visit(dep, *sub_indents, ('├╴' if above else '└╴'), sub=('│ ' if above else '  '), color=TXT_R)
    for i, dep in enumerate(inferred_deps):
      above = i < len(inferred_deps) - 1
      visit(dep, *sub_indents, '╰╴', sub=('│ ' if above else '  '), color=TXT_B)

  for root in sorted(roots):
    outL()
    visit(target=root)
    visited_roots.add(root)

arrow_up    = ' ⇡'
arrow_down  = ' ⇣'

dependent_colors = {
  'source'  : TXT_G,
  'observed' : TXT_R,
  'inferred' : TXT_B,
}


def muck_deps_list(ctx:Ctx) -> None:
  '`muck deps-list` command.'
  for target in ctx.targets:
    update_or_exit(ctx, target)
  outLL(*sorted(ctx.statuses.keys()))


def muck_prod_list(ctx:Ctx) -> None:
  '`muck prod-list` command.'
  for target in ctx.targets:
    update_or_exit(ctx, target)
  outLL(*sorted(ctx.statuses.keys()))


def muck_fake(ctx:Ctx) -> None:
  '`muck fake` command.`'
  for target in ctx.targets:
    fake_update(ctx, target)


def muck_create_patch(ctx:Ctx) -> None:
  '`muck create-patch` command.'
  original = norm_path(ctx.args.original)
  modified = norm_path(ctx.args.modified)
  ctx.validate_target_or_exit(original)
  ctx.validate_target_or_exit(modified)
  patch = modified + '.pat'
  if original.endswith('.pat'):
    exit(f"muck create-patch error: 'original' should not be a patch file: {original}")
  if modified.endswith('.pat'):
    exit(f"muck create-patch error: 'modified' should not be a patch file: {modified}")
  if path_exists(modified, follow=False) or ctx.db.contains_record(patch):
    exit(f"muck create-patch error: 'modified' is an existing target: {modified}")
  if path_exists(patch, follow=False) or ctx.db.contains_record(patch):
    exit(f"muck create-patch error: patch is an existing target: {patch}")
  update_or_exit(ctx, original)
  cmd = ['pat', 'create', original, modified, patch]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck create-patch note: creating patch: `{cmd_str}`')
  c = runC(cmd)
  set_prod_perms(modified, is_product=True, is_patched=True)
  if c: exit(c)


def muck_update_patch(ctx: Ctx) -> None:
  '`muck update-patch` command.'
  patch_path = norm_path(ctx.args.patch)
  ctx.validate_target_or_exit(patch_path)
  if path_ext(patch_path) != '.pat':
    exit(f'muck update-patch error: argument does not specify a .pat file: {patch_path!r}')

  deps = list(pat_dependencies(target=patch_path, dir_entries=ctx.dir_entries))
  assert len(deps) == 1
  orig_path = deps[0]
  update_or_exit(ctx, orig_path)
  target = path_stem(patch_path)
  patch_path_tmp = patch_path + muck_tmp_ext
  cmd = ['pat', 'diff', orig_path, target, patch_path_tmp]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck update-patch note: diffing: `{cmd_str}`')
  code = runC(cmd)
  if code: exit(code)
  move_file(patch_path_tmp, patch_path, overwrite=True)
  ctx.db.delete_record(target=target) # no-op if does not exist.
  #^ Need to remove or update the target record to avoid the 'did you mean to patch?' safeguard.
  #^ For now, just delete it to be safe; this makes the target look stale.
  #^ TODO: update target record instead.


def muck_move_to_fetched_url(args:Namespace) -> None:
  '`muck move-to-fetched-url` command.'
  path = args.path
  fetch_path = path_join('_fetch', path_for_url(args.url))
  make_dirs(path_dir(fetch_path))
  if path_exists(fetch_path, follow=False):
    exit(f'muck move-to-fetched-url error: file already exists at destination fetch path: {fetch_path}')
    # TODO: offer to remove.
  try: move_file(path, fetch_path)
  except OSError as e: exit(e)


def muck_publish(ctx:Ctx) -> None:
  '`muck publish` command: update each specified target.'

  # TODO: rewrite walk_glob to support shell-style {x,y} expansions.

  for pattern in ctx.args.files:
    if not is_glob_pattern(pattern): exit(f'muck publish error: not a glob pattern: {pattern!r}')
    if pattern.startswith('/'): exit(f'muck publish error: invalid glob pattern: leading slash: {pattern!r}')

  for target in ctx.targets:
    if is_link(target): exit(f'muck publish error: symlinks not yet supported: {target!r}')
    if is_dir(target, follow=False):
      for d in walk_dirs(target):
        update_or_exit(ctx, d)
    else:
      update_or_exit(ctx, target)

  dst_root = ctx.args.to
  make_dirs(dst_root)

  # Remove existing files that match the glob patterns in the publishing destination.
  for pattern in ctx.args.files:
    dst_glob = path_join(dst_root, pattern)
    errSL('cleaning glob:', dst_glob)
    for dst in walk_glob(dst_glob, recursive=True):
      errSL('  remove:', dst)
      remove_path(dst)

  copied_targets: Set[str] = set()

  def copy_to_pub(target:str, *, overwrite:bool) -> None:
    for src in walk_paths(target):
      if src in copied_targets: return
      if is_link(target): exit(f'muck publish error: symlinks not yet supported: {src!r}')
      dst = path_join(dst_root, src)
      errL(f'  publish: {src} -> {dst}')
      if is_dir(src, follow=False):
        make_dirs(dst)
      else:
        make_dirs(path_dir(dst))
        # TODO: do we need a special case for when target is a symlink?
        copy_path(src=src, dst=dst, overwrite=overwrite)
        set_prod_perms(target, is_product=False)
      copied_targets.add(src)

  errL(f'publishing targets:')
  for target in ctx.targets:
    copy_to_pub(target, overwrite=True)

  for pattern in ctx.args.files:
    errSL(f'publishing glob: {pattern}')
    # Walk over products, not targets, so that glob applies to products (which are not always globbable by user's shell).
    for product in walk_glob(pattern, recursive=True):
      copy_to_pub(product, overwrite=False)
