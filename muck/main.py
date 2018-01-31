# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck build tool.
This file was separated from __main__.py to make stack traces more consistent during testing.
'''

import sys
assert sys.version_info >= (3, 6, 0)

import base64
import json
import os
import shlex
import re
import time

from argparse import ArgumentParser, Namespace
from datetime import datetime
from hashlib import sha256
from importlib.util import find_spec as find_module_spec
from os import O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_WRONLY
from typing import *
from typing import BinaryIO, IO, Match, TextIO

from .pithy.ansi import *
from .pithy.format import format_to_re
from .pithy.fs import *
from .pithy.io import *
from .pithy.iterable import fan_by_pred, first_el
from .pithy.json import load_json, write_json
from .pithy.path_encode import path_for_url
from .pithy.pipe import DuplexPipe
from .pithy.string import format_byte_count
from .pithy.task import launch, runC

from .ctx import Ctx, Dependent, InvalidTarget, validate_target
from .db import TargetRecord, DB, DBError
from .constants import *
from .py_deps import py_dependencies
from .server import serve_build


def main() -> None:

  db_name = '_muck'
  reserved_names = { 'muck', '_fetch', '_fetch/tmp', db_name }

  # argument parser setup.
  # argparse's subparser feature does not allow for a default command.
  # thus we build an argument parser for each command, as well as the main one,
  # and dispatch manually based on the first argument.

  parsers: Dict[str, ArgumentParser] = {}

  def add_parser(cmd: str, fn: Callable[..., None], builds: bool, targets_dflt:Optional[bool]=None, takes_ctx:bool=True, **kwargs) -> ArgumentParser:
    reserved_names.add(cmd)
    parser = ArgumentParser(prog='muck ' + cmd, **kwargs)
    parser.set_defaults(fn=fn, builds=builds, targets_dflt=targets_dflt, takes_ctx=takes_ctx)
    parser.add_argument('-build-dir', default='_build', help="specify build directory; defaults to '_build'.")
    parser.add_argument('-dbg', action='store_true', help='log lots of details to stderr.')
    parser.add_argument('-dbg-libmuck', action='store_true', help='log lots of details to stderr.')
    if builds:
      parser.add_argument('-no-times', action='store_true', help='do not report process times.')
      parser.add_argument('-force', action='store_true', help='rebuild specified targets even if they are up to date.')
    if targets_dflt is not None:
      default = ['index.html'] if targets_dflt else None
      parser.add_argument('targets', nargs='*', default=default, help="target file names; defaults to 'index.html'.")
    parsers[cmd] = parser
    return parser

  add_parser('clean-all',     muck_clean_all,     builds=False, takes_ctx=False,    description='clean the entire build directory, including the build database.')
  add_parser('clean',         muck_clean,         builds=False, targets_dflt=False, description='clean the specified targets.')
  add_parser('deps',          muck_deps,          builds=True,  targets_dflt=True,  description='print targets and their dependencies as a visual hierarchy.')
  add_parser('deps-list',     muck_deps_list,     builds=True,  targets_dflt=True,  description='print targets and their dependencies as a list.')
  add_parser('prod-list',     muck_prod_list,     builds=True,  targets_dflt=True,  description='print products as a list.')

  create_patch = add_parser('create-patch',  muck_create_patch,  builds=True, description="create a patch; creates a new '.pat' source.",
    epilog='This command creates an empty patch called [modified].pat, and copies [original] to _build/[modified].')
  create_patch.add_argument('original', help='the target to be patched.')
  create_patch.add_argument('modified', help='the target to be produced by patching the original.')

  update_patch = add_parser('update-patch',  muck_update_patch,  builds=True, description="update a '.pat' patch.",
    epilog='The patch file will be updated with the diff between the original referenced by the patch, and _build/[modified].')
  update_patch.add_argument('patch', help='the patch to update.')

  move_to_fetched_url_parser = add_parser('move-to-fetched-url', muck_move_to_fetched_url, builds=False, takes_ctx=False,
    description="move a manually downloaded file to the '_fetch' folder.")
  move_to_fetched_url_parser.add_argument('path', help='the local file to be moved')
  move_to_fetched_url_parser.add_argument('url', help='the url from which the file was downloaded')

  # add build_parser last so that we can describe other commands in its epilog.
  cmds_str = ', '.join(parsers)
  build_parser = add_parser('build', muck_build, builds=True, targets_dflt=True, description='build targets',
    epilog=f'`build` is the default subcommand; other available commands are:\n{cmds_str}.`')
  build_parser.add_argument('-serve', nargs='?', const='index.html',
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
  args.build_dir = args.build_dir.rstrip('/')
  reserved_names.add(args.build_dir)
  db_path = path_join(args.build_dir, db_name)

  if args.dbg:
    def dbg(path: str, *items: Any) -> None:
      errL('muck dbg: ', path, ': ', *items)
  else:
    def dbg(path: str, *items: Any) -> None: pass

  make_dirs(args.build_dir) # required to create new DB.

  if not args.takes_ctx:
    args.fn(args)
    return

  ctx = Ctx(args=args, db=DB(path=db_path), build_dir=args.build_dir, build_dir_slash=args.build_dir + '/',
    build_dir_abs=abs_path(args.build_dir), reserved_names=frozenset(reserved_names), dbg=dbg, dbg_libmuck=args.dbg_libmuck)

  args.fn(ctx)


# Commands.


def muck_build(ctx: Ctx) -> None:
  '`muck build` (default) command: update each specified target.'

  def update_target(target: str) -> None: # closure to pass to serve_build.
    update_dependency(ctx, target, dependent=None, force=ctx.args.force)

  for target in ctx.args.targets:
    if path_exists(target):
      stem, ext = split_stem_ext(target)
      if ext in ext_tools:
        note(target, f'specified target is a source and not a product; building {stem!r}...')
        target = stem
      else:
        note(target, 'specified target is a source and not a product.')
    update_target(target)
  if ctx.args.serve:
    update_target(ctx.args.serve)
    serve_build(ctx, main_target=ctx.args.serve, update_target=update_target)


def muck_clean_all(args: Namespace) -> None:
  '`muck clean-all` command.'
  remove_dir_contents(args.build_dir)


def muck_clean(ctx: Ctx) -> None:
  '`muck clean` command.'
  targets = ctx.args.targets
  if not targets:
    exit('muck clean: no targets specified; did you mean `muck clean-all`?')
  for target in targets:
    if not ctx.db.contains_record(target=target):
      errL(f'muck clean note: {target}: skipping unknown target.')
      continue
    prod_path = ctx.product_path_for_target(target)
    remove_file_if_exists(prod_path)
    ctx.db.delete_record(target=target)


def muck_deps(ctx: Ctx) -> None:
  '`muck deps` command.'
  for target in ctx.args.targets:
    update_dependency(ctx, target, dependent=None)

  roots = set(ctx.args.targets)
  roots.update(t for t, dpdts in ctx.dependents.items() if len(dpdts) > 1)

  visited_roots: Set[str] = set()

  def visit(target: str, *indents: str, sub:str='  ', color='') -> None:
    record = ctx.db.get_record(target)
    assert record is not None
    dependents = ctx.dependents[target]
    src = record.src
    observed_deps = record.dyn_deps
    inferred_deps = record.deps
    some = bool(src) or bool(observed_deps) or bool(inferred_deps)
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


def muck_deps_list(ctx: Ctx) -> None:
  '`muck deps-list` command.'
  for target in ctx.args.targets:
    update_dependency(ctx, target, dependent=None)
  outLL(*sorted(ctx.change_times.keys()))


def muck_prod_list(ctx: Ctx) -> None:
  '`muck prod-list` command.'
  for target in ctx.args.targets:
    update_dependency(ctx, target, dependent=None)
  outLL(*sorted(ctx.product_path_for_target(t) for t in ctx.change_times.keys()))


def muck_create_patch(ctx: Ctx) -> None:
  '`muck create-patch` command.'
  original = ctx.args.original
  modified = ctx.args.modified
  validate_target_or_error(ctx, original)
  validate_target_or_error(ctx, modified)
  patch = modified + '.pat'
  if original.endswith('.pat'):
    exit(f"muck create-patch error: 'original' should not be a patch file: {original}")
  if modified.endswith('.pat'):
    exit(f"muck create-patch error: 'modified' should not be a patch file: {modified}")
  if path_exists(modified) or ctx.db.contains_record(patch):
    exit(f"muck create-patch error: 'modified' is an existing target: {modified}")
  if path_exists(patch) or ctx.db.contains_record(patch):
    exit(f"muck create-patch error: patch is an existing target: {patch}")
  update_dependency(ctx, original, dependent=None)
  cmd = ['pat', 'create', original, modified, '../' + patch]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck create-patch note: creating patch: `{cmd_str}`')
  exit(runC(cmd, cwd=ctx.build_dir))


def muck_update_patch(ctx: Ctx) -> None:
  '`muck update-patch` command.'
  patch_path = ctx.args.patch
  validate_target_or_error(ctx, patch_path)
  if path_ext(patch_path) != '.pat':
    exit(f'muck update-patch error: argument does not specify a .pat file: {patch_path!r}')

  deps = pat_dependencies(patch_path, open(patch_path), {})
  assert len(deps) == 1
  orig_path = deps[0]
  update_dependency(ctx, orig_path, dependent=None)
  target = path_stem(patch_path)
  patch_path_tmp = patch_path + tmp_ext
  cmd = ['pat', 'diff', orig_path, target, '../' + patch_path_tmp]
  cmd_str = ' '.join(shlex.quote(w) for w in cmd)
  errL(f'muck update-patch note: diffing: `{cmd_str}`')
  code = runC(cmd, cwd=ctx.build_dir)
  if code: exit(code)
  move_file(patch_path_tmp, patch_path, overwrite=True)
  ctx.db.delete_record(target=target) # no-op if does not exist.
  #^ need to remove or update the target record to avoid the 'did you mean to patch?' safeguard.
  #^ for now, just delete it to be safe; this makes the target look stale.
  #^ TODO: update target instead.


def muck_move_to_fetched_url(args: Namespace) -> None:
  '`muck move-to-fetched-url` command.'
  path = args.path
  fetch_path = path_join('_fetch', path_for_url(args.url))
  make_dirs(path_dir(fetch_path))
  if path_exists(fetch_path):
    exit(f'muck move-to-fetched-url error: file already exists at destination fetch path: {fetch_path}')
    # TODO: offer to remove.
  try: move_file(path, fetch_path)
  except OSError as e: exit(e)



# Core update algorithm.


def update_dependency(ctx: Ctx, target: str, dependent: Optional[Dependent], force=False) -> int:
  'returns transitive change_time.'
  validate_target_or_error(ctx, target)

  if dependent is not None:
    ctx.dependents[target].add(dependent)

  # Recursion check.
  try: change_time = ctx.change_times[target]
  except KeyError: pass
  else: # if in ctx.change_times, this path has already been visited during this build process run.
    if change_time is None: # recursion sentinal.
      involved_paths = sorted(path for path, t in ctx.change_times.items() if t is None)
      raise error(target, 'target has circular dependency; involved paths:', *('\n  ' + p for p in involved_paths))
    return change_time

  ctx.change_times[target] = None # recursion sentinal is replaced before return by update_deps_and_record.

  ctx.dbg(target, f'examining... (dependent={dependent})')
  is_product = not path_exists(target) # The semantic definition of a product.
  if is_product and is_link(target):
    raise error(target, f'target is a dangling symlink to: {read_link(target)}')
  actual_path = ctx.product_path_for_target(target) if is_product else target

  old = ctx.db.get_record(target=target)
  needs_update = force or (old is None)

  if old is not None:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target, f"target is {'now' if is_product else 'no longer'} a product.")
      needs_update = True

  if is_product:
    size: Optional[int] = None
    mtime = 0.0
    try: size, mtime = file_size_and_mtime(actual_path)
    except FileNotFoundError: pass
    if old is not None:
      if size is None: # Old product was deleted.
        needs_update = True
      else:
        check_product_not_modified(ctx, target, actual_path, size=size, mtime=mtime, old=old)
    return update_product(ctx, target, actual_path, needs_update=needs_update, mtime=mtime, old=old)
  else:
    return update_non_product(ctx, target, needs_update=needs_update, old=old)


def check_product_not_modified(ctx: Ctx, target: str, actual_path: str, size: int, mtime: float, old: TargetRecord) -> None:
  # existing product should not have been modified since record was stored.
  # if the size changed then it was definitely modified.
  # otherwise, if the mtime is unchanged, assume that the contents are unchanged, for speed.
  if size == old.size and mtime == old.mtime: return
  # if mtime is changed but contents are not, the user might have made an accidental edit and then reverted it.
  if size == old.size and hash_for_path(actual_path) == old.hash:
    note(target, f'product mtime changed but contents did not: {disp_mtime(old.mtime)} -> {disp_mtime(mtime)}.')
    # TODO: revert mtime?
    return
  # TODO: change language depending on whether product is derived from a patch?
  raise error(target, 'existing product has changed; did you mean to update a patch?\n'
    f'  Otherwise, save your changes if necessary and then `muck clean {target}`.')


def update_product(ctx: Ctx, target: str, actual_path: str, needs_update: bool, mtime: float, old: Optional[TargetRecord]) -> int:
  '''
  Returns transitive change_time.
  Note: we must pass the just-retrieved mtime, in case it has changed but product contents have not.
  '''
  ctx.dbg(target, 'update_product')
  src = source_for_target(ctx, target)
  validate_target_or_error(ctx, src)
  ctx.dbg(target, f'src: ', src)
  if old is not None and old.src != src:
    needs_update = True
    note(target, f'source path of target product changed\n  was: {old.src}\n  now: {src}')

  # Update and change times are logical times (incrementing counters), depending only on internal DB state.
  # This design avoids dependency on file system time stamps and OS clocks.
  # For file systems with poor time resolution (e.g. HFS mtime is 1 sec resolution), this is important.
  last_update_time = 0 if old is None else old.update_time
  src_change_time = update_dependency(ctx, src, dependent=Dependent(kind='source', target=target))
  needs_update = needs_update or last_update_time < src_change_time
  update_time = max(last_update_time, src_change_time)

  if not needs_update: # src has not changed since update.
    # check if any of the previously recorded dynamic dependencies have changed;
    # if they have not, then no rebuild is necessary.
    assert old is not None
    for dyn_dep in old.dyn_deps:
      dep_change_time = update_dependency(ctx, dyn_dep, dependent=Dependent(kind='observed', target=target))
      update_time = max(update_time, dep_change_time)
  needs_update = needs_update or last_update_time < update_time

  if needs_update: # must rebuild product.
    dyn_change_time, dyn_deps, all_outs = build_product(ctx, target=target, src_path=src, prod_path=actual_path)
    update_time = max(update_time, dyn_change_time)
    ctx.dbg(target, f'all_outs: {all_outs}')
    assert target in all_outs
    change_time = 0
    for product in sorted(all_outs):
      product_change_time = update_product_with_output(ctx, target=product, src=src, dyn_deps=dyn_deps, update_time=update_time)
      if product == target:
        change_time = product_change_time
    assert change_time > 0
    return change_time
  else: # not needs_update.
    assert old is not None
    return update_deps_and_record(ctx, target=target, actual_path=actual_path, is_changed=False, size=old.size, mtime=mtime,
      change_time=old.change_time, update_time=update_time, file_hash=old.hash, src=src, dyn_deps=old.dyn_deps, old=old)


def update_product_with_output(ctx: Ctx, target: str, src: str, dyn_deps: Tuple[str, ...], update_time: int) -> int:
  'Returns (target, change_time).'
  old = ctx.db.get_record(target=target)
  path = ctx.product_path_for_target(target)
  size, mtime = file_size_and_mtime(path)
  file_hash = hash_for_path(path)
  is_changed = (old is None or size != old.size or file_hash != old.hash)
  if is_changed:
    change_time = update_time
    change_verb = 'is new' if old is None else 'changed'
  else:
    assert old is not None
    change_time = old.change_time
    change_verb = 'did not change'
  note(target, f"product {change_verb}; {format_byte_count(size)}.")
  return update_deps_and_record(ctx, target=target, actual_path=path, is_changed=is_changed, size=size, mtime=mtime,
    change_time=change_time, update_time=update_time, file_hash=file_hash, src=src, dyn_deps=dyn_deps, old=old)


def update_non_product(ctx: Ctx, target: str, needs_update: bool, old: Optional[TargetRecord]) -> int:
  'returns transitive change_time.'
  ctx.dbg(target, 'update_non_product')
  size, mtime = file_size_and_mtime(target)
  prod_path = ctx.product_path_for_target(target)

  if needs_update:
    remove_file_if_exists(prod_path)
    make_link(target, prod_path, make_dirs=True)
  elif not is_link(prod_path):
    if not path_exists(prod_path): # link was deleted? replace it.
      make_link(target, prod_path, make_dirs=True)
    else:
      raise error(target, 'non-product link in build directory appears to have been replaced with a different file.')

  if needs_update:
    is_changed = True
    file_hash = hash_for_path(target)
  else: # all we know so far is that the file exists and status as a non-product has not changed.
    if (old is None or size != old.size or mtime != old.mtime): # appears changed; check if contents actually changed.
      file_hash = hash_for_path(target)
      is_changed = (old is None or old.hash != file_hash)
    else: # assume not changed based on size/mtime; otherwise we constantly recalculate hashes for large sources.
      is_changed = False
      file_hash = old.hash

  if is_changed:
    if not needs_update: note(target, 'source changed.') # only want to report this on subsequent changes.
    change_time = ctx.db.inc_ptime()
  else:
    assert old is not None
    change_time = old.change_time
    file_hash = old.hash
    if mtime != old.mtime:
      note(target, f'source modification time changed but contents did not.')
  return update_deps_and_record(ctx, target, actual_path=target, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=change_time, file_hash=file_hash, src=None, dyn_deps=(), old=old)
  # TODO: non_product update_time is meaningless? mark as -1?


def update_deps_and_record(ctx, target: str, actual_path: str, is_changed: bool, size: int, mtime: float,
 change_time: int, update_time: int, file_hash: bytes, src: Optional[str], dyn_deps: Tuple[str, ...], old: Optional[TargetRecord]) -> int:
  'returns transitive change_time.'

  ctx.dbg(target, 'update_deps_and_record')
  if is_changed:
    deps = calc_dependencies(actual_path, ctx.dir_names)
    for dep in deps:
      try: validate_target(ctx, dep)
      except InvalidTarget as e:
        exit(f'muck error: {target}: invalid dependency: {e.target!r}: {e.msg}')
  else:
    assert old is not None
    deps = old.deps

  for dep in deps:
    dep_change_time = update_dependency(ctx, dep, dependent=Dependent(kind='inferred', target=target))
    change_time = max(change_time, dep_change_time)
  update_time = max(update_time, change_time)

  assert ctx.change_times.get(target) is None
  #^ use get (which defaults to None) because when a script generates multiple outputs,
  # this function gets called without a preceding call to update_dependency.
  # note: it is possible that two different scripts could generate the same named file, causing this assertion to fail.
  # TODO: change this from an assertion to an informative error.
  ctx.change_times[target] = change_time # replace sentinal with final value.
  # always update record, because even if is_changed=False, mtime may have changed.
  record = TargetRecord(path=target, size=size, mtime=mtime, change_time=change_time, update_time=update_time,
    hash=file_hash, src=src, deps=deps, dyn_deps=dyn_deps)
  ctx.dbg(target, f'updated: ', record)
  ctx.db.insert_or_replace_record(record)
  return change_time


# Build.


class DepCtx(NamedTuple):
  ignored_deps: Set[str]
  restricted_deps_rd: Set[str]
  restricted_deps_wr: Set[str]
  dyn_deps: List[str]
  all_outs: Set[str]


def build_product(ctx: Ctx, target: str, src_path: str, prod_path: str) -> Tuple[int, Tuple[str, ...], Set[str]]:
  '''
  Run a source file, producing zero or more products.
  Return a list of produced product paths.
  '''
  src_prod_path = ctx.product_path_for_target(src_path)
  src_ext = path_ext(src_path)
  prod_dir = path_dir(prod_path)
  prod_path_out = prod_path + out_ext

  tool: Tool
  if is_file_executable_by_owner(src_prod_path):
    tool = Tool(cmd=(), deps_fn=None, env_fn=None)
  else:
    # TODO: check for explicit deps file.
    try: tool = ext_tools[src_ext]
    except KeyError as e: raise error(target, f'unsupported source file extension: {src_ext!r}') from e
    if not tool.cmd: # TODO: weird now that we create an empty tool cmd above.
      note(target, 'no op.')
      return 0, (), set() # no product.

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_wilds(target_path_for_source(ctx, src_path), target)
  if m is None:
    raise error(target, f'internal error: match failed; src_path: {src_path!r}')
  args = tuple(m.groups())
  src_arg = cast(Tuple[str, ...], () if tool.src_to_stdin else (src_path,))
  cmd = tool.cmd + src_arg + args

  msg_stdin = f' < {src_path}' if tool.src_to_stdin else ''
  note(target, f"building: `{' '.join(shlex.quote(w) for w in cmd)}{msg_stdin}`")

  make_dirs(prod_dir)
  remove_file_if_exists(prod_path_out)
  remove_file_if_exists(prod_path)

  env = os.environ.copy()
  if tool.env_fn is not None:
    env.update(tool.env_fn())
  env['DYLD_INSERT_LIBRARIES'] = libmuck_path
  #env['DYLD_PRINT_LIBRARIES'] = 'TRUE'
  if ctx.dbg_libmuck:
    env['MUCK_DEPS_DBG'] = 'TRUE'

  # Get the source's inferred dependencies, to be ignored when observing target dependencies.
  ignored_deps = set(ctx.db.get_inferred_deps(target=src_path))
  ignored_deps.update(['.', src_path])

  depCtx = DepCtx(
    ignored_deps=ignored_deps,
    restricted_deps_rd={
      ctx.db.path,
      prod_path_out,
    },
    restricted_deps_wr={
      ctx.db.path,
      prod_path_out, # muck process opens this for the child.
      src_path,
    },
    dyn_deps=[],
    all_outs=set())

  dyn_time = 0
  with open(prod_path_out, 'wb') as out_file, DuplexPipe() as pipe:
    deps_recv, deps_send = pipe.left_files()
    env.update(zip(('MUCK_DEPS_RECV', 'MUCK_DEPS_SEND'), [str(fd) for fd in pipe.right_fds]))
    env['MUCK_OUT'] = path_rel_to_ancestor(prod_path, ancestor=ctx.build_dir)
    task_stdin = open(src_prod_path, 'rb') if tool.src_to_stdin else None
    time_start = time.time()
    cmd, proc, _ = launch(cmd, cwd=ctx.build_dir, env=env, stdin=task_stdin, out=out_file, files=pipe.right_fds)
    if task_stdin: task_stdin.close()
    pipe.close_right()
    try:
      while True:
        dep_line = deps_recv.readline()
        if not dep_line: break # no more data; child is done.
        dyn_time = process_dep_line(ctx, depCtx=depCtx, target=target, dep_line=dep_line, dyn_time=dyn_time)
        print('\x06', end='', file=deps_send, flush=True) # Ascii ACK.
    except (Exception, SystemExit):
      proc.kill() # this avoids a confusing exception message from the child script when muck fails.
      raise
    code = proc.wait()
    time_elapsed = time.time() - time_start

  if code != 0: raise error(target, f'build failed with code: {code}')

  if path_exists(prod_path):
    via = 'open'
    if target not in depCtx.all_outs:
      warn(target, f'wrote data to {prod_path}, but muck did not observe `open` system call.')
    if file_size(prod_path_out) == 0:
      remove_file(prod_path_out)
    else:
      warn(target, f'wrote data to {prod_path} via `open`; ignoring output captured in `{prod_path_out}`')
  else: # no new file; use captured stdout.
    via = 'stdout'
    move_file(prod_path_out, prod_path)
  depCtx.all_outs.add(target)
  time_msg = '' if ctx.args.no_times else f'{time_elapsed:0.2f} seconds '
  note(target, f'finished: {time_msg}(via {via}).')
  return dyn_time, tuple(depCtx.dyn_deps), depCtx.all_outs


def process_dep_line(ctx: Ctx, depCtx: DepCtx, target: str, dep_line: str, dyn_time: int) -> int:
  '''
  Parse a dependency line sent from a child build process.
  This is trick because the parent and child processes have different current working directories.
  '''
  try:
    dep_line_parts = dep_line.split('\t')
    call, mode, dep = dep_line_parts
    if not (dep and dep[-1] == '\n'): raise ValueError
    dep = dep[:-1] # remove final newline.
  except ValueError as e: raise error(target, f'child process sent bad dependency line:\n{dep_line!r}') from e

  assert is_path_abs(dep), dep # libmuck converts all paths to absolute; only the client knows its own current directory.
  try: dep = path_rel_to_ancestor(dep, ancestor=ctx.build_dir_abs, dot=True)
  except PathIsNotDescendantError:
    # We cannot differentiate between harmless and ill-advised accesses outside of the build directory.
    # In particular, as long as the project dir is the parent of build_dir,
    # we cannot sensibly prevent a script from accessing the project dir directly.
    # For example, Python accesses the parent directory during startup.
    # Therefore our only option is to ignore access to parent dirs.
    return dyn_time

  if (dep in depCtx.ignored_deps) or (path_ext(dep) in ignored_dep_exts): return dyn_time
  # TODO: further verifications? source dir, etc.

  ctx.dbg(target, f'{mode} dep: {dep}')
  assert not is_path_abs(dep)
  if mode in 'RS':
    if mode == 'S' and dep == target: return dyn_time # sqlite stats the db before opening. Imperfect, but better than nothing.
    if dep in depCtx.restricted_deps_rd: raise error(target, f'attempted to open restricted file for reading: {dep!r}')
    dep_time = update_dependency(ctx, dep, dependent=Dependent(kind='observed', target=target))
    dyn_time = max(dyn_time, dep_time)
    depCtx.dyn_deps.append(dep)
  elif mode in 'AMUW':
    if dep in depCtx.restricted_deps_wr: raise error(target, f'attempted to open restricted file for writing: {dep!r}')
    validate_target_or_error(ctx, dep)
    depCtx.all_outs.add(dep)
  else: raise ValueError(f'invalid mode received from libmuck: {mode}')
  return dyn_time


# Dependency inference.

def calc_dependencies(path: str, dir_names: Dict[str, Tuple[str, ...]]) -> Tuple[str, ...]:
  '''
  Infer the dependencies for the file at `path`.
  '''
  ext = path_ext(path)
  try: deps_fn = ext_tools[ext].deps_fn
  except KeyError: return ()
  if deps_fn is None: return ()
  with open(path) as f:
    return tuple(deps_fn(path, f, dir_names))


def list_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
  'Calculate dependencies for .list files.'
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


def md_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
  return []


def sh_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> Iterable[str]:
  'Calculate dependencies for .sh files.'
  for line in src_file:
    for token in shlex.split(line):
      if path_ext(token):
        yield token


def sqlite3_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> Iterable[str]:
  'Calculate dependencies for .sql files (assumed to be sqlite3 commands).'
  for i, line in enumerate(src_file, 1):
    tokens = shlex.split(line)
    for j, token in enumerate(tokens):
      if token == '.open' and j+1 < len(tokens):
        yield tokens[j+1]


def pat_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
  try: import pat
  except ImportError: raise error(src_path, '`pat` is not installed; run `pip install pat-tool`.')
  dep = pat.pat_dependency(src_path=src_path, src_file=src_file)
  return [dep]


def writeup_dependencies(src_path: str, src_file: TextIO, dir_names: Dict[str, Tuple[str, ...]]) -> List[str]:
  try: import writeup.v0 # type: ignore
  except ImportError: raise error(src_path, '`writeup` is not installed; run `pip install writeup-tool`.')
  return writeup.v0.writeup_dependencies(src_path=src_path, text_lines=src_file) # type: ignore


# Tools.

def py_env() -> Dict[str, str]:
  return { 'PYTHONPATH' : current_dir() }


DependencyFn = Callable[[str, TextIO, Dict[str, Tuple[str, ...]]], Iterable[str]]
EnvFn = Callable[[], Dict[str, str]]

class Tool(NamedTuple):
  cmd: Tuple[str, ...]
  deps_fn: Optional[DependencyFn]
  env_fn: Optional[EnvFn]
  src_to_stdin: bool = False


ext_tools: Dict[str, Tool] = {
  # The boolean inicates that the tool expects the source as stdin.
  '.bash' : Tool(('bash',), sh_dependencies, None),
  '.csv'  : Tool(('csv-to-html',), None, None),
  '.list' : Tool((), list_dependencies, None),
  '.md'   : Tool(('cmark-gfm',), None, None),
  '.pat'  : Tool(('pat', 'apply'), pat_dependencies, None),
  '.py'   : Tool(('python3',), py_dependencies, py_env),
  '.sh'   : Tool(('sh',), sh_dependencies, None),
  '.sql'  : Tool(('sqlite3', '-batch'), sqlite3_dependencies, None, src_to_stdin=True),
  '.wu'   : Tool(('writeup',), writeup_dependencies, None),
}

ignored_dep_exts = {
  '.sqlite-journal',
  '.sqlite-shm',
  '.sqlite-wal',
  '.sqlite3-journal',
  '.sqlite3-shm',
  '.sqlite3-wal',
}


# Currently libmuck is installed as a Python C extension,
# which allows us to easily determine the path to the shared library.
libmuck_path = cast(str, find_module_spec('muck._libmuck').origin)
assert libmuck_path is not None


# Targets and paths.


def validate_target_or_error(ctx: Ctx, target: str) -> None:
  try: validate_target(ctx, target)
  except InvalidTarget as e:
    exit(f'muck error: invalid target: {e.target!r}; {e.msg}')


def target_path_for_source(ctx: Ctx, source_path: str) -> str:
  'Return the target path for `source_path` (which may itself be a product).'
  path = path_stem(source_path) # strip off source ext.
  if ctx.is_product_path(path): # source might be a product.
    return path[len(ctx.build_dir_slash):]
  else:
    return path


_wildcard_re = re.compile(r'(%+)')

def match_wilds(wildcard_path: str, string: str) -> Optional[Match[str]]:
  '''
  Match a string against a wildcard/format path.
  '''
  r = format_to_re(wildcard_path)
  return r.fullmatch(string)


# Utilities.


def hash_for_path(path: str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  if is_file(path): return hash_for_file_contents(path)
  if is_dir(path): return hash_for_dir(path)
  raise error(path, f'path is a {FileStatus.of(path).type_desc}')


def hash_for_file_contents(path: str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  hash_chunk_size = 1 << 16
  #^ a quick timing experiment suggested that chunk sizes larger than this are not faster.
  try: f = open(path, 'rb')
  except IsADirectoryError: raise error(path, 'expected a file but found a directory')
  h = sha256()
  while True:
    chunk = f.read(hash_chunk_size)
    if not chunk: break
    h.update(chunk)
  return h.digest()


def hash_for_dir(path: str) -> bytes:
  '''
  Return a hash string for the complete directory tree rooted at `path`.
  '''
  # TODO: cache tree hashes.
  h = sha256()
  for child in list_dir_paths(path, hidden=True): # Ignore hidden files.
    h.update(child.encode()) # path name.
    h.update(hash_for_path(child)) # path contents.
  return h.digest()


def file_size_and_mtime(path: str) -> Tuple[int, float]:
  stats = os.stat(path)
  return (stats.st_size, stats.st_mtime)


def source_for_target(ctx: Ctx, target: str) -> str:
  '''
  Find the unique source path whose name matches `target`, or else error.
  '''
  src_dir, prod_name = split_dir_name(target)
  src_name = source_candidate(ctx, target, src_dir, prod_name)
  src = path_join(src_dir, src_name)
  assert src != target
  return src


def source_candidate(ctx: Ctx, target: str, src_dir: str, prod_name: str) -> str:
  src_dir = src_dir or '.'
  try: src_dir_names = list_dir_filtered(ctx, src_dir)
  except FileNotFoundError: raise error(target, f'no such source directory: `{src_dir}`')
  candidates = list(filter_source_names(src_dir_names, prod_name))
  if len(candidates) == 1:
    return candidates[0]
  # error.
  # Use dependent to describe error if possible; often the dependent code is naming something that does not exist.
  # TODO: use source locations wherever possible.
  dpdts = ctx.dependents[target]
  dpdt_name = first_el(dpdts).target if dpdts else target
  if len(candidates) == 0:
    raise error(dpdt_name, f'no source candidates matching `{target}` in `{src_dir}`')
  else:
    raise error(dpdt_name, f'multiple source candidates matching `{target}`: {candidates}')


def list_dir_filtered(ctx: Ctx, src_dir: str) -> List[str]:
  '''
  Given src_dir, cache and return the list of names that might be source files.
  TODO: eventually this should be replaced by using os.scandir.
  '''
  try: return ctx.dir_names[src_dir]
  except KeyError: pass
  names = [n for n in list_dir(src_dir, hidden=False)
    if n not in ctx.reserved_names and path_ext(n) not in reserved_or_ignored_exts]
  ctx.dir_names[src_dir] = names
  return names


def filter_source_names(names: Iterable[str], prod_name: str) -> Iterable[str]:
  '''
  Given `prod_name`, find all matching source names.
  There are several concerns that make this matching complex.
  * Muck allows named formatters (e.g. '{x}') in script names.
    This allows a single script to produce many targets for corresponding arguments.
  * A source might itself be the product of another source.

  So, given product name "x.txt", match all of the following:
  * x.txt.py
  * {}.txt.py
  * x.txt.py.py
  * {}.txt.py.py
  '''
  prod = prod_name.split('.')
  for src_name in names:
    src = src_name.split('.')
    if len(src) <= len(prod): continue
    if all(match_wilds(*p) for p in zip(src, prod)): # zip stops when prod is exhausted.
      yield '.'.join(src[:len(prod)+1]) # the immediate source name has just one extension added.


def note(path: str, *items: Any) -> None:
  errL(TXT_L_ERR, f'muck note: {path}: ', *items, RST_ERR)

def warn(path: str, *items: Any) -> None:
  errL(TXT_Y_ERR, f'muck WARNING: {path}: ', *items, RST_ERR)

def error(path: str, *items: Any) -> SystemExit:
  return SystemExit(''.join((f'muck error: {path}: ',) + items))


def disp_mtime(mtime: Optional[float]) -> str:
  return str(datetime.fromtimestamp(mtime)) if mtime else '0'
