# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck's core update algorithm.
'''

from contextlib import nullcontext
from datetime import datetime as DateTime
from importlib.util import find_spec as find_module_spec
from os import environ, kill, mkfifo, remove as os_remove
from shlex import quote as sh_quote, split as sh_split
from signal import SIGCONT
from time import sleep, time as now
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple

from .constants import muck_out_ext, reserved_or_ignored_exts
from .ctx import BuildError, Ctx, Dpdt, InvalidTarget, TargetNotFound, TargetStatus, match_format
from .db import TargetRecord
from .logging import note, warn
from .paths import set_prod_perms, set_write_perm
from .pithy.ansi import BOLD, RST, RST_BOLD, TXT_G, sgr
from .pithy.filestatus import dir_entry_type_char
from .pithy.fs import (DirEntries, file_size, file_status, is_dir, is_file_executable_by_owner, make_dirs, move_file,
  path_exists, read_link, remove_file, remove_path_if_exists, scan_dir)
from .pithy.io import AsyncLineReader, errL
from .pithy.path import (PathIsNotDescendantError, is_path_abs, norm_path, path_dir, path_dir_or_dot, path_ext, path_join,
  path_name, path_rel_to_ancestor)
from .pithy.string import format_byte_count
from .pithy.task import launch
from .pithy.url import split_url
from .py_deps import py_dependencies


# Try to use a fast hashing algorithm; fall back on the system algorithm.
try:
  from hashing import Aquahash as Hasher
except ImportError:
  from hashlib import blake2b
  def Hasher() -> blake2b: return blake2b(digest_size=16) # type: ignore


def fake_update(ctx:Ctx, target:str) -> None:
  'Fake an update to the target by mutating the build record.'
  try:
    is_dir, size, mtime = file_stats(target)
    if size < 0: raise BuildError(target, f'product does not exist: {target!r}')

    record = ctx.db.get_record(target)
    if not record: raise BuildError(target, f'unknown target')
    if record.is_dir != is_dir: raise BuildError(target, f'cannot fake is_dir change: {record.is_dir} -> {is_dir}')
    fake = record._replace(size=size, mtime=mtime)
    ctx.db.insert_or_replace_record(fake)

  except BuildError as e: exit(e)


def update_or_exit(ctx:Ctx, target:str) -> int:
  'Call update_top; on error, print and exit.'
  try: return update_top(ctx, target)
  except BuildError as e: exit(e)


def update_top(ctx:Ctx, target:str) -> int:

  # Create the FIFO that we use to communicate with interposed child processes.
  try:
    mkfifo(ctx.fifo_path, mode=0o600)
  except OSError:
    if path_exists(ctx.fifo_path, follow=False):
      exit(f'muck fatal error: {ctx.fifo_path}: '
        'FIFO path already exists; another `muck` process is either running or previously failed.')
    raise

  try:
    try: fifo = AsyncLineReader(ctx.fifo_path)
    except Exception:
      exit(f'muck fatal error: {ctx.fifo_path}: FIFO path could not be opened for reading.')

    with fifo:
      dpdt = Dpdt(kind='top', target='', parent=None)
      return update_target(ctx, fifo=fifo, target=target, dpdt=dpdt, force=ctx.args.force)

  finally: # Remove the FIFO.
    try:
      os_remove(ctx.fifo_path)
    except Exception:
      exit(f'muck fatal error: {ctx.fifo_path}: fifo could not be removed.')


def update_target(ctx:Ctx, fifo:AsyncLineReader, target:str, dpdt:Dpdt, force=False) -> int:
  '''
  The central function of Muck's build algorithm.
  Returns transitive change_time.
  '''
  ctx.validate_target(target)

  if dpdt.parent is not None:
    ctx.dependents[target].add(dpdt)

  # Recursion check.
  try: target_status = ctx.statuses[target]
  except KeyError: pass
  else: # If status value is present, then this path has already been visited during this build.
    if target_status.error is not None: # Already failed; reraise.
      raise target_status.error
    if not target_status.is_updated: # We have recursed back to a target already on the stack.
      cycle = list(dpdt.cycle(target=target))
      raise BuildError(target, 'target has circular dependency:', *(f'\n  {t}' for t in cycle))
    return target_status.change_time

  target_status = ctx.statuses[target] = TargetStatus(dpdt=dpdt, expected=True)
  #^ Note: update_deps_and_record updates the status upon completion.
  try:
    return update_target_status(ctx=ctx, fifo=fifo, target=target, dpdt=dpdt, force=force, target_status=target_status)
  except BuildError as e:
    target_status.error = e
    raise


def update_target_status(ctx:Ctx, fifo:AsyncLineReader, target:str, dpdt:Dpdt, force:bool, target_status:TargetStatus) -> int:
  ctx.dbg(target, f'{TXT_G}update; {dpdt}{RST}')

  status = file_status(target, follow=False)
  if status and status.is_link and not path_exists(target, follow=True):
    raise BuildError(target, f'target is a dangling symlink to: {read_link(target)}')

  is_product = status is None or status.is_sticky # Note: this logic must match muck.paths.is_target_product.

  if is_product:
    target_dir = path_dir_or_dot(target)
    if target_dir and not path_exists(target_dir, follow=True):
      note(target, f'directory does not exist: {target_dir}')
      # Not possible to find a source; must be the contents of a built directory (or an erroneous dependency).
      update_target(ctx, fifo=fifo, target=target_dir, dpdt=dpdt.sub(kind='directory contents', target=target), force=force)
      if not target_status.is_updated: # build of parent did not create this product.
        raise BuildError(target, f'target resides in a product directory but was not created by building that directory')
      return target_status.change_time

  old = ctx.db.get_record(target=target)
  needs_update = force or (old is None)

  if old is not None:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target, f"target is {'now' if is_product else 'no longer'} a product.")
      needs_update = True

  if is_product:
    return update_product(ctx, fifo=fifo, target=target, needs_update=needs_update, old=old, dpdt=dpdt)
  else:
    assert status is not None
    return update_non_product(ctx, fifo=fifo, target=target, needs_update=needs_update, old=old, dpdt=dpdt)


def check_product_not_modified(ctx:Ctx, target:str, is_target_dir:bool, size:int, mtime:float, old:TargetRecord) -> None:
  # Existing product should not have been modified since record was stored.
  # If is_dir or size changed then it was definitely modified.
  if is_target_dir == old.is_dir and size == old.size:
    # Otherwise, if the mtime is unchanged, assume that the contents are unchanged, for speed.
    if mtime == old.mtime: return
    # if mtime is changed but contents are not, the user might have made an accidental edit and then reverted it.
    if hash_for_path(target) == old.hash:
      note(target, f'product mtime changed but contents did not: {disp_mtime(old.mtime)} -> {disp_mtime(mtime)}.')
      # TODO: revert mtime?
      return
  # TODO: change language depending on whether product is derived from a patch?
  raise BuildError(target, 'existing product has changed; did you mean to update a patch?\n'
    f'  Otherwise, save your changes if necessary and then `muck clean {target}`.')


def update_product(ctx:Ctx, fifo:AsyncLineReader, target:str, needs_update:bool, old:Optional[TargetRecord], dpdt:Dpdt) -> int:
  '''
  Returns transitive change_time.
  Note: we must pass the just-retrieved mtime, in case it has changed but product contents have not.
  '''
  ctx.dbg(target, 'update_product')

  is_target_dir, size, mtime = file_stats(target)

  if old is not None: # Old record exists.
    if size < 0: # Old file was deleted.
      needs_update = True
    else:
      check_product_not_modified(ctx, target, is_target_dir=is_target_dir, size=size, mtime=mtime, old=old)

  src = ctx.source_for_target(target, dpdt=dpdt)
  ctx.validate_target(src) # Redundant with update_target below. TODO: remove?
  ctx.dbg(target, f'src: ', src)
  if old is not None and old.src != src:
    needs_update = True
    note(target, f'source path of target product changed\n  was: {old.src}\n  now: {src}')

  # Update and change times are logical times (incrementing counters), depending only on internal DB state.
  # This design avoids dependency on file system time stamps and OS clocks.
  # For file systems with poor time resolution (e.g. HFS mtime is 1 sec resolution), this is important.
  last_update_time = 0 if old is None else old.update_time
  src_change_time = update_target(ctx, fifo=fifo, target=src, dpdt=dpdt.sub(kind='source', target=target))
  needs_update = needs_update or last_update_time < src_change_time
  update_time = max(last_update_time, src_change_time)

  if not needs_update: # src has not changed since update.
    # check if any of the previously recorded dynamic dependencies have changed;
    # if they have not, then no rebuild is necessary.
    assert old is not None
    for dyn_dep in old.dyn_deps:
      dep_change_time = update_target(ctx, fifo=fifo, target=dyn_dep, dpdt=dpdt.sub(kind='observed', target=target))
      update_time = max(update_time, dep_change_time)
  needs_update = needs_update or last_update_time < update_time

  if needs_update: # must rebuild product.
    dyn_change_time, dyn_deps, all_outs = build_product(ctx, fifo=fifo, target=target, src_path=src, dpdt=dpdt)
    update_time = max(update_time, dyn_change_time)
    ctx.dbg(target, f'all_outs: {all_outs}')
    # For `.list` and any other no-op targets, there is no output, so change_time will be zero.
    change_time = 0
    product_change_time = 0
    for product in all_outs:
      product_change_time = update_product_with_output(ctx, fifo=fifo, target=product, src=src, dyn_deps=dyn_deps,
        update_time=update_time, dpdt=dpdt)
      if product == target:
        change_time = product_change_time
    return change_time
  else: # Does not needs_update.
    assert old is not None
    return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=is_target_dir, is_changed=False,
      size=old.size, mtime=mtime, change_time=old.change_time, update_time=update_time, file_hash=old.hash, src=src,
      dyn_deps=old.dyn_deps, old=old, dpdt=dpdt)


def update_product_with_output(ctx:Ctx, fifo:AsyncLineReader, target:str, src:str, dyn_deps:Tuple[str, ...], update_time:int,
 dpdt:Dpdt) -> int:
  'Returns (target, change_time).'
  old = ctx.db.get_record(target=target)
  is_target_dir, size, mtime = file_stats(target)
  file_hash = hash_for_path(target)
  is_changed = (old is None or size != old.size or file_hash != old.hash)
  if is_changed:
    change_time = update_time
    change_verb = 'is new' if old is None else 'changed'
    change_verb = f'{sgr(BOLD)}{change_verb}{sgr(RST_BOLD)}'
  else:
    assert old is not None
    change_time = old.change_time
    change_verb = 'did not change'
  note(target, f"product {change_verb}; {format_byte_count(size)}.")
  return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=is_target_dir, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=update_time, file_hash=file_hash, src=src, dyn_deps=dyn_deps,
    old=old, dpdt=dpdt)


def update_non_product(ctx:Ctx, fifo:AsyncLineReader, target:str, needs_update:bool, old:Optional[TargetRecord], dpdt:Dpdt) \
 -> int:
  'Returns transitive change_time.'
  ctx.dbg(target, 'update_non_product')

  is_target_dir, size, mtime = file_stats(target)

  if (old is None or is_target_dir or old.is_dir or size != old.size or mtime != old.mtime):
    # All we know so far is that the asset exists, dir/file is not changed, and product/non-product is not changed.
    # Note that if the target is a directory, then we must recalculate the hash, because mtime will not reflect changes.
    target_hash = hash_for_path(target)
    is_changed = (old is None or old.hash != target_hash)
  else: # assume not changed based on size/mtime; otherwise we constantly recalculate hashes for large sources.
    target_hash = old.hash
    is_changed = False

  if is_changed:
    if not needs_update: note(target, 'source changed.') # only want to report this on subsequent changes.
    change_time = ctx.db.inc_ptime()
  else: # not changed.
    assert old is not None
    change_time = old.change_time
    target_hash = old.hash
    if mtime != old.mtime:
      note(target, f'source modification time changed but contents did not.')

  return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=is_target_dir, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=change_time, file_hash=target_hash, src=None, dyn_deps=(),
    old=old, dpdt=dpdt)
  # TODO: non_product update_time is meaningless? mark as -1?


def update_deps_and_record(ctx, fifo:AsyncLineReader, target:str, is_target_dir:bool, is_changed:bool,
 size:int, mtime:float, change_time:int, update_time:int, file_hash:bytes, src:Optional[str], dyn_deps:Tuple[str, ...],
 old:Optional[TargetRecord], dpdt:Dpdt) -> int:
  'returns transitive change_time.'

  ctx.dbg(target, 'update_deps_and_record')
  if is_changed:
    deps = calculate_dependencies(target=target, dir_entries=ctx.dir_entries)
    for dep in deps:
      try: ctx.validate_target(dep) # Redundant with update_target below. TODO: remove?
      except InvalidTarget as e:
        raise BuildError(target, f'invalid dependency: {e.target!r}; {"".join(e.msg)}')
  else:
    assert old is not None
    deps = old.deps

  for dep in deps:
    dep_change_time = update_target(ctx, fifo=fifo, target=dep, dpdt=dpdt.sub(kind='inferred', target=target))
    change_time = max(change_time, dep_change_time)
  update_time = max(update_time, change_time)

  try: status = ctx.statuses[target]
  except KeyError:
    status = TargetStatus(dpdt=dpdt, expected=False)
    ctx.statuses[target] = status
  else:
    if status.is_updated:
      ctx.dbg(target, f'target was updated by both a script and a dependency; dependents:',
        f'\n  {status.dpdt}; expected {status.expected}',
        f'\n  {dpdt}')

  status.is_updated = True
  status.change_time = change_time
  # always update record, because even if is_changed=False, mtime may have changed.
  record = TargetRecord(path=target, is_dir=is_target_dir, size=size, mtime=mtime,
    change_time=change_time, update_time=update_time, hash=file_hash, src=src, deps=deps, dyn_deps=dyn_deps)
  if old != record:
    ctx.db.insert_or_replace_record(record)
    ctx.dbg(target, f'updated: ', record)
  return change_time


# Build.


class DepCtx(NamedTuple):
  ignored_deps: Set[str]
  restricted_deps_rd: Set[str]
  restricted_deps_wr: Set[str]
  restricted_deps_all: Set[str]
  dyn_deps: Set[str]
  all_outs: Set[str]
  stale_out_dirs:Set[str] # Note: this is not effective unless we get rid of build_dir. TODO!!!

  def add_out(self, target:str) -> None:
    self.all_outs.add(target)
    self.stale_out_dirs.add(path_dir_or_dot(target))

  def refresh_out_dirs(self, dir_entries:DirEntries) -> None:
    for out_dir in self.stale_out_dirs:
      dir_entries.clear_dir(out_dir)
    self.stale_out_dirs.clear()


def build_product(ctx:Ctx, fifo:AsyncLineReader, target:str, src_path:str, dpdt:Dpdt) -> Tuple[int, Tuple[str, ...], List[str]]:
  '''
  Run a source file, producing zero or more products.
  Return a list of produced product paths.
  '''
  src_name = path_name(src_path)
  src_ext = path_ext(src_path)
  target_out = target + muck_out_ext
  target_dir = path_dir_or_dot(target)
  is_patched = (src_ext == '.pat')

  if is_dir(src_path, follow=True):
    raise BuildError(target, f'source path is a directory: {src_path!r}')

  src_arg:Tuple[str,...] = () # Optional insertion of src_name as first arg.
  if is_file_executable_by_owner(src_path):
    tool = Tool(cmd=('./' + src_name,), deps_fn=None, env_mod_fn=None)
  else:
    # TODO: check for explicit deps file.
    try: tool = ext_tools[src_ext]
    except KeyError as e: raise BuildError(target, f'unsupported source file extension: {src_ext!r}') from e
    if not tool.cmd:
      note(target, 'no-op.')
      return 0, (), [] # no product.
    if not tool.src_to_stdin:
      src_arg = (src_name,)

  # Extract args from the combination of wilds in the source and the matching target.
  m = match_format(ctx.target_for_source(src_path), target)
  if m is None:
    raise BuildError(target, f'internal error: match failed; src_path: {src_path!r}')
  args = tuple(m.groups())
  cmd = [*tool.cmd, *src_arg, *args]

  msg_stdin = f' < {src_name}' if tool.src_to_stdin else ''
  cmd_msg = f"`{' '.join(sh_quote(w) for w in cmd)}{msg_stdin}`"
  note(target, cmd_msg, ' running…')

  make_dirs(target_dir)
  remove_path_if_exists(target_out)
  remove_path_if_exists(target)

  env = environ.copy()
  # TODO: check that these variables are not already set.
  env['PROJECT_DIR'] = ctx.proj_dir
  env['TARGET'] = target
  if tool.env_mod_fn is not None:
    tool.env_mod_fn(ctx, env)
  env['MUCK_FIFO'] = ctx.fifo_path_abs
  env['MUCK_PID'] = ctx.pid_str
  env['MUCK_DYLD_INSERT_LIBRARIES'] = libmuck_path
  env['DYLD_INSERT_LIBRARIES'] = libmuck_path
  #env['DYLD_FORCE_FLAT_NAMESPACE'] = 'TRUE'
  #env['DYLD_PRINT_LIBRARIES'] = 'TRUE'
  if ctx.dbg_child:
    env['MUCK_DEPS_DBG'] = 'TRUE'

  # Get the source's inferred dependencies, to be ignored when observing target dependencies.
  ignored_deps = set(ctx.db.get_inferred_deps(target=src_path))
  ignored_deps.update(['.', src_path])

  restricted_deps_rd = {
    ctx.db.path,
    ctx.fifo_path,
    target_out,
  }
  restricted_deps_wr = restricted_deps_rd | { src_path }

  depCtx = DepCtx(
    ignored_deps=ignored_deps,
    restricted_deps_rd=restricted_deps_rd,
    restricted_deps_wr=restricted_deps_wr,
    restricted_deps_all=restricted_deps_rd | restricted_deps_wr,
    dyn_deps=set(),
    all_outs=set(),
    stale_out_dirs=set())

  dyn_time = 0
  in_cm = open(src_path, 'rb') if tool.src_to_stdin else nullcontext(None)
  with in_cm as in_file, open(target_out, 'wb') as out_file: # type: ignore
    time_start = now()
    _, proc, _ = launch(cmd, cwd=target_dir, env=env, stdin=in_file, out=out_file, lldb=ctx.dbg_child_lldb)
    if in_file: in_file.close()
    out_file.close()
    targets_not_found: Set[Tuple[str, ...]] = set()
    # For now, the best we can do is poll the nonblocking FIFO reader for deplines and the task for completion.
    try:
      while proc.poll() is None: # Child process has not terminated yet.
        dep_line = fifo.readline()
        if dep_line:
          try:
            dep_pid, dyn_time = handle_dep_line(ctx, depCtx=depCtx, fifo=fifo, target=target, dep_line=dep_line,
              dyn_time=dyn_time, dpdt=dpdt)
          except TargetNotFound as e:
            targets_not_found.add(e.args)
          kill(dep_pid, SIGCONT) # Tell whichever process sent the dep to continue.
        else:
          sleep(0.00001) # Sleep for a minimal duration.
    except BaseException:
      proc.kill()
      #^ Killing the script avoids a confusing exception message from the child script when muck fails,
      #^ and/or zombie child processes (e.g. sqlite3).
      for cause in sorted(targets_not_found): note(*cause)
      #^ Only describe targets not found if the process fails;
      #^ some scripts will stat or attempt to open nonexistant files that do not affect correctness.
      #^ While this is not desirable in terms of reproducible builds,
      #^ at the moment it seems too verbose to issue a warning every time it happens.
      raise
    finally:
      for out in depCtx.all_outs:
        try: set_prod_perms(out, is_product=True, is_patched=False)
        except FileNotFoundError: continue

    code = proc.returncode
    time_elapsed = now() - time_start

  if code != 0: raise BuildError(target, cmd_msg, f' failed with code: {code}')

  s = file_status(target, follow=False)
  if s:
    via = 'open'
    if target not in depCtx.all_outs and not s.is_dir:
      warn(target, f'wrote data to {target}, but muck did not observe `open` system call.')
    if file_size(target_out) == 0:
      remove_file(target_out)
    else:
      warn(target, f'wrote data to {target} via `open`; ignoring output captured in `{target_out}`.')
  else: # no new file; use captured stdout.
    via = 'stdout'
    set_prod_perms(target_out, is_product=True, is_patched=is_patched)
    move_file(target_out, target)
  depCtx.add_out(target)
  depCtx.refresh_out_dirs(ctx.dir_entries)
  time_msg = '' if ctx.args.no_times else f'{time_elapsed:0.2f} seconds '
  note(target, cmd_msg, f' finished: {time_msg}(via {via}).')
  all_outs = sorted(out for out in depCtx.all_outs if path_exists(out, follow=False))
  return dyn_time, tuple(sorted(depCtx.dyn_deps)), all_outs


def handle_dep_line(ctx:Ctx, fifo:AsyncLineReader, depCtx:DepCtx, target:str, dep_line:str, dyn_time:int, dpdt:Dpdt) \
 -> Tuple[int,int]:
  '''
  Parse and handle a dependency line sent from a child build process.
  Since the parent and child processes have different current working directories,
  libmuck (executing in the child process) always sends absolute paths.

  When a child process tries to open a file, the interposed libmuck `open` function is called.
  This sends child process ID and the path to be opened to Muck, and then sends the SIGSTOP signal to itself.
  Here, Muck attempts to update the dependency.
  It then signals the child process to resume with SIGCONT.
  '''
  try:
    dep_line_parts = dep_line.split('\t')
    pid_str, call, mode, dep_nl = dep_line_parts
    pid = int(pid_str)
    if not (dep_nl and dep_nl[-1] == '\n'): raise ValueError
  except ValueError as e:
    raise BuildError(target, f'child process sent bad dependency line:\n{dep_line!r}') from e

  dep_abs = dep_nl[:-1] # Remove final newline.

  if not is_path_abs(dep_abs): # libmuck converts all paths to absolute, because only the child knows its current directory.
    raise ValueError(f'libmuck sent relative path: {dep_abs}')
  try: dep = path_rel_to_ancestor(dep_abs, ancestor=ctx.proj_dir, dot=True)
  except PathIsNotDescendantError:
    # We cannot differentiate between harmless and ill-advised accesses outside of the project directory.
    # For example, Python accesses the parent directory during startup.
    # Therefore our only option is to ignore access to parent dirs.
    # Libmuck will not send paths outside of the project directory as long as PROJECT_DIR environment variable is set.
    if dep_abs != ctx.proj_dir: raise BuildError(target, f'requested dependency outside of proj_dir: {dep_abs}')
    return pid, dyn_time

  if (dep in depCtx.ignored_deps) or (path_ext(dep) in ignored_dep_exts):
    return pid, dyn_time
  if dep.startswith(ctx.fetch_dir):
    ctx.create_fetch_dirs()
    return pid, dyn_time
  if (
    ('__pycache__/' in dep) or
    # This is now necessary because python3.7 appears to produce temporary files with extensions like `.pyc.4780302000`.
    # We can either regex for the extension pattern, or just test for the prefix.
    # In general, it seems like the smart approach would be to create one regex for left-to-right match/search,
    # and a separate test that extracts the multi-extension suffix and matches against that.
    ('<frozen importlib._bootstrap' in dep)
    # Both '<frozen importlib._bootstrap>' and '<frozen importlib._bootstrap_external>' appear as stats by python3.
    # These occur in the local source dir after adding a local import to a python script.
    ):
    return pid, dyn_time
  # TODO: further verifications? source dir, etc.

  ctx.dbg(target, f'{mode} dep: {dep}')
  if mode in 'RS':
    if mode == 'S':
      # If the dependency is a stat and appears to be a product, then return.
      # For example, sqlite stats the product before opening it, as do file high level copy operations like pithy.fs.copy_path.
      # This is an imperfect heuristic; we are just guessing whether to treat the stat as a 'read' dependency.
      if (dep == target
       or dep.startswith(target + '/')
       or dep in depCtx.all_outs # This stat is getting metadata on something we just wrote out.
       #^ TODO: handle the reverse order, where we stat something first, then write it.
       or dep in depCtx.restricted_deps_all
       or path_ext(dep) in reserved_or_ignored_exts):
        return pid, dyn_time
    if dep in depCtx.restricted_deps_rd: raise BuildError(target, f'attempted to open restricted file for reading: {dep!r}')
    depCtx.refresh_out_dirs(ctx.dir_entries)
    dep_time = update_target(ctx, fifo=fifo, target=dep, dpdt=dpdt.sub(kind='observed', target=target))
    dyn_time = max(dyn_time, dep_time)
    depCtx.dyn_deps.add(dep)
  elif mode in 'AMUW':
    if dep in depCtx.restricted_deps_wr: raise BuildError(target, f'attempted to open restricted file for writing: {dep!r}')
    ctx.validate_target(dep) # Redundant with update_target in update_deps_and_record. TODO: remove?
    depCtx.add_out(dep)
    set_write_perm(dep)
  else: raise ValueError(f'invalid mode received from libmuck: {mode}')
  return pid, dyn_time


# Dependency inference.

def calculate_dependencies(target:str, dir_entries:DirEntries) -> Tuple[str, ...]:
  '''
  Infer the dependencies for the target.
  '''
  ext = path_ext(target)
  try: deps_fn = ext_tools[ext].deps_fn
  except KeyError: return ()
  if deps_fn is None: return ()
  return tuple(norm_path(dep) for dep in deps_fn(target, dir_entries))


# Type-specific dependency functions.

def html_dependencies(target:str, dir_entries:DirEntries) -> Iterator[str]:
  try: import pithy.html.loader as loader
  except ImportError as e: raise BuildError(target, '`pithy` is not installed; run `pip3 install pithy.`') from e
  html = loader.load_html(target)
  target_dir = path_dir(target)
  for url_str in html.attr_urls:
    scheme, netloc, path, query, fragment = split_url(url_str)
    if not scheme and not netloc: # Only return local urls.
      if not path: continue
      if path.endswith('.html'): continue # For now ignore other pages, which typically cause circular references.
      yield dep_path_for_url_path(target_dir, path)


def list_dependencies(target:str, dir_entries:DirEntries) -> Iterator[str]:
  'Calculate dependencies for .list files.'
  target_dir = path_dir(target)
  with open(target) as f:
    for line in f:
      line = line.strip()
      if line and not line.startswith('#'):
        yield dep_path_for_url_path(target_dir, line)


def sqlite3_dependencies(target:str, dir_entries:DirEntries) -> Iterator[str]:
  'Calculate dependencies for .sql files (assumed to be sqlite3 commands).'
  with open(target) as f:
    for i, line in enumerate(f, 1):
      tokens = sh_split(line)
      for j, token in enumerate(tokens):
        if token == '.open' and j+1 < len(tokens):
          yield tokens[j+1]


def pat_dependencies(target:str, dir_entries:DirEntries) -> Iterator[str]:
  try: import pithy.pat as pat
  except ImportError as e: raise BuildError(target, '`pat` is not installed; run `pip3 install pithy`.') from e
  with open(target) as f:
    dep = pat.pat_dependency(src_path=target, src_lines=f)
  yield dep_path_for_url_path(path_dir(target), dep)


def writeup_dependencies(target:str, dir_entries:DirEntries) -> Iterator[str]:
  try: import wu
  except ImportError as e: raise BuildError(target, '`writeup` is not installed; run `pip3 install wu`.') from e
  with open(target) as f:
    url_deps = wu.writeup_dependencies(src_path=target, text_lines=f)
  target_dir = path_dir(target)
  return (dep_path_for_url_path(target_dir, url_dep) for url_dep in url_deps)


def dep_path_for_url_path(target_dir:str, url_dep:str) -> str:
  'Convert a url path to a dependency path (a path relative to the project directory).'
  if url_dep.startswith('/'): # Relative to project.
    return url_dep.lstrip('/')
  else: # Relative to target.
    return path_join(target_dir, url_dep)


# Tools.

def py_env(ctx:Ctx, env:Dict[str,str]) -> None:
  # Python automatically adds the script's directory path, which when running under muck is also the CWD.
  # Here we add the project root dir as well so that modules/packages can be accessed relative to project root.
  ppath = env.get('PYTHONPATH', '')
  if ppath: ppath += ':' + ctx.proj_dir
  else: ppath = ctx.proj_dir
  env['PYTHONPATH'] = ppath


DependencyFn = Callable[[str,DirEntries], Iterable[str]]
EnvModFn = Callable[[Ctx,Dict[str, str]],None]

class Tool(NamedTuple):
  cmd: Tuple[str, ...]
  deps_fn: Optional[DependencyFn]
  env_mod_fn: Optional[EnvModFn]
  src_to_stdin: bool = False


ext_tools: Dict[str, Tool] = {
  '.bash'   : Tool(('bash',), None, None),
  '.csv'    : Tool(('csv-to-html',), None, None),
  '.dash'   : Tool(('dash',), None, None),
  '.html'   : Tool((), html_dependencies, None),
  '.list'   : Tool((), list_dependencies, None),
  '.md'     : Tool(('cmark-gfm',), None, None),
  '.pat'    : Tool(('pat', 'apply'), pat_dependencies, None),
  '.py'     : Tool(('python3',), py_dependencies, py_env),
  '.sh'     : Tool(('sh',), None, None),
  '.sqlite' : Tool(('sqlite3', '-batch'), sqlite3_dependencies, None, src_to_stdin=True),
  '.wu'     : Tool(('writeup',), writeup_dependencies, None),
}

ignored_dep_exts = {
  '.pyx',
  '.sqlite-journal',
  '.sqlite-shm',
  '.sqlite-wal',
  '.sqlite3-journal',
  '.sqlite3-shm',
  '.sqlite3-wal',
}


# Currently libmuck is installed as a Python C extension,
# which allows us to easily determine the path to the shared library.
_libmuck_modspec = find_module_spec('muck._libmuck')
if _libmuck_modspec is None: exit('error: muck._libmuck is not installed.')
_libmuck_path = _libmuck_modspec.origin
if _libmuck_path is None: exit('error: muck._libmuck path could not be determined.')
libmuck_path = _libmuck_path


# Utilities.


def hash_for_path(path:str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  s = file_status(path, follow=True)
  assert s is not None, path
  if s.is_file: return hash_for_file_contents(path)
  if s.is_dir: return hash_for_dir_listing(path)
  raise BuildError(path, f'path is a {s.type_desc}')


def hash_for_file_contents(path:str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  hash_chunk_size = 1 << 16
  #^ a quick timing experiment suggested that chunk sizes larger than this are not faster.
  try: f = open(path, 'rb')
  except IsADirectoryError: raise BuildError(path, 'expected a file but found a directory')

  try:
    h = Hasher()
    while True:
      chunk = f.read(hash_chunk_size)
      if not chunk: break
      h.update(chunk)
    return h.digest()
  except KeyboardInterrupt:
    errL()
    warn(path, f'interrupted while hashing file: {path!r}')
    raise


def hash_for_dir_listing(path:str) -> bytes:
  '''
  Return a hash string for the directory tree at `path`.
  We define the hash of a directory to include the name and file type of the immediate children.
  This may seem overly simplistic, but consider that when a syscall is made on a directory,
  that is essentially the information that is obtainable;
  recursion into the deep tree by the process requires additional syscalls,
  and will thus trigger additional dependency analysis.
  '''
  try:
    h = Hasher()
    for entry in scan_dir(path, hidden=False): # Ignore hidden files.
      h.update(dir_entry_type_char(entry).encode())
      h.update(entry.name.encode())
      h.update(b'\0')
    return h.digest()
  except KeyboardInterrupt:
    errL()
    warn(path, f'interrupted while hashing directory: {path!r}')
    raise


def file_stats(path:str) -> Tuple[bool, int, float]:
  'Returns (is_dir, size, mtime). Negative size indicates file does not exist.'
  s = file_status(path, follow=True)
  if s is None: return (False, -1, -1)
  return (s.is_dir, s.size, s.mtime)


def disp_mtime(mtime:Optional[float]) -> str:
  return str(DateTime.fromtimestamp(mtime)) if mtime else '0'
