# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck's core update algorithm.
'''

from contextlib import nullcontext
from datetime import datetime as DateTime
from hashlib import blake2b
from importlib.util import find_spec as find_module_spec
from os import (O_RDONLY, O_NONBLOCK,
  environ, kill, mkfifo, open as os_open, read as os_read, close as os_close, remove as os_remove)
from shlex import quote as sh_quote, split as sh_split
from signal import SIGCONT
from time import sleep, time as now
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Set, TextIO, Tuple, cast

from .constants import *
from .ctx import Ctx, Dependent, InvalidTarget, TargetNotFound, TargetStatus, match_wilds
from .db import DB, DBError, TargetRecord
from .logging import error, error_msg, note, warn
from .pithy.ansi import RST, TXT_G
from .pithy.fs import (FileStatus, PathIsNotDescendantError, current_dir, dir_entry_type_char, file_size, file_status, is_dir,
  is_dir_not_link, is_file_executable_by_owner, is_link, is_path_abs, make_dir, make_dirs, make_link, move_file, path_dir,
  path_exists, path_ext, path_rel_to_ancestor, read_link, remove_file, remove_path, remove_path_if_exists, scan_dir)
from .pithy.io import AsyncLineReader, errL
from .pithy.string import format_byte_count
from .pithy.task import launch
from .py_deps import py_dependencies


def update_top(ctx:Ctx, target:str) -> int:

  # Create the FIFO.
  try:
    mkfifo(ctx.fifo_path, mode=0o600)
  except OSError as e:
    if path_exists(ctx.fifo_path):
      raise error(ctx.fifo_path, 'FIFO path already exists; another `muck` process is either running or previously failed.') from e
    raise

  try:
    try: fifo = AsyncLineReader(ctx.fifo_path)
    except Exception as e: raise error(ctx.fifo_path, 'FIFO path could not be opened for reading.') from e

    with fifo:
      try: return update_target(ctx, fifo=fifo, target=target, dependent=None, force=ctx.args.force)
      except TargetNotFound as e: raise error(*e.args) from e

  finally: # Remove the FIFO.
    try:
      os_remove(ctx.fifo_path)
    except Exception as e:
      raise error(ctx.fifo_path, 'fifo could not be removed.')


def update_target(ctx:Ctx, fifo:AsyncLineReader, target:str, dependent:Optional[Dependent], force=False) -> int:
  '''
  The central function of the Muck.
  returns transitive change_time.
  '''
  ctx.validate_target_or_error(target)

  if dependent is not None:
    ctx.dependents[target].add(dependent)

  # Recursion check.
  try: target_status = ctx.statuses[target]
  except KeyError: pass
  else: # if in ctx.statuses, this path has already been visited during this build process run.
    if not target_status.is_updated: # recursion check.
      involved_paths = sorted(path for path, s in ctx.statuses.items() if not s.is_updated)
      raise error(target, 'target has circular dependency; involved paths:', *('\n  ' + p for p in involved_paths))
    elif target_status.error is not None: # Previously encountered TargetNotFound exception; reraise.
      raise TargetNotFound(*target_status.error)
    return target_status.change_time

  target_status = ctx.statuses[target] = TargetStatus() # Update_deps_and_record updates the status upon completion.
  ctx.dbg(target, f'{TXT_G}update; {dependent or "<requested>"}{RST}')

  status = file_status(target) # follows symlinks.
  if status is None and is_link(target):
    raise error(target, f'target is a dangling symlink to: {read_link(target)}')

  is_product = status is None # A target is a product if it does not exist in the source tree.

  if is_product:
    target_dir = path_dir(target)
    if target_dir and not path_exists(target_dir): # Not possible to find a source; must be the contents of a built directory.
      update_target(ctx, fifo=fifo, target=target_dir, dependent=Dependent(kind='directory contents', target=target), force=force)
      if not target_status.is_updated: # build of parent did not create this product.
        raise error(target, f'target resides in a product directory but was not created by building that directory')
      return target_status.change_time # TODO: verify that we should be returning this change_time and not the result of target_dir update.

  old = ctx.db.get_record(target=target)
  needs_update = force or (old is None)

  if old is not None:
    old_is_product = (old.src is not None)
    if is_product != old_is_product: # nature of the target changed.
      note(target, f"target is {'now' if is_product else 'no longer'} a product.")
      needs_update = True

  if is_product:
    try:
      return update_product(ctx, fifo=fifo, target=target, needs_update=needs_update, old=old)
    except TargetNotFound as e:
      target_status.error = e.args
      raise
  else:
    assert status
    return update_non_product(ctx, fifo=fifo, target=target, status=status, needs_update=needs_update, old=old)


def check_product_not_modified(ctx:Ctx, target:str, prod_path:str, is_prod_dir:int, size:int, mtime:float, old:TargetRecord) -> None:
  # Existing product should not have been modified since record was stored.
  # If is_dir or size changed then it was definitely modified.
  if is_prod_dir == old.is_dir and size == old.size:
    # Otherwise, if the mtime is unchanged, assume that the contents are unchanged, for speed.
    if mtime == old.mtime: return
    # if mtime is changed but contents are not, the user might have made an accidental edit and then reverted it.
    if hash_for_path(prod_path) == old.hash:
      note(target, f'product mtime changed but contents did not: {disp_mtime(old.mtime)} -> {disp_mtime(mtime)}.')
      # TODO: revert mtime?
      return
  # TODO: change language depending on whether product is derived from a patch?
  raise error(target, 'existing product has changed; did you mean to update a patch?\n'
    f'  Otherwise, save your changes if necessary and then `muck clean {target}`.')


def update_product(ctx:Ctx, fifo:AsyncLineReader, target:str, needs_update:bool, old:Optional[TargetRecord]) -> int:
  '''
  Returns transitive change_time.
  Note: we must pass the just-retrieved mtime, in case it has changed but product contents have not.
  '''
  ctx.dbg(target, 'update_product')
  prod_path = ctx.product_path_for_target(target)

  is_prod_dir, size, mtime = file_stats(prod_path)

  if old is not None: # Old record exists.
    if size < 0: # Old file was deleted.
      needs_update = True
    else:
      check_product_not_modified(ctx, target, prod_path=prod_path, is_prod_dir=is_prod_dir, size=size, mtime=mtime, old=old)

  src = ctx.source_for_target(target)
  ctx.validate_target_or_error(src)
  ctx.dbg(target, f'src: ', src)
  if old is not None and old.src != src:
    needs_update = True
    note(target, f'source path of target product changed\n  was: {old.src}\n  now: {src}')

  # Update and change times are logical times (incrementing counters), depending only on internal DB state.
  # This design avoids dependency on file system time stamps and OS clocks.
  # For file systems with poor time resolution (e.g. HFS mtime is 1 sec resolution), this is important.
  last_update_time = 0 if old is None else old.update_time
  src_change_time = update_target(ctx, fifo=fifo, target=src, dependent=Dependent(kind='source', target=target))
  needs_update = needs_update or last_update_time < src_change_time
  update_time = max(last_update_time, src_change_time)

  if not needs_update: # src has not changed since update.
    # check if any of the previously recorded dynamic dependencies have changed;
    # if they have not, then no rebuild is necessary.
    assert old is not None
    for dyn_dep in old.dyn_deps:
      dep_change_time = update_target(ctx, fifo=fifo, target=dyn_dep, dependent=Dependent(kind='observed', target=target))
      update_time = max(update_time, dep_change_time)
  needs_update = needs_update or last_update_time < update_time

  if needs_update: # must rebuild product.
    dyn_change_time, dyn_deps, all_outs = build_product(ctx, fifo=fifo, target=target, src_path=src, prod_path=prod_path)
    update_time = max(update_time, dyn_change_time)
    ctx.dbg(target, f'all_outs: {all_outs}')
    assert target in all_outs
    change_time = 0
    for product in sorted(all_outs):
      product_change_time = update_product_with_output(ctx, fifo=fifo, target=product, src=src, dyn_deps=dyn_deps, update_time=update_time)
      if product == target:
        change_time = product_change_time
    assert change_time > 0
    return change_time
  else: # not needs_update.
    assert old is not None
    return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=False, actual_path=prod_path, is_changed=False,
      size=old.size, mtime=mtime, change_time=old.change_time, update_time=update_time, file_hash=old.hash, src=src,
      dyn_deps=old.dyn_deps, old=old)


def update_product_with_output(ctx:Ctx, fifo:AsyncLineReader, target:str, src:str, dyn_deps:Tuple[str, ...], update_time:int) -> int:
  'Returns (target, change_time).'
  old = ctx.db.get_record(target=target)
  path = ctx.product_path_for_target(target)
  is_target_dir, size, mtime = file_stats(path)
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
  return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=is_target_dir, actual_path=path, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=update_time, file_hash=file_hash, src=src, dyn_deps=dyn_deps,
    old=old)


def update_non_product(ctx:Ctx, fifo:AsyncLineReader, target:str, status:FileStatus, needs_update:bool, old:Optional[TargetRecord]) -> int:
  'returns transitive change_time.'
  ctx.dbg(target, 'update_non_product')

  is_target_dir = status.is_dir
  size = status.size
  mtime = status.mtime
  prod_path = ctx.product_path_for_target(target)
  prod_status = file_status(prod_path)

  if needs_update or prod_status is None or (is_target_dir != prod_status.is_dir):
    is_changed = True
    target_hash = hash_for_path(target)
  elif (old is None or is_target_dir or size != old.size or mtime != old.mtime):
    # All we know so far is that the asset exists, dir/file is not changed, and product/non-product is not changed.
    # Note that if the target is a directory, then we must recalculate the hash, because mtime will not reflect changes.
    target_hash = hash_for_path(target)
    is_changed = (old is None or old.hash != target_hash)
  else: # assume not changed based on size/mtime; otherwise we constantly recalculate hashes for large sources.
    is_changed = False
    target_hash = old.hash

  if is_changed:

    if is_target_dir:
      if prod_status and not prod_status.is_dir: # Old product is not a true directory.
        remove_file(prod_path)
      if not (prod_status and prod_status.is_dir):
        make_dirs(prod_path)
      # Link contents of source dir into prod dir.
      prod_entries = {e.path : e for e in scan_dir(prod_path)}
      for entry in scan_dir(target):
        entry_prod_path = ctx.product_path_for_target(entry.path)
        prod_entry = prod_entries.pop(entry_prod_path, None)
        if entry.is_dir():
          if not prod_entry:
            make_dir(entry_prod_path)
          elif not prod_entry.is_dir(follow_symlinks=False): # Child already exists, but not a directory.
            remove_file(entry_prod_path)
            make_dir(entry_prod_path)
        else: # asset is a file.
          # For now just always rewrite the links.
          # Could try to optimize this, but would need to read_link and compare which is tricky.
          if prod_entry: remove_path(entry_prod_path)
          make_link(entry.path, link=entry_prod_path)
      # Remove remaining prod_entries, which did not match entries in source and are therefore stale.
      for entry in prod_entries.values():
        assert entry.is_symlink(), entry
        remove_file(entry.path)

    else: # target is regular file.
      if prod_status: remove_path(prod_path)
      make_link(target, link=prod_path, create_dirs=True)

    if not needs_update: note(target, 'source changed.') # only want to report this on subsequent changes.
    change_time = ctx.db.inc_ptime()

  else: # not changed.
    assert old is not None
    change_time = old.change_time
    target_hash = old.hash
    if mtime != old.mtime:
      note(target, f'source modification time changed but contents did not.')

  return update_deps_and_record(ctx, fifo=fifo, target=target, is_target_dir=False, actual_path=target, is_changed=is_changed,
    size=size, mtime=mtime, change_time=change_time, update_time=change_time, file_hash=target_hash, src=None, dyn_deps=(), old=old)
  # TODO: non_product update_time is meaningless? mark as -1?


def update_deps_and_record(ctx, fifo:AsyncLineReader, target:str, is_target_dir:bool, actual_path:str, is_changed:bool,
 size:int, mtime:float, change_time:int, update_time:int, file_hash:bytes, src:Optional[str], dyn_deps:Tuple[str, ...],
 old:Optional[TargetRecord]) -> int:
  'returns transitive change_time.'

  ctx.dbg(target, 'update_deps_and_record')
  if is_changed:
    deps = calculate_dependencies(actual_path, ctx.dir_names)
    for dep in deps:
      try: ctx.validate_target(dep)
      except InvalidTarget as e:
        raise error(target, f'invalid dependency: {e.target!r}: {e.msg}')
  else:
    assert old is not None
    deps = old.deps

  for dep in deps:
    dep_change_time = update_target(ctx, fifo=fifo, target=dep, dependent=Dependent(kind='inferred', target=target))
    change_time = max(change_time, dep_change_time)
  update_time = max(update_time, change_time)

  try: status = ctx.statuses[target]
  except KeyError:
    status = TargetStatus()
    ctx.statuses[target] = status
  else:
    if status.is_updated:
      raise error(target, f'target was updated by both a script and a dependency') # TODO: track updater in TargetStatus.

  status.is_updated = True
  status.change_time = change_time
  # always update record, because even if is_changed=False, mtime may have changed.
  record = TargetRecord(path=target, is_dir=is_target_dir, size=size, mtime=mtime,
    change_time=change_time, update_time=update_time, hash=file_hash, src=src, deps=deps, dyn_deps=dyn_deps)
  ctx.dbg(target, f'updated: ', record)
  ctx.db.insert_or_replace_record(record)
  return change_time


# Build.


class DepCtx(NamedTuple):
  ignored_deps: Set[str]
  restricted_deps_rd: Set[str]
  restricted_deps_wr: Set[str]
  dyn_deps: Set[str]
  all_outs: Set[str]



def build_product(ctx:Ctx, fifo:AsyncLineReader, target:str, src_path:str, prod_path:str) -> Tuple[int, Tuple[str, ...], Set[str]]:
  '''
  Run a source file, producing zero or more products.
  Return a list of produced product paths.
  '''
  src_prod_path = ctx.product_path_for_target(src_path)
  src_ext = path_ext(src_path)
  prod_dir = path_dir(prod_path)
  prod_path_out = prod_path + out_ext

  if is_dir(src_prod_path):
    raise error(target, f'source path is a directory: {src_prod_path!r}')
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
  m = match_wilds(ctx.target_for_source(src_path), target)
  if m is None:
    raise error(target, f'internal error: match failed; src_path: {src_path!r}')
  args = tuple(m.groups())
  src_arg = cast(Tuple[str, ...], () if tool.src_to_stdin else (src_path,))
  cmd = [*tool.cmd, *src_arg, *args]

  msg_stdin = f' < {src_path}' if tool.src_to_stdin else ''
  note(target, f"building: `{' '.join(sh_quote(w) for w in cmd)}{msg_stdin}`")

  make_dirs(prod_dir)
  remove_path_if_exists(prod_path_out)
  remove_path_if_exists(prod_path)

  env = environ.copy()
  # TODO: check that these variables are not already set.
  env['MUCK_TARGET'] = target
  if tool.env_fn is not None:
    env.update(tool.env_fn())
  env['MUCK_PROJ_DIR'] = ctx.proj_dir
  env['MUCK_FIFO'] = ctx.fifo_path
  env['MUCK_PID'] = ctx.pid_str
  env['DYLD_INSERT_LIBRARIES'] = libmuck_path
  #env['DYLD_FORCE_FLAT_NAMESPACE'] = 'TRUE'
  #env['DYLD_PRINT_LIBRARIES'] = 'TRUE'
  if ctx.dbg_child:
    env['MUCK_DEPS_DBG'] = 'TRUE'

  # Get the source's inferred dependencies, to be ignored when observing target dependencies.
  ignored_deps = set(ctx.db.get_inferred_deps(target=src_path))
  ignored_deps.update(['.', src_path])

  depCtx = DepCtx(
    ignored_deps=ignored_deps,
    restricted_deps_rd={
      ctx.db.path,
      ctx.fifo_path,
      prod_path_out,
    },
    restricted_deps_wr={
      ctx.db.path,
      ctx.fifo_path,
      prod_path_out, # muck process opens this for the child.
      src_path,
    },
    dyn_deps=set(),
    all_outs=set())

  dyn_time = 0
  in_cm = open(src_prod_path, 'rb') if tool.src_to_stdin else nullcontext(None)
  with in_cm as in_file, open(prod_path_out, 'wb') as out_file: # type: ignore
    time_start = now()
    _, proc, _ = launch(cmd, cwd=ctx.build_dir, env=env, stdin=in_file, out=out_file, lldb=ctx.dbg_child_lldb)
    if in_file: in_file.close()
    out_file.close()
    possible_causes: List[Tuple[str, ...]] = []
    # For now, the best we can do is poll the nonblocking FIFO reader for deplines and the task for completion.
    try:
      while proc.poll() is None: # Child process has not terminated yet.
        dep_line = fifo.readline()
        if dep_line:
          try:
            dep_pid, dyn_time = handle_dep_line(ctx, depCtx=depCtx, fifo=fifo, target=target, dep_line=dep_line, dyn_time=dyn_time)
          except TargetNotFound as e:
            possible_causes.append(e.args)
          kill(dep_pid, SIGCONT) # Tell whichever process sent the dep to continue.
        else:
          sleep(0.00001) # Sleep for a minimal duration.
    except BaseException:
      proc.kill()
      #^ Killing the script avoids a confusing exception message from the child script when muck fails,
      #^ and/or zombie child processes (e.g. sqlite3).
      for cause in possible_causes:
        errL(error_msg(*cause))
      raise
    code = proc.returncode
    time_elapsed = now() - time_start

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
  return dyn_time, tuple(sorted(depCtx.dyn_deps)), depCtx.all_outs


def handle_dep_line(ctx:Ctx, fifo:AsyncLineReader, depCtx:DepCtx, target:str, dep_line:str, dyn_time:int) -> Tuple[int, int]:
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
    pid_str, call, mode, dep = dep_line_parts
    pid = int(pid_str)
    if not (dep and dep[-1] == '\n'): raise ValueError
    dep = dep[:-1] # remove final newline.
  except ValueError as e:
    raise error(target, f'child process sent bad dependency line:\n{dep_line!r}') from e

  if not is_path_abs(dep): # libmuck converts all paths to absolute, because only the child knows its own current directory.
    raise ValueError(f'libmuck sent relative path: {dep}')
  try: dep = path_rel_to_ancestor(dep, ancestor=ctx.build_dir_abs, dot=True)
  except PathIsNotDescendantError:
    # We cannot differentiate between harmless and ill-advised accesses outside of the build directory.
    # In particular, as long as the project dir is the parent of build_dir,
    # we cannot sensibly prevent a script from accessing the project dir directly.
    # For example, Python accesses the parent directory during startup.
    # Therefore our only option is to ignore access to parent dirs.
    # Libmuck will not send paths outside of the project directory as long as MUCK_PROJECT_DIR is set.
    if dep != ctx.proj_dir: ctx.dbg(target, f'requested dependency outside of build_dir: {dep}')
    return pid, dyn_time

  if (dep in depCtx.ignored_deps) or (path_ext(dep) in ignored_dep_exts):
    return pid, dyn_time
  # TODO: further verifications? source dir, etc.

  ctx.dbg(target, f'{mode} dep: {dep}')
  assert not is_path_abs(dep)
  if mode in 'RS':
    if mode == 'S' and dep == target:
      return pid, dyn_time # sqlite stats the db before opening. Imperfect, but better than nothing.
    if dep in depCtx.restricted_deps_rd: raise error(target, f'attempted to open restricted file for reading: {dep!r}')
    dep_time = update_target(ctx, fifo=fifo, target=dep, dependent=Dependent(kind='observed', target=target))
    dyn_time = max(dyn_time, dep_time)
    depCtx.dyn_deps.add(dep)
  elif mode in 'AMUW':
    if dep in depCtx.restricted_deps_wr: raise error(target, f'attempted to open restricted file for writing: {dep!r}')
    ctx.validate_target_or_error(dep)
    depCtx.all_outs.add(dep)
  else: raise ValueError(f'invalid mode received from libmuck: {mode}')
  return pid, dyn_time


# Dependency inference.

def calculate_dependencies(path:str, dir_names:Dict[str, Tuple[str, ...]]) -> Tuple[str, ...]:
  '''
  Infer the dependencies for the file at `path`.
  '''
  ext = path_ext(path)
  try: deps_fn = ext_tools[ext].deps_fn
  except KeyError: return ()
  if deps_fn is None: return ()
  with open(path) as f:
    return tuple(deps_fn(path, f, dir_names))


# Type-specific dependency functions.

def list_dependencies(src_path:str, src_file:TextIO, dir_names:Dict[str, Tuple[str, ...]]) -> List[str]:
  'Calculate dependencies for .list files.'
  lines = (line.strip() for line in src_file)
  return [l for l in lines if l and not l.startswith('#')]


def sqlite3_dependencies(src_path:str, src_file:TextIO, dir_names:Dict[str, Tuple[str, ...]]) -> Iterable[str]:
  'Calculate dependencies for .sql files (assumed to be sqlite3 commands).'
  for i, line in enumerate(src_file, 1):
    tokens = sh_split(line)
    for j, token in enumerate(tokens):
      if token == '.open' and j+1 < len(tokens):
        yield tokens[j+1]


def pat_dependencies(src_path:str, src_file:TextIO, dir_names:Dict[str, Tuple[str, ...]]) -> List[str]:
  try: import pithy.pat as pat
  except ImportError: error(src_path, '`pat` is not installed; run `pip install pithy`.')
  dep = pat.pat_dependency(src_path=src_path, src_file=src_file)
  return [dep]


def writeup_dependencies(src_path:str, src_file:TextIO, dir_names:Dict[str, Tuple[str, ...]]) -> List[str]:
  try: import writeup
  except ImportError: raise error(src_path, '`writeup` is not installed; run `pip install pithy`.')
  return writeup.writeup_dependencies(src_path=src_path, text_lines=src_file)


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
  '.bash' : Tool(('bash',), None, None),
  '.csv'  : Tool(('csv-to-html',), None, None),
  '.dash' : Tool(('dash',), None, None),
  '.list' : Tool((), list_dependencies, None),
  '.md'   : Tool(('cmark-gfm',), None, None),
  '.pat'  : Tool(('pat', 'apply'), pat_dependencies, None),
  '.py'   : Tool(('python3',), py_dependencies, py_env),
  '.sh'   : Tool(('bash',), None, None), # TODO: change to `sh` once we get dash working.
  '.sql'  : Tool(('sqlite3', '-batch'), sqlite3_dependencies, None, src_to_stdin=True),
  '.wu'   : Tool(('writeup',), writeup_dependencies, None),
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
  s = file_status(path)
  assert s is not None
  if s.is_file: return hash_for_file_contents(path)
  if s.is_dir: return hash_for_dir_listing(path)
  raise error(path, f'path is a {s.type_desc}')


def hash_for_file_contents(path:str) -> bytes:
  '''
  Return a hash string for the contents of the file at `path`.
  '''
  hash_chunk_size = 1 << 16
  #^ a quick timing experiment suggested that chunk sizes larger than this are not faster.
  try: f = open(path, 'rb')
  except IsADirectoryError: raise error(path, 'expected a file but found a directory')

  try:
    h = blake2b(digest_size=32)
    while True:
      chunk = f.read(hash_chunk_size)
      if not chunk: break
      h.update(chunk)
    return h.digest()
  except KeyboardInterrupt:
    errL()
    warn(path, 'interrupted while hashing file.')
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
  h =  blake2b(digest_size=32)
  for entry in scan_dir(path, hidden=False): # Ignore hidden files.
    h.update(dir_entry_type_char(entry).encode())
    h.update(entry.name.encode())
    h.update(b'\0')
  return h.digest()


def file_stats(path:str) -> Tuple[bool, int, float]:
  'Returns (is_dir, size, mtime). Negative size indicates file does not exist.'
  s = file_status(path)
  if s is None: return (False, -1, -1)
  return (s.is_dir, s.size, s.mtime)


def disp_mtime(mtime:Optional[float]) -> str:
  return str(DateTime.fromtimestamp(mtime)) if mtime else '0'