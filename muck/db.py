# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck stores build info in an sqlite3 database.
However the database could be replaced with a key-value store.
'''

from marshal import dumps as to_marshalled, loads as from_marshalled
from sqlite3 import Cursor, DatabaseError, IntegrityError, OperationalError, connect, sqlite_version, version as module_version
from typing import *
from .pithy.fs import path_join
from .pithy.io import errL, errSL
from .pithy.encodings import enc_lep62


class TargetRecord(NamedTuple):
  path:str # target path (not product paths prefixed with build dir).
  is_dir:bool
  size:int
  mtime:float
  change_time:int
  update_time:int
  hash:bytes
  src:Optional[str] # None for non-product sources.
  deps:Tuple[str, ...] # sorted tuple of target path strings.
  dyn_deps:Tuple[str, ...]

  def __str__(self) -> str:
    opts = []
    if self.src: opts.append(f'src={self.src}')
    if self.deps: opts.append(f'deps=[{" ".join(self.deps)}]')
    if self.dyn_deps: opts.append(f'dyn_deps=[{" ".join(self.dyn_deps)}]')
    return (
      f'TargetRecord(path={self.path} is_dir={self.is_dir} size={self.size} mtime={self.mtime} '
      f'change_time={self.change_time} update_time={self.update_time} '
      f'hash={enc_lep62(self.hash)!r}{" " if opts else ""}{" ".join(opts)})')


idx_id, idx_path, idx_is_dir, idx_size, idx_mtime, idx_change_time, idx_update_time, idx_hash, \
idx_src, idx_deps, idx_dyn_deps = range(11)


class DBError(Exception): pass


class DB:

  def __init__(self, path:str) -> None:
    self.path = path
    self.conn = connect(path)
    self.conn.isolation_level = None # autocommit mode.

    try:
      self.run('SELECT COUNT(*) FROM sqlite_master') # dummy query to check file integrity.
    except DatabaseError as e:
      if e.args[0] in {'file is not a database', 'file is encrypted or is not a database'}:
        exit('muck error: build database is outdated or corrupt; run `muck clean-all`.')
      raise #!cov-ignore.

    self.create_table('targets',
      'id INTEGER PRIMARY KEY',
      'path TEXT',
      'is_dir BOOL',
      'size INT',
      'mtime REAL',
      'change_time INT',
      'update_time INT',
      'hash BLOB',
      'src TEXT',
      'deps BLOB',
      'dyn_deps BLOB')

    self.create('UNIQUE INDEX', 'targets_paths', 'ON targets(path)')

    self.create_table('globals',
      'id INTEGER PRIMARY KEY',
      'key BLOB',
      'val BLOB')

    self.create('UNIQUE INDEX', 'globals_keys', 'ON globals(key)')

    self.run('INSERT OR IGNORE INTO globals (key, val) VALUES ("ptime", 0)')



  def run(self, query:str, **args:Any) -> Cursor:
    return self.conn.execute(query, args)


  def fetch_opt(self, query:str, **args:Any) -> Optional[List[Any]]:
    return self.run(query, **args).fetchone() # type: ignore


  def create(self, type:str, name:str, *words:str) -> None:
    'Run a create query, and check that any existing schema matches the current one.'
    row = self.fetch_opt('SELECT sql FROM sqlite_master WHERE name=:name', name=name)
    sql = ' '.join(('CREATE', type, name) + words)
    if row is None:
      try: self.run(sql)
      except OperationalError:
        errSL('sql:', sql)
        raise
    elif sql != row[0]: exit('muck error: build database is outdated; run `muck clean-all`.')


  def create_table(self, name:str, *columns:str) -> None:
    self.create('TABLE', name, f"({', '.join(columns)})")


  def dbg_query(self, *stmts:str) -> None:
    for stmt in stmts: #!cov-ignore.
      errL(f'\nDBG: {stmt}')
      c = self.run(stmt)
      errSL('COLS:', *[col[0] for col in c.description])
      for row in c.fetchall():
        errSL('  ', *['{k}:{v!r}' for k, v in zip(row.keys(), row)])


  def contains_record(self, target:str) -> bool:
    row = self.run('SELECT COUNT(*) FROM targets WHERE path=:path', path=target).fetchone()
    return bool(row[0])


  def get_record(self, target:str) -> Optional[TargetRecord]:
    c = self.run('SELECT * FROM targets WHERE path=:path', path=target)
    rows = c.fetchall()
    if len(rows) > 1:
      raise DBError(f'multiple rows matching target path: {target!r}') #!cov-ignore.
    if rows:
      r = rows[0]
      return TargetRecord(path=target, is_dir=bool(r[idx_is_dir]), size=r[idx_size], mtime=r[idx_mtime],
        change_time=r[idx_change_time], update_time=r[idx_update_time], hash=r[idx_hash], src=r[idx_src],
        deps=from_marshalled(r[idx_deps]), dyn_deps=from_marshalled(r[idx_dyn_deps]))
    else:
      return None


  def insert_or_replace_record(self, record:TargetRecord) -> None:
    try:
      self.run(
        'INSERT OR REPLACE INTO targets (path, is_dir, size, mtime, change_time, update_time, hash, src, deps, dyn_deps) '
        'VALUES (:path, :is_dir, :size, :mtime, :change_time, :update_time, :hash, :src, :deps, :dyn_deps)',
        path=record.path, is_dir=record.is_dir, size=record.size, mtime=record.mtime,
        change_time=record.change_time, update_time=record.update_time,
        hash=record.hash, src=record.src,
        deps=to_marshalled(record.deps), dyn_deps=to_marshalled(record.dyn_deps))
    except IntegrityError as e: #!cov-ignore.
      raise DBError(f'insert_record: target path is not unique: {record.path}') from e


  def delete_record(self, target:str) -> None:
    self.run('DELETE FROM targets WHERE path=:path', path=target)


  def inc_ptime(self) -> int:
    self.run('UPDATE globals SET val = val + 1 WHERE key = "ptime"')
    c = self.run('SELECT val FROM globals WHERE key="ptime"')
    rows = c.fetchall()
    assert len(rows) == 1
    val = rows[0][0]
    assert isinstance(val, int)
    return val


  def get_inferred_deps(self, target:str) -> Tuple[str, ...]:
    record = self.get_record(target)
    assert record is not None
    return record.deps


  def get_dependents(self, target:str) -> Set[str]:
    c = self.run('SELECT path, deps, dyn_deps FROM targets')
    rows = c.fetchall()
    dependents:Set[str] = set()
    for path, deps_blob, dyn_deps_blob in rows:
      d = from_marshalled(dyn_deps_blob)
      if (target in from_marshalled(deps_blob)) or (target in from_marshalled(dyn_deps_blob)):
        dependents.add(path)
    return dependents
