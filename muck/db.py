# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck stores build info in an sqlite3 database.
However the database operations are simple and could be replaced with a simple key-value store.
'''

from marshal import dumps as to_marshalled, loads as from_marshalled
from sqlite3 import Cursor, DatabaseError, IntegrityError, connect, sqlite_version, version as module_version
from typing import *
from .pithy.fs import path_join
from .pithy.io import errL, errSL


class TargetRecord(NamedTuple):
  path: str # target path (not product paths prefixed with build dir).
  size: int
  mtime: float
  change_time: int
  update_time: int
  hash: bytes
  src: Optional[str] # None for non-product sources.
  deps: Tuple[str, ...] # sorted tuple of target path strings.
  dyn_deps: Tuple[str, ...]


class DBError(Exception): pass


idx_id, idx_path, idx_size, idx_mtime, idx_change_time, idx_update_time, idx_hash, idx_src, idx_deps, idx_dyn_deps = range(10)


class DB:

  def __init__(self, path: str) -> None:
    self.conn = connect(path)
    self.conn.isolation_level = None # autocommit mode.

    try:
      self.run('SELECT COUNT(*) FROM sqlite_master') # dummy query to check file integrity.
    except DatabaseError as e:
      if e.args[0] in {'file is not a database', 'file is encrypted or is not a database'}:
        exit('muck error: database is outdated or corrupt; run `muck clean-all`.')
      raise #!cov-ignore.

    self.run('''
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY,
      path TEXT,
      size INT,
      mtime REAL,
      change_time INT,
      update_time INT,
      hash BLOB,
      src TEXT,
      deps BLOB,
      dyn_deps BLOB
    )''')

    self.run('CREATE UNIQUE INDEX IF NOT EXISTS targets_paths ON targets(path)')

    self.run('''
    CREATE TABLE IF NOT EXISTS globals (
      id INTEGER PRIMARY KEY,
      key BLOB,
      val BLOB
    )''')

    self.run('CREATE UNIQUE INDEX IF NOT EXISTS globals_keys ON globals(key)')
    self.run('INSERT OR IGNORE INTO globals (key, val) VALUES ("ptime", 0)')



  def run(self, query: str, **args: Any) -> Cursor:
    return self.conn.execute(query, args)


  def dbg_query(self, *stmts: str) -> None:
    for stmt in stmts: #!cov-ignore.
      errL(f'\nDBG: {stmt}')
      c = self.run(stmt)
      errSL('COLS:', *[col[0] for col in c.description])
      for row in c.fetchall():
        errSL('  ', *['{k}:{v!r}' for k, v in zip(row.keys(), row)])


  def contains_record(self, target: str) -> bool:
    c = self.run('SELECT COUNT(*) FROM targets WHERE path=:path', path=target)
    count = c.fetchone()[0]
    return bool(count)


  def get_record(self, target: str) -> Optional[TargetRecord]:
    c = self.run('SELECT * FROM targets WHERE path=:path', path=target)
    rows = c.fetchall()
    if len(rows) > 1:
      raise DBError(f'multiple rows matching target path: {target!r}') #!cov-ignore.
    if rows:
      r = rows[0]
      return TargetRecord(target, r[idx_size], r[idx_mtime], r[idx_change_time], r[idx_update_time], r[idx_hash], r[idx_src],
        from_marshalled(r[idx_deps]), from_marshalled(r[idx_dyn_deps]))
    else:
      return None


  def insert_or_replace_record(self, record: TargetRecord) -> None:
    try:
      self.run(
        'INSERT OR REPLACE INTO targets (path, size, mtime, change_time, update_time, hash, src, deps, dyn_deps) '
        'VALUES (:path, :size, :mtime, :change_time, :update_time, :hash, :src, :deps, :dyn_deps)',
        path=record.path, size=record.size, mtime=record.mtime, change_time=record.change_time, update_time=record.update_time,
        hash=record.hash, src=record.src,
        deps=to_marshalled(record.deps), dyn_deps=to_marshalled(record.dyn_deps))
    except IntegrityError as e: #!cov-ignore.
      raise DBError(f'insert_record: target path is not unique: {record.path}') from e


  def delete_record(self, target: str) -> None:
    self.run('DELETE FROM targets WHERE path=:path', path=target)


  def inc_ptime(self) -> int:
    self.run('UPDATE globals SET val = val + 1 WHERE key = "ptime"')
    c = self.run('SELECT val FROM globals WHERE key="ptime"')
    rows = c.fetchall()
    assert len(rows) == 1
    val = rows[0][0]
    assert isinstance(val, int)
    return val


