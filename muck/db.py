# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck stores build info in an sqlite3 database.
It is a single table and could be swapped out for a different key-value store.
'''

from marshal import dumps as to_marshalled, loads as from_marshalled
from sqlite3 import Cursor, DatabaseError, IntegrityError, connect, sqlite_version, version as module_version
from typing import *
from .pithy.fs import path_join
from .pithy.io import errL, errSL


class TargetRecord(NamedTuple):
  path: str # target path (not product paths prefixed with build dir).
  size: int # 0 for empty/missing records, but can also be 0 for legitimate records.
  mtime: float # 0 for empty/missing records.
  hash: Optional[bytes]
  src: Optional[str] # None for non-product sources.
  deps: Tuple[str, ...] # sorted tuple of target path strings.
  dyn_deps: Tuple[str, ...]


def empty_record(target: str) -> TargetRecord:
  return TargetRecord(path=target, size=0, mtime=0, hash=None, src=None, deps=(), dyn_deps=())


def is_empty_record(record: TargetRecord) -> bool:
  return record.hash is None


class DBError(Exception): pass


idx_id, idx_path, idx_size, idx_mtime, idx_hash, idx_src, idx_deps, idx_dyn_deps = range(8)


class DB:

  def __init__(self, path: str) -> None:
    self.conn = connect(path)
    self.conn.isolation_level = None # autocommit mode.

    try:
      self.run('SELECT COUNT(*) FROM sqlite_master') # dummy query to check file integrity.
    except DatabaseError as e:
      if e.args[0] == 'file is encrypted or is not a database':
        exit('muck error: database is outdated or corrupt; run `muck clean-all`.')
      raise #!cov-ignore.

    self.run('''
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY,
      path TEXT,
      size INT,
      mtime REAL,
      hash BLOB,
      src TEXT,
      deps BLOB,
      dyn_deps BLOB
    )''')

    self.run('CREATE UNIQUE INDEX IF NOT EXISTS target_paths ON targets(path)')


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


  def get_record(self, target: str) -> TargetRecord:
    c = self.run('SELECT * FROM targets WHERE path=:path', path=target)
    rows = c.fetchall()
    if len(rows) > 1:
      raise DBError(f'multiple rows matching target path: {target!r}') #!cov-ignore.
    if rows:
      r = rows[0]
      return TargetRecord(target, r[idx_size], r[idx_mtime], r[idx_hash], r[idx_src],
        from_marshalled(r[idx_deps]), from_marshalled(r[idx_dyn_deps]))
    else:
      return empty_record(target)


  def update_record(self, record: TargetRecord) -> None:
    self.run(
      'UPDATE targets SET '
      'size=:size, mtime=:mtime, hash=:hash, src=:src, deps=:deps, dyn_deps=:dyn_deps '
      'WHERE path=:path',
      size=record.size, mtime=record.mtime, hash=record.hash, src=record.src,
      deps=to_marshalled(record.deps), dyn_deps=to_marshalled(record.dyn_deps),
      path=record.path)


  def insert_record(self, record: TargetRecord) -> None:
    try:
      self.run(
        'INSERT INTO targets (path, size, mtime, hash, src, deps, dyn_deps) '
        'VALUES (:path, :size, :mtime, :hash, :src, :deps, :dyn_deps)',
        path=record.path, size=record.size, mtime=record.mtime, hash=record.hash, src=record.src,
        deps=to_marshalled(record.deps), dyn_deps=to_marshalled(record.dyn_deps))
    except IntegrityError as e: #!cov-ignore.
      raise DBError(f'insert_record: target path is not unique: {record.path}') from e


  def delete_record(self, target: str) -> None:
    self.run('DELETE FROM targets WHERE path=:path', path=target)


