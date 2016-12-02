# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

'''
Muck stores build info in an sqlite3 database.
It is a single table and could be swapped out for a different key-value store.
'''

from collections import namedtuple
from marshal import dumps as to_marshalled, loads as from_marshalled
from sqlite3 import DatabaseError, IntegrityError, connect, sqlite_version, version as module_version
from pithy.fs import path_join
from pithy.io import failF


TargetRecord = namedtuple('TargetRecord', 'path size mtime hash src deps')
'''
TargetRecord format:
 path: target path (not product paths prefixed with build_dir).
 size: int (0 for empty/missing records, but can also be 0 for legitimate records).
 mtime: float (0 for empty/missing records).
 src: Optional[str]; None for non-product sources.
 deps: sorted tuple of target path strings.
'''


def empty_record(target_path):
  return TargetRecord(path=target_path, size=0, mtime=0, hash=None, src=None, deps=())


def is_empty_record(record):
  return record.hash is None


class DBError(Exception):
  def __init__(self, fmt, *items, **kw):
    super().__init__(fmt.format(*items, **kw))


idx_id, idx_path, idx_size, idx_mtime, idx_hash, idx_src, idx_deps = range(7)


def all_deps_for_target(ctx, target):
  record = ctx.db[target]
  if record.src is not None:
    return [record.src] + record.deps
  else:
    return record.deps


class DB:

  def __init__(self, path):
    self.conn = connect(path)
    self.conn.isolation_level = None # autocommit mode.

    try:
      self.run('SELECT COUNT(*) FROM sqlite_master') # dummy query to check file integrity.
    except DatabaseError as e:
      if e.args[0] == 'file is encrypted or is not a database':
        failF('muck error: database is outdated or corrupt; run `muck clean-all`.')
      else: raise

    self.run('''
    CREATE TABLE IF NOT EXISTS targets (
      id INTEGER PRIMARY KEY,
      path TEXT,
      size INT,
      mtime REAL,
      hash BLOB,
      src TEXT,
      deps BLOB
    )''')

    self.run('CREATE UNIQUE INDEX IF NOT EXISTS target_paths ON targets(path)')


  def run(self, query, **args):
    return self.conn.execute(query, args)


  def contains_record(self, target_path):
    c = self.run('SELECT COUNT(*) FROM targets WHERE path=:path', path=target_path)
    count = c.fetchone()[0]
    return bool(count)


  def all_target_paths(self):
    for row in self.run('SELECT path FROM targets'):
      yield row[0]


  def get_record(self, target_path):
    c = self.run('SELECT * FROM targets WHERE path=:path', path=target_path)
    rows = c.fetchall()
    if len(rows) > 1:
      raise DBError('multiple rows matching target path: {!r}', target_path)
    if rows:
      r = rows[0]
      return TargetRecord(target_path, r[idx_size], r[idx_mtime], r[idx_hash], r[idx_src], from_marshalled(r[idx_deps]))
    else:
      return empty_record(target_path)


  def update_record(self, record: TargetRecord):
    self.run('UPDATE targets SET size=:size, mtime=:mtime, hash=:hash, src=:src, deps=:deps WHERE path=:path',
      path=record.path, size=record.size, mtime=record.mtime, hash=record.hash, src=record.src, deps=to_marshalled(record.deps))


  def insert_record(self, record: TargetRecord):
    try:
      self.run('INSERT INTO targets (path, size, mtime, hash, src, deps) VALUES (:path, :size, :mtime, :hash, :src, :deps)',
        path=record.path, size=record.size, mtime=record.mtime, hash=record.hash, src=record.src, deps=to_marshalled(record.deps))
    except IntegrityError as e:
      raise DBError('insert_record: target path is not unique: {}', record.path) from e


  def delete_record(self, target_path: str):
    self.run('DELETE FROM targets WHERE path=:path', path=target_path)


  def dbg_query(self, *stmts):
    for stmt in stmts:
      errFL('\nDBG: {}', stmt)
      c = self.run(stmt)
      errSL('COLS:', *[col[0] for col in c.description])
      for row in c.fetchall():
        errSL('  ', *['{}:{!r}'.format(k, v) for k, v in zip(row.keys(), row)])



# Build info.


def all_deps_for_target(ctx, target):
  record = ctx.db[target]
  if record.src is not None:
    return [record.src] + record.deps
  else:
    return record.deps


'''
Database format:
 'target': target path (not product paths prefixed with build_dir).
 'val: TargetRecord.
 src is None for non-product sources.
 Each dependency is a target path.
 TODO: save info about muck version itself in the dict under reserved name 'muck'.
'''

def load_db():
  try:
    with open(db_path) as f:
      return load_json(f, types=(TargetRecord,))
  except FileNotFoundError:
    return {}
  except json.JSONDecodeError as e:
    warnF(db_path, 'JSON decode failed; ignoring build database ({}).', e)
    return {}


def save_db(db: dict):
  with open(db_path, 'w') as f:
    write_json(f, { k: record._asdict() for k, record in db.items() })




def main():
  #dbg_query('SELECT * FROM sqlite_master')
  #dbg_query('EXPLAIN QUERY PLAN SELECT * FROM targets WHERE path=""');
  db = DB(':memory:')

  db.insert_record(TargetRecord('a', size=0, mtime=1, hash=b'abcd', src='', deps=()))
  errSL('GET A:', db.get_record('a'))
  errSL('ALL:', *db.all_target_paths())
  errFL('CONTAINS a: {}; b: {}', db.contains_record('a'), db.contains_record('b'))
  db.insert_record(TargetRecord('a', size=1, mtime=2, hash=b'zzzz', src='', deps=('b', 'c')))
  errSL('GET A:', db.get_record('a'))

if __name__ == '__main__': main()
