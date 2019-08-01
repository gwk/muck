// Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

// This dynamic library provides a replacement of several system calls, most notably the `open` function.
// It is meant to be loaded by Muck client processes via DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux).
// The replacement functions wrap the originals, but first notify the Muck parent process of the file being opened,
// thus providing the build system with an opportunity to update dependencies.

// We will probably need to implement additional syscall wrappers.
// Choosing which ones to wrap is a critical design concern,
// because we are essentially creating on-demand semantics for the file system.

// For a list of system calls on a unix system, try `apropos . | grep '(2)'`.

// Currently, libmuck is installed as a Python C extension dynamic library.
// This is something of a hack, because it is not a legitimate Python extension.
// If you try to import it you will get: `ImportError: dynamic module does not define module export function (PyInit_libmuck)`.
// We could make it behave like a real python module, but there is no real benefit.
// The downside would be that a real module might cause extra dynamic linking whenever this library is loaded for every client process.
//PyMODINIT_FUNC PyInit_libmuck(void) { return PyModule_Create(&libmuck); }

// If we use secret initialization, then siphash becomes resistant to collision attacks
// but hash table bugs become harder to reproduce.
#define MUCK_USE_SECURE_HASH 0

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc/malloc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/param.h>

// macOS interposition macro.
// source: https://opensource.apple.com/source/dyld/dyld-519.2.1/include/mach-o/dyld-interposing.h
#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = \
{ (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee }

#define INTERPOSE(name) DYLD_INTERPOSE(muck_##name, name)


// Type aliases.

typedef size_t Size;
typedef uint64_t Hash;
typedef uint64_t Idx;
typedef uint8_t U8;

// Diagnostic macros.

static const char* program_name = "?";
static char pid_str[24] = "<PID>"; // U64 max is 20 chars plus terminator.

#define errF(fmt, ...) { \
  fprintf(stderr, "\x1b[36mlibmuck %s:\x1b[m " fmt, program_name, ## __VA_ARGS__); \
  fflush(stderr); \
}

#define errFL(fmt, ...) errF(fmt "\n", ## __VA_ARGS__)

#define errFRL(chars, fmt, ...) { errF(fmt, __VA_ARGS__); write_chars_repr(2, chars); write_nl(2); }

#define fail(fmt, ...) { errFL("error: " fmt, ## __VA_ARGS__); exit(1); }

#define check(cond, fmt, ...) { if (!(cond)) {fail(fmt, ## __VA_ARGS__);} }


// Checked system operations.

static void* alloc(Size size) {
  assert(size >= 0);
  // malloc does not return null for zero size;
  // we do so that a len/ptr pair with zero len always has a null ptr.
  if (!size) return NULL;
  void* p = malloc(size);
  check(p, "malloc failed.")
  return p;
}

static void write_bytes(int fd, const char* bytes, Size len) {
  ssize_t res = write(fd, bytes, len);
  check((Size)res == len, "write failed: %s.\n", strerror(errno));
}

static void write_chars(int fd, const char* chars) {
  write_bytes(fd, chars, strlen(chars));
}

static void write_nl(int fd) { write_bytes(fd, "\n", 2); }


static void write_chars_repr(int fd, char* chars) {
  if (!chars) {
    write_chars(fd, "NULL");
    return;
  }
  char buffer[4096] = {'"'};
  Size buf_len = 1;
  #define append(character) buffer[buf_len++] = character
  while (*chars) {
    char c = *chars++;
    if (c >= ' ' && c <= '~' && c != '"') { // Printable.
      append(c);
    } else {
      append('\\');
      switch (c) {
      case '\0': append('0'); break;
      case '\t': append('t'); break;
      case '\n': append('n'); break;
      case '"':  append('"'); break;
      default:
        append('x');
        append((c>>8)+'0');
        append((c&0xf)+'0');
      }
    }
    if (buf_len > sizeof(buffer) - 4) { // Each iteration can add up to 4 chars.
      write_bytes(fd, buffer, buf_len);
      buf_len = 0;
    }
  }
  append('"');
  write_bytes(fd, buffer, buf_len);
  #undef append
}


// Str.

typedef struct {
  char* ptr;
  Size len; // length, excluding null terminator.
  Size cap; // capacity, excluding null terminator. Always 2**n - 1.
} Str;


static void str_validate(Str* str) {
  if (str->len) {
    check(str->ptr, "str_validate: positive length but null pointer.");
    check(str->ptr[str->len] == 0, "str_validate: missing null terminator.");
    for (Size i = 0; i < str->len; i++) {
      check(str->ptr[i] > 0, "str_validate: null byte at position %lu; length:%lu.", i, str->len);
    }
  } else {
    check(!str->ptr, "str_validate: zero length but non-null pointer.");
  }
  check(str->cap >= str->len, "str_validate: len:%lu > cap:%lu.", str->len, str->cap);
}


static char* str_end(Str* str) { return str->ptr + str->len; }

static char str_last_char(Str* str) { return str->ptr[str->len - 1]; }

static void str_clear(Str* str) { str->len = 0; }

static void str_terminate(Str* str) { str->ptr[str->len] = '\0'; }

static void str_truncate_by(Str* str, Size n) {
  check(str->len >= n, "str_truncate_by: truncation length %lu is greater than string length %lu", n, str->len);
  str->len -= n;
  str->ptr[str->len] = '\0';
}

static void str_truncate_to_char(Str* str, char c) {
  Size l = str->len;
  while (l > 0 && str->ptr[l-1] != c) l--;
  str->len = l;
  str->ptr[l] = '\0';
}

static void str_grow_to(Str* str, Size cap) {
  while (str->cap < cap) {
    str->cap += str->cap + 1; // Guarantees that cap is 2**n - 1.
  }
  str->ptr = (char*)realloc(str->ptr, str->cap);
  check(str->ptr, "grow_str failed.");
}

static void str_grow_by(Str* str, Size increase) {
  str_grow_to(str, str->len + increase);
}

static void str_append_char(Str* str, char c) {
  str_grow_by(str, 1);
  char* end = str_end(str);
  end[0] = c;
  end[1] = 0;
  str->len++;
}

static void str_append_chars(Str* str, const char* chars) {
  Size chars_len = strlen(chars);
  str_grow_by(str, chars_len);
  char* end = str_end(str);
  memcpy(end, chars, chars_len+1); // +1 includes null terminator.
  str->len += chars_len;
}

static void str_append_str(Str* str, const Str s) {
  str_grow_by(str, s.len);
  char* end = str_end(str);
  memcpy(end, s.ptr, s.len+1); // +1 includes null terminator.
  str->len += s.len;
}

static void write_str(int fd, Str* str) {
  write_bytes(fd, str->ptr, str->len);
}


// Global hash set implementation for strings.
// The table uses prime table sizes and quadratic probing with maximum load factor of 0.5.
// The use of prime sizes and load factor 0.5 guarantees that quadratic probing never fails:
// https://en.wikipedia.org/wiki/Quadratic_probing#Limitations

// We assume that table keys are char strings that we own.
typedef char* Key;

static Size prime_caps[49];
static Size prime_caps_count = sizeof(prime_caps) / sizeof(Size);


static Key* table = NULL; // The global hash set.
static Size table_len = 0;
static Size table_cap = 0;
static Size table_cap_idx = 0; // Index into prime_caps.
static U8 hash_secret[16] = {};
static bool hash_secret_initialized = false;


static void hash_init() {
  assert(!hash_secret_initialized);
  #if MUCK_USE_SECURE_HASH
    arc4random_buf(hash_secret, sizeof(hash_secret));
  #endif
  hash_secret_initialized = true;
}


static Key key_for_chars(char* chars) {
  Size len = strlen(chars) + 1;
  Key key = alloc(len);
  memcpy(key, chars, len);
  return key;
}


static Hash siphash(const U8* in, const Size inlen, const U8* k);

static Hash hash_for_chars(char* chars) {
  assert(hash_secret_initialized);
  return siphash((U8*)chars, strlen(chars), hash_secret);
}


static void set_resize() {
  table_cap_idx += 1;
  check(table_cap_idx < prime_caps_count, "set_resize: insane table_cap_idx.")
  Size new_table_cap = prime_caps[table_cap_idx];
  Key* new_table = alloc(new_table_cap * sizeof(Key));
  memset(new_table, 0x00, new_table_cap * sizeof(Key)); // Set to invalid.
  for (Idx idx = 0; idx < table_cap; idx++) {
    Key key = table[idx];
    if (!key) continue;
    Hash hash = hash_for_chars(key);
    hash %= new_table_cap;
    for (Size jump = 0; jump < new_table_cap; jump++) {
      Idx new_idx = (hash + jump * jump) % new_table_cap; // Quadratic probing.
      if (!new_table[new_idx]) { // Found an open slot.
        new_table[new_idx] = key;
        goto next;
      }
    }
    fail("set_resize failed to find an open slot.");
    next: continue;
  }
  free(table);
  table = new_table;
  table_cap = new_table_cap;
}


static bool set_insert_chars(char* chars) {
  // Returns true if the key is already present in the table.
  if (!table) {
    assert(!table_len);
    assert(!table_cap);
    assert(!table_cap_idx);
    table_cap_idx = 1;
    set_resize();
  }

  if ((false)) { // Dump table.
    write_nl(2);
    for (Idx idx = 0; idx < table_cap; idx++) {
      Key existing = table[idx];
      errFRL(existing, "TABLE idx=%llu ", idx);
    }
  }

  Hash hash = hash_for_chars(chars);
  hash %= table_cap;
  //errFRL(chars, "CHARS idx=%llu ", hash);
  for (Size jump = 0; jump < table_cap; jump++) {
    Idx idx = (hash + jump * jump) % table_cap; // Quadratic probing.
    Key existing = table[idx];
    if (existing) {
      //errFRL(existing, "EXIST idx=%llu ", idx);
      if (strcmp(existing, chars)) continue; // Different keys.
      else {
        return true; // Key is already present.
      }
    }
    // Found an open slot.
    //errFL("AVAIL idx=%llu ", idx);
    if ((false)) { // Debug check that the key is actually novel.
      for (Idx i = 0; i < table_cap; i++) {
        Key ex = table[i];
        if (ex) { check(strcmp(ex, chars), "hash set missed existing key: %s", chars); }
      }
    }
    table[idx] = key_for_chars(chars);
    table_len++;
    // Supposedly we are guaranteed to find an open slot even when we are already exactly half full.
    // This means that we can check the load factor after insertion.
    // Note that this fails for table_cap == 2, because the next cap is 3 and so the load remains too high.
    // This is addressed at initialization by stepping up to table_cap == 3 immediately.
    if (table_len * 2 > table_cap) { // Table has exceeded 0.5 load factor.
      set_resize();
    }
    return false; // New key.
  }
  fail("set_insert_chars failed to find an open slot; hash:%llx", hash);
}


// Muck.

static bool is_setup = 0;
static int fd_fifo = 0;
static int dbg = 0;
static Str msg = {};
static Str canon_path = {};
static char proj_dir[MAXPATHLEN] = {};
static char curr_dir[MAXPATHLEN] = {};


static void update_curr_dir() {
  // Update the current working directory buffer.
  // We cannot use getcwd, because it calls stat, which would put muck_communicate into infinite recursion.
  // Instead, we use a lower-level, platform specific approach.
  int fd = open(".", O_RDONLY); // Note: this does not trigger libmuck's own interposition.
  check(fd >= 0, "update_curr_dir: open failed.");
  // This approach was extracted from the getcwd implementation in macOS Libc-1244.1.7.
#if __APPLE__
	int err = fcntl(fd, F_GETPATH, curr_dir);
#else
  #error "unsupported platform."
#endif
	check(!err, "update_curr_dir; fcntl failed.");
  close(fd);
}


static void muck_init() {
  // Initialize.

  is_setup = true;

  // Get program name.
  #if defined(__APPLE__) || defined(__FreeBSD__)
  program_name = getprogname();
  #elif defined(_GNU_SOURCE)
  program_name = program_invocation_name;
  #else
  #error "unsupported platform."
  #endif

  hash_init();

  // Get this process' identifier.
  const int pid_cap = sizeof(pid_str);
  int n_chars = snprintf(pid_str, pid_cap, "%lld", (int64_t)getpid());
  check(n_chars > 0 && n_chars < pid_cap, "failed to format PID.");

  // Get the project dir.
  char* env_proj_dir = getenv("PROJECT_DIR");
  if (env_proj_dir && *env_proj_dir) {
    Size buf_len = strlen(env_proj_dir) + 1;
    check(buf_len <= MAXPATHLEN, "PROJECT_DIR is greater than maximum path length.")
    memcpy(proj_dir, env_proj_dir, buf_len);
  }

  // Get the FIFO path.
  char* fifo_path = getenv("MUCK_FIFO");
  if (fifo_path && *fifo_path) {
    fd_fifo = open(fifo_path, O_WRONLY);
  } else {
    errFL("NOTE: MUCK_FIFO build process env is not set.");
  }

  // Get the debug flag.
  char* dbg_flag = getenv("MUCK_DEPS_DBG");
  dbg = (dbg_flag && *dbg_flag);

  if (dbg) { errFL("\x1b[36minitialized.\x1b[m"); }
}


static bool has_prefix(const char* str, const char* prefix) {
  while (*prefix) {
    if (!*str || *str != *prefix) return false;
    str++;
    prefix++;
  }
  return true;
}


#define COMMUNICATE(mode_char, file_path) muck_communicate(__func__+5, mode_char, file_path)

static void muck_communicate(const char* call_name, char mode_char, const char* file_path) {
  if (!is_setup) {
    muck_init();
  }

  // Canonicalize the file path.
  str_clear(&canon_path);

  if (file_path[0] == '/') {
    // Begin at root slash and advance to make file_path relative.
    file_path += 1;
  } else { // Not absolute path; prefix with current working directory.
    update_curr_dir();
    str_append_chars(&canon_path, curr_dir);
  }
  str_append_char(&canon_path, '/'); // Leading slash.

  // Copy file_path to canon_path, one character at a time, canonicalizing as we go.
  while (*file_path) { // Have remaining directory component.
    assert(str_last_char(&canon_path) == '/');
    if (*file_path == '/') { // Double slash; skip it.
      file_path += 1;
      continue;
    }
    if (has_prefix(file_path, "./")) { // Dot slash; skip it.
      file_path += 2;
      continue;
    }
    if (has_prefix(file_path, "../")) { // Drop back one level.
      // First, need to clip trailing slash.
      assert(str_last_char(&canon_path) == '/');
      canon_path.len -= 1;
      str_truncate_to_char(&canon_path, '/');
      file_path += 3;
      continue;
    }
    // Normal; copy chars to next path separator.
    while (*file_path) {
      char c = *file_path++;
      str_append_char(&canon_path, c);
      if (c == '/') break;
    }
  }
  str_validate(&canon_path);

  // If we have the project dir, check that the requested path is in it before sending the message.
  if (*proj_dir) {
    if (!has_prefix(canon_path.ptr, proj_dir)) {
      return;
    }
  }

  // Format the message.
  str_clear(&msg);
  str_append_chars(&msg, pid_str);
  str_append_char(&msg, '\t');
  Idx call_pos = msg.len;
  str_append_chars(&msg, call_name);
  str_append_char(&msg, '\t');
  str_append_char(&msg, mode_char);
  str_append_char(&msg, '\t');
  str_append_str(&msg, canon_path);

  // If we have previously sent this exact message, skip it.
  if (set_insert_chars(msg.ptr+call_pos)) {  // Skip the pid prefix, which changes per invocation. Makes debugging stable.
    return;
  }
  if (dbg) { errFL("\x1b[36m%s\x1b[0m", msg.ptr); }
  str_append_char(&msg, '\n');

  if (fd_fifo) { // Communicate with the muck build process.
    write_str(fd_fifo, &msg);
    raise(SIGSTOP); // Stop this process. The parent will cause it to resume with SIGCONT.
  }
  if (dbg) { // show that the client is no longer blocked.
    //str_truncate_by(&msg, 1); // Trim newline for debug printing.
    errFL("\x1b[36mresume.\x1b[m");
  }
}


// fcntl.h.

static int muck_open(const char* filename, int oflag, int mode) {
  char mode_char = '?';
  if (oflag & O_RDWR) { mode_char = 'U'; }
  else if (oflag & O_WRONLY) {
    if (oflag & O_TRUNC) { mode_char = 'W'; } // clean write.
    else if (oflag & O_APPEND) { mode_char = 'A'; } // append write.
    else { mode_char = 'M'; } // mutating write.
  }
  else { mode_char = 'R'; } // read-only.

  COMMUNICATE(mode_char, filename);
  return open(filename, oflag, mode);
}
INTERPOSE(open);


// sys/stat.h.

static int muck_stat(const char* restrict path, struct stat* restrict buf) {
  COMMUNICATE('S', path);
  return stat(path, buf);
}
INTERPOSE(stat);

static int muck_lstat(const char* restrict path, struct stat* restrict buf) {
  COMMUNICATE('S', path);
  return lstat(path, buf);
}
INTERPOSE(lstat);

static int muck_fstatat(int fd, const char* path, struct stat* buf, int flag) {
  fail("fstatat is not yet supported; fd=%d, path=%s, buf=%p, flag=0x%x", fd, path, (void*)buf, flag)
}
INTERPOSE(fstatat);


// libc.

static FILE* muck_fopen(const char* __restrict __filename, const char* __restrict __mode) {
  char mode_char = '?';
  const char* m = __mode;
  while (*m) {
    switch (*m++) {
      case '+': mode_char = 'U'; break;
      case 'r': mode_char = 'R'; continue;
      case 'w': mode_char = 'W'; continue;
      case 'a': mode_char = 'A'; continue;
      default: continue;
    }
  }
  COMMUNICATE(mode_char, __filename);
  return fopen(__filename, __mode);
}
INTERPOSE(fopen);


static DIR* muck_opendir(const char* name) {
  COMMUNICATE('R', name);
  return opendir(name);
}
INTERPOSE(opendir);


// Hash table capacity primes.
// Index with a power of two, to get the largest prime less than that power of two.
static Size prime_caps[] = {
  1, // 0.
  2, // 1.
  3, // 2.
  7, // 3.
  13, // 4.
  31, // 5.
  61, // 6.
  127, // 7.
  251, // 8.
  509, // 9.
  1021, // 10.
  2039, // 11.
  4093, // 12.
  8191, // 13.
  16381, // 14.
  32749, // 15.
  65521, // 16.
  131071, // 17.
  262139, // 18.
  524287, // 19.
  1048573, // 20.
  2097143, // 21.
  4194301, // 22.
  8388593, // 23.
  16777213, // 24.
  33554393, // 25.
  67108859, // 26.
  134217689, // 27.
  268435399, // 28.
  536870909, // 29.
  1073741789, // 30.
  2147483647, // 31.
  4294967291, // 32.
  8589934583, // 33.
  17179869143, // 34.
  34359738337, // 35.
  68719476731, // 36.
  137438953447, // 37.
  274877906899, // 38.
  549755813881, // 39.
  1099511627689, // 40.
  2199023255531, // 41.
  4398046511093, // 42.
  8796093022151, // 43.
  17592186044399, // 44.
  35184372088777, // 45.
  70368744177643, // 46.
  140737488355213, // 47.
  281474976710597, // 48.
};


/*
SipHash reference C implementation, modified by George King to return uint64_t directly.

original: https://raw.githubusercontent.com/veorq/SipHash/93ca99dcfa6a32b1b617e9a5c3c044685254ce8e/siphash.c

Copyright (c) 2012-2016 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

You should have received a copy of along with this software.
See the CC0 Public Domain Dedication: <http://creativecommons.org/publicdomain/zero/1.0/>.
*/


/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

static uint64_t siphash(const uint8_t *in, const size_t inlen, const uint8_t *k) {

    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;
    uint64_t k0 = U8TO64_LE(k);
    uint64_t k1 = U8TO64_LE(k + 8);
    uint64_t m;
    int i;
    const uint8_t *end = in + inlen - (inlen % sizeof(uint64_t));
    const int left = inlen & 7;
    uint64_t b = ((uint64_t)inlen) << 56;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    for (; in != end; in += 8) {
        m = U8TO64_LE(in);
        v3 ^= m;
        for (i = 0; i < cROUNDS; ++i) SIPROUND;
        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)in[6]) << 48;
    case 6:
        b |= ((uint64_t)in[5]) << 40;
    case 5:
        b |= ((uint64_t)in[4]) << 32;
    case 4:
        b |= ((uint64_t)in[3]) << 24;
    case 3:
        b |= ((uint64_t)in[2]) << 16;
    case 2:
        b |= ((uint64_t)in[1]) << 8;
    case 1:
        b |= ((uint64_t)in[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    for (i = 0; i < cROUNDS; ++i) SIPROUND;

    v0 ^= b;
    v2 ^= 0xff;

    for (i = 0; i < dROUNDS; ++i) SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    return b;
}
