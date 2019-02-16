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

// Diagnostic macros.

static const char* program_name = "?";

#define errF(fmt, ...) { \
  fputs("\x1b[36mlibmuck: ", stderr); \
  fputs(program_name, stderr); \
  fprintf(stderr, ":\x1b[0m " fmt, ## __VA_ARGS__); \
  fflush(stderr); \
}

#define errFL(fmt, ...) errF(fmt "\n", ## __VA_ARGS__)

#define fail(fmt, ...) { errFL("error: " fmt, ## __VA_ARGS__); exit(1); }

#define check(cond, fmt, ...) { if (!(cond)) {fail(fmt, ## __VA_ARGS__);} }


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

static void str_write(Str* str, int fd) {
  check((Size)write(fd, str->ptr, str->len) == str->len, "write failed: %s.\n", strerror(errno));
}


// Muck.

static bool is_setup = 0;
static int fd_fifo = 0;
static int dbg = 0;
static Str msg = {};
static Str canon_path = {};
static char pid[21] = "<UNKNOWN PID>";
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

  // Get this process' identifier.
  const int pid_cap = sizeof(pid);
  int n_chars = snprintf(pid, pid_cap, "%lld", (int64_t)getpid());
  check(n_chars > 0 && n_chars < pid_cap, "failed to print PID.");

  // Get the project dir.
  char* env_proj_dir = getenv("MUCK_PROJ_DIR");
  if (env_proj_dir) {
    Size buf_len = strlen(env_proj_dir) + 1;
    check(buf_len <= MAXPATHLEN, "MUCK_PROJ_DIR is greater than maximum path length.")
    memcpy(proj_dir, env_proj_dir, buf_len);
  }

  // Get the FIFO path.
  char* fifo_path = getenv("MUCK_FIFO");
  if (fifo_path) {
    fd_fifo = open(fifo_path, O_WRONLY);
  } else {
    errFL("NOTE: MUCK_FIFO build process env is not set.");
  }

  // Get the debug flag.
  dbg = (getenv("MUCK_DEPS_DBG") != NULL);
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

  // If we have the project dir, check that the reouested path is in it before sending the message.
  if (*proj_dir) {
    if (!has_prefix(canon_path.ptr, proj_dir)) return;
  }

  // Write the path and mode to message buffer.
  str_clear(&msg);
  str_append_chars(&msg, call_name);
  str_append_char(&msg, '\t');
  str_append_char(&msg, mode_char);
  str_append_char(&msg, '\t');
  str_append_chars(&msg, pid);
  str_append_char(&msg, '\t');
  str_append_str(&msg, canon_path);
  if (dbg) { errFL("\x1b[36m%s\x1b[0m", msg.ptr); }
  str_append_char(&msg, '\n');

  if (fd_fifo) { // Communicate with the muck build process.
    str_write(&msg, fd_fifo);
    raise(SIGSTOP); // Stop this process. The parent will cause it to resume with SIGCONT.
  }
  if (dbg) { // show that the client is no longer blocked.
    str_truncate_by(&msg, 1); // Trim newline for debug printing.
    errFL("\x1b[30m%s -- done.\x1b[0m", msg.ptr)
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
