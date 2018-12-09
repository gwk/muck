// Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc/malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>

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


// source: https://opensource.apple.com/source/dyld/dyld-519.2.1/include/mach-o/dyld-interposing.h
#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = \
{ (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee }

#define INTERPOSE(name) DYLD_INTERPOSE(muck_##name, name)


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


typedef struct {
  char* ptr;
  size_t len; // length, excluding null terminator.
  size_t cap; // capacity, excluding null terminator. Always 2**n - 1.
} Str;

static char* str_end(Str* str) { return str->ptr + str->len; }

static void str_clear(Str* str) { str->len = 0; }

static void str_truncate_by(Str* str, size_t n) {
  str->len -= n;
  str->ptr[str->len] = '\0';
}

static void str_grow_to(Str* str, size_t cap) {
  while (str->cap < cap) {
    str->cap += str->cap + 1; // Guarantees that cap is 2**n - 1.
  }
  str->ptr = (char*)realloc(str->ptr, str->cap);
  check(str->ptr, "grow_str failed.");
}

static void str_grow_by(Str* str, size_t increase) {
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
  size_t chars_len = strlen(chars);
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
  check((size_t)write(fd, str->ptr, str->len) == str->len, "write failed: %s.\n", strerror(errno));
}


static bool is_setup = 0;
static int fd_send = 0;
static int fd_recv = 0;
static int dbg = 0;
static Str msg = {};


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


#define COMMUNICATE(mode_char, file_path) muck_communicate(__func__+5, mode_char, file_path)

static void muck_communicate(const char* call_name, char mode_char, const char* file_path) {
  if (!is_setup) {
    is_setup = true;
    #if defined(__APPLE__) || defined(__FreeBSD__)
    program_name = getprogname();
    #elif defined(_GNU_SOURCE)
    program_name = program_invocation_name;
    #else
    #error "unsupported platform."
    #endif
    char* fd_send_str = getenv("MUCK_DEPS_SEND");
    char* fd_recv_str = getenv("MUCK_DEPS_RECV");
    if (fd_send_str && fd_recv_str) {
      fd_send = atoi(fd_send_str);
      fd_recv = atoi(fd_recv_str);
    } else {
      errFL("NOTE: build process env is not set; MUCK_DEPS_SEND: %s; MUCK_DEPS_RECV: %s.", fd_send_str, fd_recv_str);
    }
    dbg = (getenv("MUCK_DEPS_DBG") != NULL);
  }

  // Write the path and mode to message buffer.
  str_clear(&msg);
  str_append_chars(&msg, call_name);
  str_append_char(&msg, '\t');
  str_append_char(&msg, mode_char);
  str_append_char(&msg, '\t');
  if (file_path[0] != '/') { // not absolute path; must prefix with current working directory.
    update_curr_dir();
    str_append_chars(&msg, curr_dir);
    str_append_char(&msg, '/');
  }
  str_append_chars(&msg, file_path);
  if (dbg) { errFL("\x1b[36m%s\x1b[0m", msg.ptr); }
  str_append_char(&msg, '\n');

  if (fd_send) { // communicate with the muck build process.
    str_write(&msg, fd_send);
    // Read the confirmation byte from the receive channel;
    // the read blocks this process until the parent build process is done updating dependencies.
    unsigned char ack = 0;
    check(read(fd_recv, &ack, 1) == 1, "MUCK_DEPS_RECV read failed: %s.", strerror(errno));
    check(ack == 0x6, "MUCK_DEP_RECV expected ACK (0x6) byte confirmation; received: 0x%02x.", (int)ack);
  }
  if (dbg) { // show that the client is no longer blocked.
    str_truncate_by(&msg, 1);
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
