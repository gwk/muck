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
// We could behave like a real python module, but there is no real benefit.
// Downside would be that a real module might require extra dynamic linking whenever this library is loaded for every client process.
//PyMODINIT_FUNC PyInit_libmuck(void) { return PyModule_Create(&libmuck); }


// source: https://opensource.apple.com/source/dyld/dyld-519.2.1/include/mach-o/dyld-interposing.h
#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = \
{ (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee }

#define INTERPOSE(name) DYLD_INTERPOSE(muck_##name, name)


#define errF(fmt, ...) { \
  fputs("libmuck: ", stderr); \
  fputs(program_name, stderr); \
  fprintf(stderr, ": " fmt, ## __VA_ARGS__); \
  fflush(stderr); \
}

#define fail(fmt, ...) { errF("error: " fmt, ## __VA_ARGS__); exit(1); }

static int is_setup = 0;
static int fd_send = 0;
static int fd_recv = 0;
static int dbg = 0;
static char* buffer = NULL;
static const char* program_name = "?";
static size_t buffer_size = 0;


#define COMMUNICATE(mode_char, file_path) muck_communicate(__func__+5, mode_char, file_path)

static void muck_communicate(const char* call_name, char mode_char, const char* file_path) {
  if (!is_setup) {
    is_setup = 1;
    #if defined(__APPLE__) || defined(__FreeBSD__)
    program_name = getprogname();
    #elif defined(_GNU_SOURCE)
    program_name = program_invocation_name;
    #endif
    char* fd_send_str = getenv("MUCK_DEPS_SEND");
    char* fd_recv_str = getenv("MUCK_DEPS_RECV");
    if (fd_send_str && fd_recv_str) {
      fd_send = atoi(fd_send_str);
      fd_recv = atoi(fd_recv_str);
    } else {
      errF("NOTE: build process env is not set; MUCK_DEPS_SEND: %s; MUCK_DEPS_RECV: %s.\n", fd_send_str, fd_recv_str);
    }
    dbg = (getenv("MUCK_DEPS_DBG") != NULL);
  }

  // Write the path and mode to the buffer.
  size_t call_len = strlen(call_name);
  size_t path_len = strlen(file_path);
  size_t req_size = call_len + 1 + 1 + 1 + path_len + 2; // call, tab, mode, tab, path, newline, null.
  if (buffer_size < req_size) {
    buffer_size = malloc_good_size(req_size);
    buffer = (char*)realloc(buffer, buffer_size);
    assert(buffer);
  }
  int act_len = snprintf(buffer, buffer_size, "%s\t%c\t%s\n", call_name, mode_char, file_path);
  assert(act_len > 0 && (size_t)act_len < buffer_size);

  if (dbg) { errF("%s", buffer); }

  if (fd_send) { // communicate with the muck build process.
    if (write(fd_send, buffer, (size_t)act_len) != (ssize_t)act_len) {
      fail("MUCK_DEPS_SEND write failed: %s; path: %s\n", strerror(errno), file_path);
    }
    // Read the confirmation byte from the receive channel;
    // the read blocks this process until the parent build process is done updating dependencies.
    unsigned char ack = 0;
    if (read(fd_recv, &ack, 1) != 1) {
      fail("MUCK_DEPS_RECV read failed: %s.\n", strerror(errno));
    }
    if (ack != 0x6) { // Ascii ACK.
      fail("MUCK_DEP_RECV expected ACK (0x6) byte confirmation; received: %02x\n", (int)ack)
    }
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

static int muck_stat(const char *restrict path, struct stat *restrict buf) {
  COMMUNICATE('S', path);
  return stat(path, buf);
}
INTERPOSE(stat);

static int muck_lstat(const char *restrict path, struct stat *restrict buf) {
  COMMUNICATE('S', path);
  return lstat(path, buf);
}
INTERPOSE(lstat);

static int muck_fstatat(int fd, const char *path, struct stat *buf, int flag) {
  fail("fstatat is not yet supported.")
}
INTERPOSE(fstatat);


static FILE *muck_fopen(const char* __restrict __filename, const char* __restrict __mode) {
  // libc.
  char mode_char = '?';
  const char* m = __mode;
  while (*m) {
    switch (*m) {
      case 'r': mode_char = 'R'; break;
      case 'w': mode_char = 'W'; break;
      case 'a': mode_char = 'A'; break;
      case '+': mode_char = 'U'; break;
      default: continue;
    }
    m++;
  }
  muck_communicate("fopen", mode_char, __filename);
  return fopen(__filename, __mode);
}
INTERPOSE(fopen);


static DIR* muck_opendir(const char *name) {
  // libc.
  muck_communicate("opendir", 'R', name);
  return opendir(name);
}
INTERPOSE(opendir);
