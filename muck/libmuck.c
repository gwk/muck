// Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc/malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// This dynamic library provides a replacement of the system's `open` function,
// and is meant to be loaded by Muck client processes using or DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux).
// The replacement wraps the original, but first notifies the Muck parent process of the file being opened,
// thus providing the build system with an opportunity to update dependencies.

// Currently, libmuck is installed as a Python C extension dynamic library.
// This is admittedly a hack, because it is not a legitimate Python extension.
// If you try to import it you will get: `ImportError: dynamic module does not define module export function (PyInit_libmuck)`.
// We could behave like a real python module, but there is no real benefit.
// Downside would be that it might cause extra dynamic linking whenever this library is loaded for every client process.
//PyMODINIT_FUNC PyInit_libmuck(void) { return PyModule_Create(&libmuck); }



// source: https://opensource.apple.com/source/dyld/dyld-519.2.1/include/mach-o/dyld-interposing.h
#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = \
{ (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee }


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


static void muck_communicate(const char* filename, char mode) {
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
  size_t path_len = strlen(filename);
  size_t req_size = path_len + 4; // path, tab, mode, newline, null.
  if (buffer_size < req_size) {
    buffer_size = malloc_good_size(req_size);
    buffer = (char*)realloc(buffer, buffer_size);
    assert(buffer);
  }
  int act_len = snprintf(buffer, buffer_size, "%s\t%c\n", filename, mode);
  assert(act_len > 0 && (size_t)act_len < buffer_size);

  if (dbg) { errF("%s", buffer); }

  if (fd_send) { // communicate with the muck build process.
    if (write(fd_send, buffer, (size_t)act_len) != (ssize_t)act_len) {
      fail("MUCK_DEPS_SEND write failed: %s; path: %s\n", strerror(errno), filename);
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

static int muck_open(const char* filename, int oflag, int mode) {
  char mode_char = '?';
  if (oflag & O_RDWR) { mode_char = 'U'; }
  else if (oflag & O_WRONLY) {
    if (oflag & O_TRUNC) { mode_char = 'W'; } // clean write.
    else { mode_char = 'M'; } // mutating write.
  }
  else { mode_char = 'R'; } // read-only.

  muck_communicate(filename, mode_char);
  return open(filename, oflag, mode);
}

DYLD_INTERPOSE(muck_open, open);