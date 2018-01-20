# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

from typing import Callable
from http.server import SimpleHTTPRequestHandler, HTTPServer
from .pithy.task import run
from .pithy.fs import *
from .pithy.io import *
from .ctx import Ctx


def serve_build(ctx: Ctx, main_target: str, update_target: Callable[[str], None]) -> None:
  address = ('localhost', 8000)
  host, port = address
  addr_str = f'http://{host}:{port}/{main_target}'
  should_rebuild = False # starts from built state.

  ignored_paths = {
    'apple-touch-icon-precomposed.png',
  }

  class Handler(SimpleHTTPRequestHandler):

    def translate_path(self, path):
      '''
      Translate a URL path to the appropriate file system path.
      This gets called by super's send_head (and also run_cgi, which we can ignore).
      super's implementation returns an absolute path based on cwd; we want one relative to build_dir.
      Note: we could reimplement necessary URL parsing logic here and not call super().translate_path, but this is easier.
      '''
      target = rel_path(super().translate_path(path)) # type: ignore # this is technically a private method.
      return ctx.product_path_for_target(target)


    def send_head(self):
      '''
      SimpleHTTPRequestHandler.send_head does the work for both HEAD and GET requests.
      We override it to detect dependencies and build them before sending the header.
      Note that the header contains file size and mtime, so we must finish building the product first.
      TODO: decide if we need to send the header immediately for long-running build steps.
      '''
      nonlocal should_rebuild

      if self.path not in ignored_paths:
        target = self.target_for_url_path()
        if target == main_target:
          if should_rebuild: ctx.reset()
          should_rebuild = True
        ctx.dbg(f'local request: {self.path}; target: {target}')
        update_target(target)

      return super().send_head() # type: ignore # this is technically a private method.


    def send_response(self, code, message=None):
      super().send_response(code=code, message=message)
      self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')


    def do_GET(self):
      '''Serve a GET request.'''
      if self.path == '/favicon.ico':
        self.send_header('Content-type', 'image/x-icon')
        self.send_header('Content-Length', 0)
        self.end_headers()
        return

      f = self.send_head()
      if not f: return
      try: self.copyfile(f, self.wfile)
      finally: f.close()


    def target_for_url_path(self):
      '''
      Special case maps directories to index.html; based on the beginning of super's implementation of `send_head`.
      Note: this assumes that any directory is a source directory and not a generated product.
      Not sure how this will generalize, but seems like an obscure case.
      Note: muck does not support 'index.htm', only 'index.html', nor does it support the fallback directory listing.
      '''
      target = rel_path(super().translate_path(self.path)) # type: ignore # this is technically a private method.
      return path_join(target, 'index.html') if is_dir(target) else target


  server = HTTPServer(address, Handler)

  # note: the way we tell the OS to open the URL in the browser is a rather suspicious hack:
  # the `open` command returns and then we launch the web server,
  # relying on the fact that the OS takes some time to actually dispatch the request to the browser app.
  # In other words, we are relying on the slowness of the OS so that we can launch the web server in time.
  run(['open', addr_str])
  try: server.serve_forever()
  except KeyboardInterrupt:
    errL('\nKeyboard interrupt received; shutting down.')
    exit()