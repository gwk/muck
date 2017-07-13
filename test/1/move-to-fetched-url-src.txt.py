from muck import *

# fetch something that is guaranteed not to exist on the net;
# if the preceding local move-to-fetched-url command worked,
# then it should be retrieved from the '_fetch' cache directory.
load_url('http://gwk.github.io/muck/does-not-exist.txt')
