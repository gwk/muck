
# Muck

Muck is a build tool for data projects. Given a target (a file to be built), it looks in the current directory tree for a source file with a matching name, determines its dependencies, recursively builds those, and then builds the target. Unlike Make and other traditional build systems, Muck does not use a "makefile". Instead, Muck determines the dependencies of a given file by analyzing its contents.

With Muck, programmers can organize projects into discrete steps with arbitrary dependencies between them. When the source code for a particular step changes, Muck will rebuild that step and all dependent ("downstream") steps, but will not redo any work that is not affected by the change. This incremental rebuild behavior can speed up the development process dramatically, and helps prevent errors due to stale product files getting used by accident.

The project is hosted at https://github.com/gwk/muck.

For more details, please visit the documentation: https://gwk.github.io/muck.


## License
All of the source code and documentation is dedicated to the public domain under CC0: https://creativecommons.org/.publicdomain/zero/1.0/.

The development of this project is sponsored by the [https://towcenter.org](Tow Center for Digital Journalism).
