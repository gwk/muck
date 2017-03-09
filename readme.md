<section class="S1" id="s0">
  <h1 id="h0">Muck</h1>
  <p>
    Muck is a build tool for data projects. Given a target (a file to be built), it looks in the current directory tree for a source file with a matching name, determines its dependencies, recursively builds those, and then builds the target. Unlike Make and other traditional build systems, Muck does not use a "makefile". Instead, Muck determines the dependencies of a given file by analyzing its contents.
  </p>
  <p>
    With Muck, programmers can organize projects into discrete steps with arbitrary dependencies between them. When the source code for a particular step changes, Muck will rebuild that step and all dependent ("downstream") steps, but will not redo any work that is not affected by the change. This incremental rebuild behavior can speed up the development process dramatically, and helps prevent errors due to stale product files getting used by accident.
  </p>
  <p>
    The project is hosted at <a href=https://github.com/gwk/muck>https://github.com/gwk/muck</a>, with documentation at <a href=https://gwk.github.io/muck>https://gwk.github.io/muck</a>.
  </p>
  <p>
    The development of this project is sponsored by the <a href=https://towcenter.org>Tow Center for Digital Journalism</a>.
  </p>
  <p>
    Muck is limited to source languages that it understands, and to source code written using Muck conventions. In particular, Muck provides a few functions that scripts must use to make data dependencies explicit to the analyzer.
  </p>
  <p>
    By choosing sensible names for each step, the programmer can make the purpose of each step clear. Muck can print the entire dependency graph of the project, resulting in a precise, high-level description of how the code is organized.
  </p>
  <p>
    Muck is a good choice for projects where the products can be given descriptive, discrete names.
  </p>
  <section class="S2" id="s0.1">
    <h2 id="h0.1">License</h2>
    <p>
      All of the source code and documentation is dedicated to the public domain under CC0: <a href=https://creativecommons.org/.publicdomain/zero/1.0/>https://creativecommons.org/.publicdomain/zero/1.0/</a>.
    </p>
  </section>
</section>
