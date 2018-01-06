<section class="S1" id="s0">
  <h1 id="h0">Muck</h1>
  <p>
    Muck is a build tool for data analysis projects. Given a target (a file to be built), it looks in the current directory tree for a source file with a matching name, determines its static dependencies, recursively builds those, and then builds the target, possibly building additional dynamic dependencies as necessary. For example, if we ask Muck to build <code class="inline">some.txt</code>, it will run any source file with <code class="inline">some.txt</code> as a prefix, e.g. <code class="inline">some.txt.py</code>, <code class="inline">some.txt.sh</code>, or <code class="inline">some.txt.md</code> (there must be a single source candidate). If <code class="inline">some.txt.py</code> opens <code class="inline">data.txt</code>, Muck will suspend the execution of the process and update <code class="inline">data.txt</code>.
  </p>
  <p>
    Unlike Make and other traditional build systems, Muck does not use a "makefile". Instead, Muck determines the dependencies of a given file using static analysis and runtime interposition of the Unix <code class="inline">open</code> system call. With Muck, programmers can organize projects into discrete steps with arbitrary file dependencies between them. When the source code for a particular step changes, Muck will rebuild that step and all dependent ("downstream") steps, but will not redo any work that is not affected by the change. This incremental rebuild behavior speeds up the development process and helps prevent errors due to stale product files.
  </p>
  <p>
    Muck is most useful for projects where the various products can be given descriptive, discrete names. It is less useful for problems that can be framed as processing a continuous stream of inputs; these are better served by an application server.
  </p>
  <section class="S2" id="s0.1">
    <h2 id="h0.1">Getting Started</h2>
    <p>
      Muck is a work in progress. I encourage people to try it out, with the caveat that it is not yet entirely stable. If you run into issues, I am more than happy to help you work through them. The project is hosted at <a href="https://github.com/gwk/muck">https://github.com/gwk/muck</a>, with documentation at <a href="https://gwk.github.io/muck">https://gwk.github.io/muck</a>. To get started, read the "Installation" section.
    </p>
  </section>
  <section class="S2" id="s0.2">
    <h2 id="h0.2">License</h2>
    <p>
      All of the source code and documentation is dedicated to the public domain under CC0: <a href="https://creativecommons.org/.publicdomain/zero/1.0/">https://creativecommons.org/.publicdomain/zero/1.0/</a>.
    </p>
  </section>
  <section class="S2" id="s0.3">
    <h2 id="h0.3">Status</h2>
    <p>
      Muck is still in development. Currently it only runs on Mac OS, but Linux support is coming soon. It has been used for a variety of experimental projects, but more work is needed to make it production-ready. In particular, Linux support has recently fallen behind, and the test suite and documentation need improvement.
    </p>
  </section>
  <section class="S2" id="s0.4">
    <h2 id="h0.4">Issues</h2>
    <p>
      Please file any bugs, questions, or comments at <a href="https://github.com/gwk/muck/issues">https://github.com/gwk/muck/issues</a>.
    </p>
  </section>
</section>
