# Introduction
Cascade is a project to build a new high level language for defining SELinux
policy.

The overall structure of the language is essentially object oriented, with types
carrying knowledge of their use and a hierarchical inheritance tree of type
definition which reflects real world usage in a variety of scenarios.  The
syntax is largely rust inspired, although inspiriation is taken from a variety
of language with a focus on simplicity, consistency and familiarity to
developers from a variety of backgrounds.

# Getting Started
To build the executables run:

```
$ cargo build
```

To run tests, run:

```
$ cargo test
```

Cargo will automatically download all Rust crate dependencies.  The tests depend
on the secilc package.

## casc
The Cascade compiler is named casc, and will be located at target/debug/casc after a
successful build.  Input files are supplied as arguments.  Directory arguments
are searched recursively for policy files.  If no valid policy files are found,
casc will exit with an error.

```
$ casc my_policy.cas
```

casc will create a file named out.cil, containing CIL policy.  This CIL policy
can then be compiled into final SELinux policy using secilc.

More arguments and configuration for casc will be added in future releases

## audit2cascade
The current audit2cascade binary is a simple placeholder.  Eventually this will
be turned into a tool similar to audit2allow or audit2why which generates
Cascade policy based on an output of AVC denial messages in the audit logs.  It
will take advantage of the semantic information present in the hll policy to
aid the developer in making intelligent decisions about handling denials rather
than simply adding raw allow rules.

# Writing Cascade policy
For details on writing Cascade policy, see [Type Enforcement](doc/TE.md).

# Contribute
Thank you for your interest in contributing!  There are several ways you can
contribute to this project.

## Reporting bugs and suggesting enhancements
If you see something wrong or have a suggestion for improvement, feel free to
create an issue in the [Issue tracker](https://github.com/dburgener/cascade/issues)

## Contributing code
We'd welcome your code contributions via GitHub PR.  If you're planning on
adding a major feature, it would probably be good to discuss it in the issue
tracker prior to doing too much work so that we can all come to a consensus on
how it should work.  No advanced discussion is needed for smaller tweaks and
bug fixes.
