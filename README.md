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

## hllc
The Cascade compiler is named casc, and will be located at target/debug/casc after a
successful build.  It takes one argument, the name of a policy file to be built:

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
TODO
