# Introduction 
HLL is a project to build a new high level language for defining SELinux policy.

The overall structure of the language is essentially object oriented, with types
carrying knowledge of their use and a hierarchical inheritance tree of type
definition which reflects real world usage in a variety of scenarios.  The
syntax is largely rust inspired, although inspiriation is taken from a variety
of language with a focus on simplicity, consistency and familiarity to developers
from a variety of backgrounds.

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
The HLL compiler is named hllc, and will be located at target/debug/hllc after a
successful build.  It takes one argument, the name of a policy file to be built:

```
$ hllc my_policy.hll
```

Hllc will create a file named out.cil, containing CIL policy.  This CIL policy
can then be compiled into final SELinux policy using secilc.

More arguments and configuration for hllc will be added in future releases

## audit2hll
The current audit2hll binary is a simple placeholder.  Eventually this will be
turned into a tool similar to audit2allow or audit2why which generates HLL
policy based on an output of AVC denial messages in the audit logs.  It will
take advantage of the semantic information present in the hll policy to aid the
developer in making intelligent decisions about handling denials rather than
simply adding raw allow rules.

# Writing hll policy
For details on writing HLL policy, see doc/TE.md

# Contribute
TODO
