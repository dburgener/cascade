# Introduction
This document describes the project roadmap and goals.  It is intended to be a living document, and open to community input.

## Major milestones
The details of what is included in these milestones is described below.

0.1 (targeted by 2022-05-31) - Clean compilation of a substantial system policy

1.0 (targeted by 2022-09-30) - Capable of building a functional TE policy for booting a Fedora 36 system in enforcing mode with comparable functionality to targeted policy

1.1 (targeted by 2022-12-23) - audit2cascade

1.2 (targeted by 2023-02-28) - UBAC and RBAC

1.3 (targeted by 2023-06-30) - Ready for large scale production workloads

# Detailed roadmap steps
This lists remaining steps.  Remove steps below as they are completed.

General bugfixing and clean-up tasks are assumed.  This lists major features needed for each milestone.

## 0.1
API Blocks - A feature similar to rust traits to create a set of functions that a child must implement
Derive annotation - Automatic derivation of inherited member functions
Associate resources with resources
Associate types via nesting in a block
Parse networking rules
Parse filesystem and ephemeral object rules
Extend keyword - Allows to extend a type block initially declared elsewhere
Syntax to call parent class version of functions

## 1.0
Documentation Comments
Port labeling implementation
Conditionals - Combining both tunables and booleans into a single feature with configurability for runtime vs compiletime resolution
Ephemeral object and filesystem labeling implementation
System compilation - Assemble a collection of modules into a full system policy
Build individual policy modules and systems
Ergonomic compiler front end for selecting build targets
Enhanced file_context path support - Treat paths as though they are actual paths, rather than just strings/regexes
Compiler warnings support
Documentation updates

## 1.1
Add support for debug symbols carried with the policy
Implement @hint annotation
audit2cascade front end
audit2cascade back end structure - A flexible engine for combining heuristics about policy to make recommendations
heuristic #1 - TBD
heuristic #2 - TBD
heuristic #3 - TBD

## 1.2
RBAC support
UBAC support
Local symbol binding

## 1.3
delete() function - Or similar
neverallow rules
additional higher level abstractions - TBD
Automatically check documentation examples for correctness

## Future
MLS/MCS support
Policy binary size optimizations
Object class and permission customization
Generics (possibly?)
