# Introduction
This document describes the project roadmap and goals.  It is intended to be a living document, and open to community input.

## Major milestones
The details of what is included in these milestones is described below.

0.1 (targeted by 2023-03-31) - Clean compilation of a substantial system policy

1.0 (targeted by 2023-09-30) - Capable of building a functional TE policy for booting a Fedora 36 system in enforcing mode with comparable functionality to targeted policy

1.1 (targeted by 2023-09-30) - audit2cascade

1.2 (targeted TBD) - UBAC and RBAC

# Detailed roadmap steps
This lists remaining steps.  Remove steps below as they are completed.

General bugfixing and clean-up tasks are assumed.  This lists major features needed for each milestone.

## 0.1
* Associate resources with resources
* Associate types via nesting in a block
* Syntax to call parent class version of functions

## 1.0
* Documentation Comments
* Port labeling implementation
* Conditionals - Combining both tunables and booleans into a single feature with configurability for runtime vs compiletime resolution
* Documentation updates
* drop keyword 

## 1.1
* Add support for debug symbols carried with the policy
* Implement @hint annotation
* audit2cascade front end
* audit2cascade back end structure - A flexible engine for combining heuristics about policy to make recommendations
* heuristic #1 - TBD
* heuristic #2 - TBD
* heuristic #3 - TBD
* Build individual policy modules and systems
* Enhanced file_context path support - Treat paths as though they are actual paths, rather than just strings/regexes

## 1.2
* RBAC support
* UBAC support

## 1.3
* neverallow rules
* additional higher level abstractions - TBD
* Automatically check documentation examples for correctness

## Future
* MLS/MCS support
* Policy binary size optimizations
* Object class and permission customization
* Generics (possibly?)
