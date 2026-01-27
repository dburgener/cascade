# Introduction
This document describes the project roadmap and goals.  It is intended to be a living document, and open to community input.

## Project status
This project is not currently being actively developed.  I am available to review and merge PRs, provide support and guidance, and do small maintenance tasks, but I am not actively developing the project.

The minimum feature set to make this generally usable is enumerated below under the 0.1 milestone and community contributions to get to that milestone are welcome.

## Major milestones
The details of what is included in these milestones is described below.

0.1 - Clean compilation of a substantial system policy

1.0 - Capable of building a functional TE policy for booting a Fedora 36 system in enforcing mode with comparable functionality to targeted policy

1.1 - audit2cascade

1.2 - UBAC and RBAC

# Detailed roadmap steps
This lists remaining steps.  Remove steps below as they are completed.

General bugfixing and clean-up tasks are assumed.  This lists major features needed for each milestone.  If there is community interest in a particular feature, it is certainly acceptable to add it earlier.

The 0.1 milestone is substantially more fleshed out to enable community contributions.

## 0.1
* Compile refpolicy3
	* Refpolicy3 is available here: https://github.com/pebenito/refpolicy3
* Error refactor
* Support target libsepol version
* The - thing


## 1.0
* Documentation Comments
* Port labeling implementation
* Conditionals - Combining both tunables and booleans into a single feature with configurability for runtime vs compiletime resolution
* Documentation updates

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
