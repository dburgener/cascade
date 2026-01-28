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
	* Changes may be needed to either Cascade or refpolicy3 to make this work
	* The current status is that Cascade generates a CIL file for refpolicy3, but that CIL file is invalid and does not compile.
		* Cascade needs to be updated in order to only produce valid CIL and error if the the policy is invalid.
* Error handling refactor
	* Errors point at a code point in the input policy using a filename and a position in that file.
	* Unfortunately, currently the position and the file are tracked through the code separately, which can result in them getting out of sync with unfortunate consequences.
	* I have a WIP branch to get this working at dburgener/wip-error-refactor
* Support target libsepol version
	* Some features desired by Cascade are only supported on certain libsepol versions
	* Currently Cascade generates one output CIL policy for a given input, which is expected to compile on libsepol 3.0 or greater.
	* Ideally we could take in a target libsepol version and compile policy for that, which would allow taking advantage of newer CIL language constructs when available
		* genfscon syntax can be more specific at some point - we don't use that now to be back compatible.  We could use it when available, and report an error if input policy tries to overspecify a genfscon
		* deny rules were added at some point.  Once we implement delete, we'll want to do so using deny rules, if they exist.
* Output associated resource names correctly
	* Currently, an associated resource in the policy is named as `my_domain.my_resource`, but outputs to the CIL as `my_domain-my_resource`
	* This may be confusing for users
	* The historical reason for this is expediency - you can't use a `.` character in CIL type names because it's used for CILs own namespacing functionality
		* But the workaround is straightforward - just use that namespacing functionality.  The below produces the desired result:
			```
			(type my_domain)
			(block my_domain
				(type my_resource))
			```
* Validate file permissions
	* Currently, Cascade assumes that rules have permissions valid for those object classes.  We should validate that.
	* This is a little tricky, since permissions can be function arguments, so the object class validity needs to be tracked through function validation based on how they're called.
	* Another complication is that some permissions can be used for multiple object classes
* Update for compliance with latest rust
	* This project was last tested on rust 1.83
	* Latest stable rust produces a few warnings
	* There are new clippy warnings to be cleaned up
	* Presumably our dependencies may have new semver breaking versions that need updating

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
