# Cascade backwards compatibility
Cascade follows semantic versioning (https://semver.org/).  This means that all
changes in a major version are considered backwards compatible.  An increment
of the major version signifies a breaking change, an increment of the the minor
version signifies a backwards compatible addition of functionality, and an
increment of the patch number indicates bug fixes.

Changes to the following will be considered breaking backwards compatibiliy
for Cascade:

1. Any change to the signatures of existing public API elements in the library
portion of Cascade.
2. Any user visible change to the usage of command line arguments on casc.
3. Any Cascade policy that previously compiled correctly, produced valid CIL
that compiled correctly, and was in line with the behavior specified in the
Cascade documentation, unless a warning was displayed on that policy for the
entirety of the major version.

Changes to the following will *NOT* be considered backwards compatibility
breaking changes for Cascade:

1. The addition of new public API elements (increment minor version)
2. The addition of new flags and options to casc (increment minor version)
3. The addition of new binaries (eg audit2cascade)
4. Modification to anything that was explicitly declared to be unstable in the
documentation (for example, if Cascade begins publishing a new binary, it may
have a period of unstability).  Such exceptions will be clearly documented.
5. As we add new functionality, policy that did not previously compile may
start to compile.
6. If a policy compiled to invalid CIL, that is considered a Cascade bug.  No
guarantees are made about preserving any backwards compatibilty around such
policy.
7. If a policy display a warning message which indicates that it may change,
changing that policy syntax will not be considered a breaking change.  However,
if a major version was published without such a warning at some point, then the
change becomes a breaking change.
8. The addition of new compiler *warnings* to previously compiling policy is
not considered a breaking change.
9. Fixing compilation to valid but incorrect behavior will not be considered a
breaking change.  For example, policy that compiled but omitted certain policy
rules may begin to output those rules in a future minor version.  However, if
those new rules produce invalid CIL, that is a Cascade bug.
