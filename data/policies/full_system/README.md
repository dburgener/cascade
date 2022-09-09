This directory contains a sample full system cascade policy intended for
demonstrating and testing Cascade.

The target system for this policy is an unmodified Fedora Workstation 36.

The intent is to create a policy that boots in enforcing mode and allows simple
tests and demonstrations to be run on that system.  This is not intended as a
basis for a production policy and should not be used on any system you care
about.

To build the policy in this directory, run:

```
casc --package -m cascade data/policies/full_system/*.cas
```

That will create a tarball of a policy named cascade that can be staged at
/etc/selinux.

To switch the system to use the Cascade policy, you can modify
/etc/selinux/config to reference the "cascade" policy name.

The files in the contexts folders are SELinux configuration files that need to
be staged at the following locations on the target system:

/etc/selinux/cascade/contexts/default_contexts
/etc/selinux/cascade/contexts/virtual_domain_context
/etc/selinux/cascade/contexts/virtual_image_context
/etc/selinux/cascade/contexts/x_contexts

Eventually, Cascade plans to add the functionality to generate these files, but
in the meantime, they need to be manually staged.  Cascade does currently stage
dbus_contexts and seusers automatically when the --package flag is used.

If any other context files are needed for your use case, you will need to add
them manually.

In order to use the Cascade system, you can relabel by rebooting into
permissive mode with your Cascade policy, running:

```
restorecon -RF /
```

And then rebooting again in enforcing mode.
