# Resource Association
Resource association is a new feature in Cascade to make working with resources
that logically correspond to a domain easier.  Domains often have certain
resource types, traditionally with common suffixes such as `[domain]_tmp_t`,
`[domain]_conf_t` etc.  These types are conventionally refered to as "derived
types" and typically have similar access patterns resulting in large amounts of
highly similar redundant policy.  Automatically handling these scenarios
reduces effort and risk of mistakes in policy writing.

## Example: tmp files
Many processes write files in /tmp. A common pattern in refpolicy style
policies is to create a `[domain]_tmp_t` type, associate it with the `tmp_file`
attribute, set up type transitions so that new files in /tmp will get the new
label and allow the parent domain `manage` access on it.  If any other domains
require access to the derived type, interfaces must be created in the
associated `.if` file.

As an example, one can look at the iptables module in refpolicy [1].  The
domain is first created and associated with the attribute:

```
type iptables_tmp_t;
files_tmp_file(iptables_tmp_t)
```

Later in the file, access is granted on files and directories, and a type
transition is set up:

```
allow iptables_t iptables_tmp_t:dir manage_dir_perms;
allow iptables_t iptables_tmp_t:file manage_file_perms;
files_tmp_filetrans(iptables_t, iptables_tmp_t, { file dir })
```

In this instance, no interfaces have been defined in iptables.if for
`iptables_tmp_t`.  If another domain required access to `iptables_tmp_t`,
those interfaces would need to be manually defined in order to maintain proper
encapsulation.

### Potential problems with the traditional approach
The above described scheme has many numerous possible failures.  Five different
sorts of rules are required for proper functionality and all must be manually
written, with omissions potentially resulting in functional issues that may
only be obvious under rigorous testing.  The possible object classes these
files will be must be enumerated by the policy developer, who may forget less
common use cases such as directories or symlinks, even when they are desired.
Interface names are typically very standard (`domainname_read_tmp_files()`),
but require several lines of boilerplate to define, an exercise typically done
on an ad hoc as needed basis.

## Tmp files in Cascade with resource association
Using resource association, we write all of the repeated access as part of the
`tmp_files` virtual resource (equivalent in this case to a refpolicy attribute),
inherit the full functionality in child types, and then associate them with a
domain to automatically handle all of the mapping between domain and access to
a particular resource.  These associated resources can then automatically be
carried to children, covering a use case of templates in a more readable and
scalable manner.

In tmp.cas:

```
resource tmp_file {
	// all common functions go here
	// In practice, tmp_file may inherit from other domains providing many standard functions
	fn read_files(domain source) {
		allow(source, this, file, read);
	}
	// etc

	@associated_call
	fn associate_tmp_files(domain source) {
		this.manage_files(source);
		this.manage_dirs(source);
		this.manage_symlinks(source);
		resource_transition(source, this, [file dir symlink]);
	}
}
```

In iptables.cas:

```
// Note that in the common case, iptables_tmp needs no special rules
resource iptables_tmp inherits tmp_file {}

// Sets up all of the items discussed above based on the implementation of tmp_file as inherited in iptables_tmp
@associate([iptables_tmp])
domain iptables {}
```

## Inheriting association
When a domain inherits from another domain, new resources that inherit from
associated resources are automatically created.  This enables a pattern of
setting up a group of domains with common access patterns and deriving specific
instances.  Using this pattern in refpolicy requires templates, and an example
can be found in the `qemu_domain_template()` policy [2].  In order to implement
similar functionality in Cascade, a developer would write policy like this:

```
virtual resource qemu_tmp inherits tmp_file {}

@associate([qemu_tmp])
virtual domain qemu {
	// other generic qemu domain policy
}

domain some_qemu_domain inherits qemu {}
```

In this case, a resource inheriting from `qemu_tmp` is automatically created,
named `some_qemu_domain-qemu_tmp`, equivalent to the following definition:

```
resource some_qemu_domain-qemu_tmp inherits qemu_tmp {}
```

The `associate_tmp_files()` call will also automatically be performed as part
of the inheritance from `qemu`.


[1] https://github.com/SELinuxProject/refpolicy/blob/master/policy/modules/system/iptables.te
https://github.com/SELinuxProject/refpolicy/blob/master/policy/modules/system/iptables.if

[2] https://github.com/SELinuxProject/refpolicy/blob/master/policy/modules/apps/qemu.if
