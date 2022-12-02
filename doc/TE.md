# Type Enforcement
Type Enforcement (TE) is one of the security models provided by SELinux.  In
type enforcement, objects on the system (processes, files, sockets, etc) are
each assigned a unique identifier known as a type.  Policy rules specify how
types may interact.

Type Enforcement policies have a subject, which attempts to perform some
action, an object which is acted upon, and a description of the action(s).  In
SELinux this description is made up of an 'object class', which describes what
sort of resource the object is, and permissions (such as read or write) which
describe the access.  Permissions are defined in relation to object classes (so
'listen' is a valid permission on sockets, but not on files).

For more information, review the official SELinux documentation at
https://selinuxproject.org/page/Main_Page

## Types
In SELinux, a type is a unique identifier that specifies security equivalence
from the perspective of TE policy.  Cascade is also a strongly typed language.
The types that are used as identifiers for TE policy are also in the set of
types from the language perspective, however there are also additional types,
described below.  All other types in a policy must derive from one of the below
types.

A 'domain' is a type describing a process on a Linux system and therefore may
be a subject in a TE rule.[1]  Domains may also be the object in a TE rule. Two
common examples of this are:

1. Files in /proc typically have labels matching the process they describe.
2. Many IPC mechanisms request access directly on the target process.

A 'resource' is a type that is not a domain.  Resources may not be the subject
in a TE rule in Cascade.

Domains and resources are declared using the domain and resource keywords
respectively:

```
domain iptables {}

resource iptables_conf {}
```

The block enclosed in curly braces may be used to specify access rules and
member functions on this type.

The rationale for this distinction between domains and resources is that it
allows us to take advantage of this semantic knowledge at compile time for
use in built in functions, syntax improvements and linting.

Cascade is statically typed and function calls must specify the types of their
arguments.  For arguments that may be either domains or resources, the "type"
keyword may be used, however new types must always be either a domain or a
resource.

Additional built in types are listed below.

Lists of objects of the same type are supported and specified by the syntax
[type].

[1] In the SELinux base policy language, non-domains may actually be subjects
in certain contexts (e.g. the filesystem associate permission).  In Cascade we
enforce the rule that only domains may be subjects and handle situations where
resources are subjects through another mechanism (to be determined).

### Extending types
A type that has been declared elsewhere can be extended using the keyword
`extend`.  The contents of an extend block are identical to a normal block, but
instead of creating a new type, it adds rules and declarations to a previously
declared type.

This can be used for source code organization, for example adding local
modifications to an open source policy while maintaining source compatibility
with the open source policy to simplify pulling in the latest changes from
upstream.

```
// foo has been declared elsewhere
extend foo {
	// Some rules
}
```

### Functions

Policy authors can define functions using the keyword 'fn'.  Functions defined
inside the curly block for a type will be member functions of that type, and
will be able to refer to the containing type using the keyword 'this'.  To call
a member function, you use the `.` operator, with the name of the type,
followed by a `.`, followed by the function name.  For example if the read()
function is defined on the `iptables_conf` resource, then it can be called
using `iptables_conf.read()`.

If a function is called inside a curly block, Cascade will attempt to pass the
type of the curly block as the first argument to the function.  If this is not
valid according to type checking, it is a compiler error.

For example:

```
resource iptables_conf {
	fn read(domain source) {
		// Define the function here
	}
}

domain iptables {
	iptables_conf.read(); // passes 'this' (aka iptables) as the first argument
}
```

A function marked with the `virtual` keyword is not allowed to be called
directly. The purpose of such functions is to be inherited and called on the
child type. If a parent function is marked virtual the child *must* define it,
either explicitely or via a derive (if some parent implementation exists).
This is used to define an expected interface that children are guaranteed to
implement.

### Type inheritance
Child types inherit the following from their parents:
1. Any rules refering to the parent
2. Any non-virtual member functions from the parent
3. New copies of associated resources (see 'Resource Association') below

When inheriting from multiple types, different types may provide member
functions with conflicting names (in object oriented language parlance, this is
commonly refered to as "the diamond problem").  If that is the case, the
derived type *must* override that member function with one of its own.  This
can be done by manually defining a new funtion (which may call parent classes
using the syntax classname::function_name()), or using the "derive" annotation.
See the section on annotations for details on deriving.

The common case for type inheritance will be inheriting from virtual types,
which conveniently allows reference to all derived types, automatically
generates common resources, and reduces boilerplate by including common
functions.

Inheriting from concrete types can be desirable for various applications, and
is made more useful than previous cloning implementations by the resource
association mechanism, but is not currently supported in the current version.

### Virtual types
A virtual type does not result in a concrete type existing on the system.
Virtual types are highly similar to attributes in traditional policy (and are
compiled into attributes), but with benefits of member functions and
inheritance, member functions on a virtual type automatically create member
functions on the child, greatly reducing boilerplate.

Virtual types are created using the virtual keyword:

```
virtual domain foo {}
```

Unlike concrete types, virtual types inherit virtual functions from their
parents.

### List of built in types
The following types are built in to the language:

* domain
* resource
* class
* perm
* api
* string
* port
* func
* role
* user
* mls
* bool
* [T] (a list of any other types)

TODO: Which of these can be in a standard library instead of the compiler?

### Associating resources with a domain

Resources may be "associated" with a domain using the `@associate` annotation,
which takes a single list of resources to associate:

```
@associate([bar baz])
domain foo {}
```

Associating a resource with a domain does three things:

1. It causes that resource to be grouped together with the domain when the  
domain is included in a module or full system policy
2. It calls any @associated_call member functions in the resource with the domain
as the first argument.
3. If the domain is inherited from, a child resource is automatically created  
and is associated with the child class.  This resource is named  
`[child name].[resource name]`.

See the specific resource association document for more information.

For more details and examples, see resource_association.md

## AV Rules

Access vector rules define what happens on an access attempt.  They are defined
on the quadruple of: source type, target type, target object class, permissions.

There are five kinds of access vector rules provided by Cascade: allow,
auditallow, dontaudit, neverallow, delete.  Allow rules grant access.
Auditallow audit access when it is granted (by a separate allow rule). 
Dontaudit rules disable auditing for denied access.  Neverallow rules are a
compile time assertion that certain access should not be allowed.  Delete rules
remove access if it is allowed elsewhere.

These rules are defined by five built-in functions: allow(), audit(),
dontaudit(), neverallow(), delete().  Note the rename from the SELinux base
language auditallow to audit, to emphasize that auditallow does not actually
allow access.

These functions have identical signatures except for the function name:

```
fn allow(domain source, type target, class obj_class, [permission] perm);
```

And likewise for audit(), dontaudit(), neverallow() and delete().  Lists of
sources and targets are intentionally omitted to encourage clarity and readability.
Policy authors are encouraged to create virtual types to specify groups and/or
declare their own functions grouping related av rules.

Note the use the makelist annotation to allow automatic coercion from a single
class or permission to a list (See 'annotations' section).

## File labeling

SELinux supports three types of labeling: dynamic labeling, file contexts and
default contexts (of different varieties).

Dynamic labeling rules are specified in policy and determine when the default
labeling behavior should be overridden.  For example, when creating a file in a
directory with type foo, the new file will automatically get the label foo
(matching the parent directory), unless overridden by dynamic labeling rules in
the policy, which may define some other type for the newly created file to get.

File contexts specify standard labels that should be applied by a labeling tool
such as restorecon or setfiles.  These contexts are compiled into a test based
configuration file which is read by these tools when they are run to apply the
labels to target files based on path.

Default contexts specify what labels should be applied to objects that cannot
store labels in extended attributes.  For example, files on filesystems that do
not support extended attributes would get default contexts.  Additionally,
certain non-file objects such as ports or packets will get contexts on creation
as defined by the policy (although packets have their own special handling
which is outside the scope of this document).

Reference Policy implementations treat these types of labeling independently,
which reflects how they are handled at a kernel/system level, but not how high
level users conceptualize them.  In Cascade, all forms of labeling for a given
resource are specified in its resource block.

Runtime resource transitions are achieved through the resource_transition()
built in function, which has the following prototypes:

```
fn resource_transition(resource default, source domain, resource parent, class obj_class);
fn resource_transition(resource default, source domain, resource parent, [class] obj_classes);
```

The default field is first so that it can be passed in when called as a member
function from resources.

TODO: Named resource transitions

TODO: File context labeling

This is under discussion now.  We agree that we should take advantage of the fact that we are parsing paths, not arbitrary strings to provide appropriate semantic checking.  Mickael to provide motivating use case for query syntax approach.

TODO: default contexts.  This will be part of the next phase of design

TODO: file_contexts.subs_dist (although is it necessary with advanced file_context handling features?)

## Constants

Constants may be a helpful way to name data for later reference.  They are
introduced with the "let" keyword.  For example:

```
let read_file_perms = [ read, open, getattr ];
```

The name `read_file_perms` can be used elsewhere and will be replaced at compile
time with the list of permissions.  The compiler infers the type of the
constant from what is assigned to it (this is case the type is [perm]).

## Annotations

Annotations are a way to provide additional metadata about a resource.  This
metadata may be used in various ways by the associated tooling.

Annotations are prefixed with the '@' symbol, followed by the name of the
annotation, and arguments (if any) in parentheses. For example:

```
@derive(*,*)
```

Annotation lines do not end in a semicolon.

### derive annotation

The derive annotation tells the compiler to define member functions by using
the union of the parent class member functions of the same name.  It takes the
name(s) of function(s) to derive, and the list of parents to use as arguments.

```
@derive([foo], *)
```

Is equivalent to:

```
fn foo(...) {
	parent1::foo(...);
	parent2::foo(...);
	// etc
}
```

The derive function may also be given the special character `*` instead of
function names to derive all conflicting functions from parent classes using
this method.

### hint annotation

The hint annotation is passed on to audit2cascade to provide suggestions to
policy authors on certain denials.

When used above a resource, the hint matches AVC messages with that resource as
the *target*.  When used above a domain it matches AVC messages with that
resource used as a *source*). Policy authors may also optionally specify the
other of target or source, the object class, and permissions to hint on.

The final argument is the string to provide to the user.

For example:

```
@hint("Typically domains should derive their own custom tmp type rather than accesing tmp directly")
resource tmp { ... }
```

Example using additional fields:

```
@hint(class=capability, perm=sys_admin, hint="This may be an indication of an attack")
domain foo { ... } 
```

The following arguments may be specified:
source: The scontext field of a denial
target: The tcontext field of a denial
class: The tclass field of a denial
perm: Any permission listed in a denial
hint: A text string to display when using newaudit2allow
attack: Set to True to indicate that this denial should be treated as a
possible security incident
cve: Reference a CVE associated with this denial

### ignore annotation

The ignore annotation can be used to disable compiler warnings for a given line.

```
if (condition) {
	@ignore(conditional-define)
	domain foo { ... }
}
```

The above code would ordinarily display a warning because conditional
definitions can lead to unexpected behavior.  If we wish to leave the code as
is and suppress the warning, we can do so via this annotation.  Of course,
warnings are typically supplied for good reason, and you should seriously
consider whether you really want to suppress the warning rather than fixing
the underlying issue.

### makelist annotation

Tells the compiler that if an object of this type is used in a context that
expects a list, that it should be enclosed in a list.

```
@makelist
type foo;
type bar inherits foo;

fn baz([foo]) { ... }

baz(bar); // Converts to [bar] because of annotation.  Would be a compiler error otherwise
```

### Alias annotation

The alias annotation tells the compiler to provide an alternate name for
referrering to the same item.

This is often used for interoperability. For example, if one is renaming a
type or function in an already deployed policy, one can provide an alias to the
old name for backwards compatibility during a transition period until labels or
callers have been updated.

``
@alias(bar)
resource foo {}
```

## Traits

A trait block defines a collection of functions that children must implement.
It may also provide default implementations of those functions for children to
derive.

## Comments

Comments are a way for a policy author to provide explanatory notes for human
consumption in the code.

Comments in Cascade are introduced with the characters "//".  The compiler will
ignore anything found after "//" until the end of the line.
