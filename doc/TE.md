# Type Enforcement
Type Enforcement (TE) is one of the security models provided by SELinux.  In type enforcement, objects on the system (processes, files, sockets, etc) are each assigned a unique identifier known as a type.  Policy rules specify how types may interact.

Type Enforcement policies have a subject, which attempts to perform some action, an object which is acted upon, and a description of the action.  In SELinux this description is made up of an 'object class', which describes what sort of thing the object is, and permissions (such as read or write) which describe the access.  Permissions are defined in relation to object classes (so 'listen' is a valid permission on sockets, but not on files).

For more information, review the official SELinux documentation at https://selinuxproject.org/page/Main_Page

## Types
In SELinux, a type is a unique identifier that specifies security equivalence from the perspective of TE policy.  HLL is also a strongly typed language.  The types that are used as identifiers for TE policy are also in the set of types from the language perspective.  In HLL there are several special types that are built into the language.  All other types in our policy must derive from one of these types.

A 'domain' is a type describing a process on a Linux system and therefore may be a subject in a TE rule.[1]  Domains may also be the object in a TE rule (two common examples of this are: 1. Files in /proc typically have labels matching the process they describe and 2. Many IPC mechanisms request access directly on the target process.)

A 'resource' is a type that is not a domain.  Resources may not be the subject in a TE rule.

Domains and resources are declared using the domain and resource keywords respectively:

    domain iptables {}

    resource iptables_conf {}

The block enclosed in curly braces may be used to specify access rules on this type, covered later in this document.

The rationale for this distinction between domains and resources is that it allows us to take advantage of this semantic knowledge at compile time for use in built in functions, syntax improvements and linting.

HLL is statically types and function calls must specify the types of their arguments.  For arguments that may be either domains or resources, the "type" keyword may be used, however new types must always be either a domain or a resource.

Additional built in types include: object classes and permissions.

Lists of objects of the same type are supported and specified by the syntax [type].

[1] In the SELinux base policy language, non-domains may actually be subjects in certain contexts (the filesystem associate permission).  In HLL we enforce the rule that only domains may be subjects and handle filesystem associate through another mechanism (see the "Resources" section)

### Type inheritance
When inheriting from multiple types, they may provide member functions with conflicting names.  If that is the case, the derived type *must* override these types.  This can be done by manually defining a new funtion (which may call parent classes using the syntax classname::function_name()), or using the "derive" annotation.  See the section on annotations.

### List of built in types
The following types are built in to the language:

* object
	- domain
	- resource
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
* [T]

TODO: add heirachy chart
TODO: Make a directory tree to get formatting
TODO: Which of these can be in a core library?

### Associating resources with a domain

Resources may be "associated" with a domain using the `associate` built in function, which takes a single list of resources to associate:

    domain foo {
        associate([
            bar
            baz
         ]);
    }

Associating a resource with a domain does three things:

1. It causes that resource to be grouped together with the domain when the domain is included in a module or full system policy
2. It calls the resource's __assoc__() function (if present) with the domain as the first argument.
3. If the domain is inherited from, a child resource (TODO: named?) is automatically created and is associated with the child class

## AV Rules

Access vector rules define what happens on an access attempt.  They are defined on the quadruple of: source type, target type, target object class, permissions.

There are five kinds of access vector rules provided by HLL: allow, auditallow, dontaudit, neverallow, delete.  Allow rules grant access.  Auditallow audit access when it is granted (by a separate allow rule).  Dontaudit rules disable auditing for denied access.  Neverallow rules are a compile time assertion that certain access should not be allowed.  Delete rules remove access if it is allowed elsewhere.

These rules are defined by five built-in functions: allow(), audit(), dontaudit(), neverallow(), delete().  Note the rename from the SELinux base language auditallow to audit, to emphasize that auditallow does not actually allow access.

These functions have identical signatures except for the function name:

    fn allow(domain source, object target, [class] obj_classes, [permission] perm);

And likewise for audit(), dontaudit(), neverallow() and delete().  Lists of sources and targets are intentionally omitted to encourage clarity and readability.  Policy authors are encouraged to create virtual types to specify groups and/or declare their own functions grouping related av rules.

Note the use the makelist annotation to allow automatic coercion from a single class or permission to a list.

## Functions

Policy authors can define functions using the keyword 'fn'.  Functions defined inside the curly block for a type will be member functions of that type, and will be able to refer to themselves as using the keyword 'this'.  To call a member function, you use the '.' operator, with the name of the type, followed by a ., followed by the function name.  For example if the read() function is defined on the iptables_conf resource, then it can be called using iptables_conf.read().

If a function is called inside a curly block, HLL will attempt to pass the type of the curly block as the first argument to the function.  If this is not valid according to type checking, it is a compiler error.

For example:

    resource iptables_conf {
    	fn read(domain source) {
    		// Define the function here
    	}
    }

    domain iptables {
    	iptables_conf.read(); // passes 'this' (aka iptables) as the first argument
    }

TODO: this syntax is potentially confusing.  Do we have a better suggestion (Mickael to think)

## File labeling

SELinux supports three types of labeling: dynamic labeling, file contexts and default contexts (of different varieties).

Dynamic labeling rules are specified in policy and determine when the default labeling behavior should be overridden.  For example, when creating a file in a directory with type foo, the new file will automatically get the label foo (matching the parent directory), unless overridden by dynamic labeling rules in the policy, which may define some other type for the newly created file to get.

File contexts specify standard labels that should be applied by a labeling tool such as restorecon or setfiles.  These contexts are compiled into a test based configuration file which is read by these tools when they are run to apply the labels to target files based on path.

Default contexts specify what labels should be applied to objects that cannot store labels in extended attributes.  For example, files on filesystems that do not support extended attributes would get default contexts.  Additionally, certain non-file objects such as ports or packets will get contexts on creation as defined by the policy (although packets have their own special handling which is outside the scope of this document).

Reference Policy implementations treat these types of labeling independently, which reflects how they are handled at a kernel/system level, but not how high level users conceptualize them.  In HLL, all forms of labeling for a given resource are specified in its resource block.

Runtime resource transitions are achieved through the resource_transition() built in function, which has the following prototypes:

    fn resource_transition(resource target, source domain, resource parent_dir, class obj_class);
    fn resource_transition(resource target, source domain, resource parent_dir, [class] obj_classes);

The target field is first so that it can be passed in when called as a member function from resources.

TODO: File context labeling

This is under discussion now.  We agree that we should take advantage of the fact that we are parsing paths, not arbitrary strings to provide appropriate semantic checking.  Mickael to provide motivating use case for query syntax approach.

TODO: default contexts.  This will be part of the next phase of design

TODO: file_contexts.subs_dist (although is it necessary with advanced file_context handling features?)

## Constants

Constants may be a helpful way to name data for later reference.  They are introduced with the "let" keyword.  For example:

let read_file_perms = [ read, open, getattr ];

The read_file_perms can be used elsewhere and will be replaced at compile time with the list of permissions.  The compiler infers the type of the constant from what is assigned to it (this is case the type is [perm]).

## Annotations

Annotations are a way to provide additional metadata about a resource.  This metadata may be used in various ways by the associated tooling.

Annotations are prefixed with the '@' symbol, followed by the name of the annotation, and arguments (if any) in parentheses. For example:

    @derive(all)

Annotation lines do not end in a semicolon.

### derive annotation

The derive annotation tells the compiler to define member functions by using the union of the parent class member functions of the same name.  It takes the name(s) of function(s) to derive as arguments.

    @derive(foo)

Is equivalent to:

    fn foo(...) {
    	parent1::foo(...);
    	parent2::foo(...);
    	// etc
    }

The derive function may also be given the keyword "all" instead of function names to derive all conflicting functions from parent classes using this method.  (This implies that the word "all" is reserved and cannot be used as a function name).

TODO: This should maybe be a macro rather than an attribute
	DB: I see the point here.  But macros are a dangerous feature in general (support obfuscation and challenging for automatic parsing).  While it may be more naturally thought of as a macro, I'm not sure why it couldn't be implemented as annotation in order to keep macros out of the language

### hint annotation

The hint annotation is passed on to newaudit2allow (TODO: name TBD) to provide suggestions to policy authors on certain denials.

When used above a resource, the hint matches AVC messages with that resource as the *target*.  When used above a domain it matches AVC messages with that resource used as a *source*). Policy authors may also optionally specify other of target or source, the object class, and permissions to hint on.

The final argument is the string to provide to the user.

For example:

    @hint("Typically domains should derive their own custom tmp type rather than accesing tmp directly")
    resource tmp { ... }

Example using additional fields:

    @hint(class=capability, perm=sys_admin, hint="This may be an indication of an attack")
    domain foo { ... } 

The following arguments may be specified:
source: The scontext field of a denial
target: The tcontext field of a denial
class: The tclass field of a denial
perm: Any permission listed in a denial
hint: A text string to display when using newaudit2allow
attack: Set to True to indicate that this denial should be treated as a possible ongoing security incident
cve: Reference a CVE associated with this denial

### ignore annotation

The ignore annotation can be used to disable compiler warnings for a given line.

    if (condition) {
        @ignore(conditional-define)
        domain foo { ... }
    }

The above code would ordinarily display a warning because conditional definitions can lead to unexpected behavior.  If we wish to leave the code as is and suppress the warning, we can do so via this annotation.  Of course, warnings are typically supplied for good reason, and you should seriously consider whether you really want to suppress the warning rather than fixing the underlying issue.

### makelist annotation

Tells the compiler that if an object of this type is used in a context that expects a list, that it should be enclosed in a list

    @makelist
    type foo;
    type bar inherits foo;

    fn baz([foo]) { ... }

    baz(bar); // Converts to [bar] because of annotation.  Would be a compiler error otherwise

## Comments

Comments are a way for a policy author to provide explanatory notes for human consumption in the code.

Comments in HLL are introduced with the characters "//".  The compiler will ignore anything found after "//" until the end of the line.

Multiline comments are not currently supported, but may be considered in the future.  Multiline comments have the following drawbacks:
* They encourage the anti-pattern of commenting out code.  Commented out code will typically be unmaintained and clutters the code base. Maintaining historical information is the role of the version control system.
* Forgotten terminators or nested terminators create class of bugs where comments don't end where expected.
* Version control systems don't reflect the history of a line being removed and/or re-added to a code base on a line by line basis.

