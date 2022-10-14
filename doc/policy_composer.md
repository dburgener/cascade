# Modules
Modules are made up of domains, resources, traits and other modules. They are
the building blocks for larger scale policy and are a core component of a System.

The user can declare multiple modules and create systems from these modules.
Modules can have alias annotations to provide an alternate name. The user can
then decide which of these individual modules or systems to build (Building of
individual modules and systems is not yet supported. See ROADMAP.md for more
information). A module can also be made virtual, in which case it cannot be
built. The purpose of a virtual module is to create other modules from it.
Since virtual modules cannot have a real instantiation, they are ineligible to
be compile targets. The addition of modules not only simplifies the process of
policy building for users, but also allows for customizability and scalability.

Example module declaration:

```
module my_module {
	domain foo;
	domain bar;
	module other_module;
}
```

# Systems
Systems contain modules and configuration options. Some configurations are
mandatory, meaning that they must be explicitly included in a system, while
other are optional. If the user does not include the optional configurations in
a system, the default values will be given.

Configuration | Mandatory? | Description
--------------|------------|-------------
handle_unknown_perms|Yes|This is how permissions missing from the policy will be handled when loading the policy. The options are allow, deny, and reject. [handleunknown](https://github.com/SELinuxProject/selinux/blob/master/secilc/docs/cil_policy_config_statements.md#handleunknown)
system_type|No|This controls whether MLS/MCS controls are enabled. The only currently supported option is standard. Options for mls and mcs will be added in the future. The default is standard. [MLS/MCS](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/mls_mcs.md)
monolithic|No|This is the option for choosing to build monolithic or modular policy. The options are true and false, with true being for a monolithic build and false for modular. The default is true. [Monolithic and Modular policies](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/types_of_policy.md#monolithic-policy)

Example system declaration:

```
system my_system {
	module my_module;
	module some_other_module;
	let handle_unknown_perms = "allow";
}
```

# System Building
There are 3 options for system building.

(1) compile_combined  
This is the default when casc is ran without the -s flag. It compiles all
defined policies into a single, combined policy. This policy is then outputted
into a file named "out.cil" unless another filename is specified using the -o
flag.

(2) compile_system_policies  
This builds the system(s) that the user chooses by supplying the names of those
systems after the -s flag is used. The CIL policy for each individual system is
outputted into a file named "\<system_name>.cil".

(3) compile_system_policies_all  
This builds all of the systems if the -s flag is used followed by "all".
The CIL policy for each individual system is outputted into a file named "\<system_name>.cil".

## Functions
Currently, if the system to build contains a call to a function that exists in
the policy, but is not in the system, there will be a "No such function"
compile error. This is because during compilation, the function map is reduced
to only the functions within the particular system.
