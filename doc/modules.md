# Modules
Modules are made up of domains, resources, traits (still in development) and
other modules. They are the building blocks for larger scale policy and are a
core component of a System. The user can declare multiple modules and create
systems from these modules. Modules can have alias annotations to provide an
alternate name. The user can then decide which of these individual modules or
systems to build (Building of individual modules and systems is not yet
supported. See ROADMAP.md for more information). Note that a module can also be
made virtual, in which case it cannot be built. The purpose of a virtual module
is to create other modules from it. Since virtual modules cannot have a real
instantiation, they are ineligible to be compile targets. The addition of
modules not only simplifies the process of policy building for users, but also
allows for customizability and scalability.

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