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