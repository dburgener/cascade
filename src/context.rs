// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::iter;

use codespan_reporting::files::SimpleFile;

use crate::ast::{Argument, CascadeString};
use crate::functions::{
    argument_to_typeinfo, argument_to_typeinfo_vec, ArgForValidation, FunctionArgument,
};
use crate::internal_rep::{type_slice_to_variant, ClassList, TypeInfo, TypeInstance, TypeMap};

use crate::CascadeErrors;

#[derive(Clone, Debug)]
pub enum BindableObject<'a> {
    Type(TypeInstance<'a>),
    TypeList(TypeInstance<'a>),
    PermList(Vec<String>), // all perms are @makelist
    Class(String),
    ClassList(Vec<String>),
    // Arguments are mapped to the final string by CIL,
    // other sorts of bindings need to be handled in Cascade
    Argument(FunctionArgument<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockType {
    Domain,
    Resource,
    Function,
    Annotation,
    Collection,
    Global,
    Optional,
}

// Encapsulate all local context in a block's scope
#[derive(Clone, Debug)]
pub struct Context<'a> {
    symbols: BTreeMap<CascadeString, BindableObject<'a>>,
    parent_type: Option<&'a TypeInfo>,
    block_type: BlockType,
    parent_context: Option<&'a Context<'a>>,
}

impl<'a> Context<'a> {
    pub fn new(
        block_type: BlockType,
        parent_type: Option<&'a TypeInfo>,
        parent_context: Option<&'a Context<'a>>,
    ) -> Self {
        Context {
            symbols: BTreeMap::new(),
            parent_type,
            block_type,
            parent_context,
        }
    }

    pub fn new_from_args(
        args: &[FunctionArgument<'a>],
        parent_type: Option<&'a TypeInfo>,
        parent_context: &'a Context<'a>,
    ) -> Self {
        // This is only called in functions::validate_body(), to use the arguments in validating
        // the body
        // The local contexts are actually constructed later, in do_rules_pass().  We can set the
        // global context as a parent, but that won't make let bindings in the direct parent
        // available
        let mut context = Context::new(BlockType::Function, parent_type, Some(parent_context));
        context.insert_function_args(args);
        context
    }

    // Remove all symbols from other and add to self
    pub fn drain_symbols(&mut self, other: &mut Self) {
        self.symbols.append(&mut other.symbols);
    }

    pub fn insert_function_args(&mut self, args: &[FunctionArgument<'a>]) {
        for a in args {
            // a.name really should be an CascadeString rather than a String
            self.symbols.insert(
                CascadeString::from(&a.name as &str),
                BindableObject::Argument(a.clone()),
            );
        }
    }

    pub fn symbol_in_context(&self, arg: &str, type_map: &'a TypeMap) -> Option<&'a TypeInfo> {
        let arg = self.convert_arg_this(arg);
        match self.symbols.get(&CascadeString::from(&arg as &str)) {
            Some(b) => match b {
                BindableObject::Type(t) => Some(t.type_info.borrow()),
                // TypeList isn't natural to implement with the current API
                BindableObject::TypeList(_) => todo!(),
                BindableObject::PermList(_) => type_map.get("perm"),
                BindableObject::Class(_) | BindableObject::ClassList(_) => type_map.get("class"),
                BindableObject::Argument(a) => Some(a.param_type),
            },
            None => self
                .parent_context
                .and_then(|c| c.symbol_in_context(&arg, type_map)),
        }
    }

    // Returns whether a symbol refers to a list.  If the symbol does not exist, returns false.
    // Use symbol_in_context to determine existance
    pub fn symbol_is_list(&self, arg: &str) -> bool {
        let arg = self.convert_arg_this(arg);
        match self.symbols.get(&CascadeString::from(&arg as &str)) {
            Some(BindableObject::Type(_)) | Some(BindableObject::Class(_)) | None => false,
            Some(BindableObject::TypeList(_))
            | Some(BindableObject::PermList(_))
            | Some(BindableObject::ClassList(_)) => true,
            Some(BindableObject::Argument(a)) => a.is_list_param,
        }
    }

    // Converts this.* to resolve "this".  Leaves "this" alone, because a bare this is resolved at
    // the CIL level
    pub fn convert_arg_this(&self, arg: &str) -> String {
        match self.parent_type {
            Some(parent) => {
                let mut arg_parts = arg.split('.').peekable();
                if arg_parts.next() == Some("this") && arg_parts.peek().is_some() {
                    // TODO: rewrite with iterators
                    iter::once(parent.name.as_ref())
                        .chain(arg_parts)
                        .collect::<Vec<&str>>()
                        .join(".")
                } else {
                    arg.to_string()
                }
            }
            None => arg.to_string(),
        }
    }

    // Returns the string this is ultimately bound to for use in generated CIL.
    // This should only return a single string, so if the object is a list, it
    // returns None
    // If the object is not in the context, then the string is valid elsewhere,
    // so just return the string
    pub fn get_name_or_string(&self, arg: &CascadeString) -> Option<CascadeString> {
        match self.get_symbol(arg.as_ref()) {
            None => Some(arg.clone()),
            Some(BindableObject::Type(t)) => t.get_name_or_string(self).ok(),
            Some(BindableObject::Argument(_)) => Some(arg.clone()),
            Some(BindableObject::Class(s)) => Some(CascadeString::from(s as &str)),
            Some(BindableObject::TypeList(_))
            | Some(BindableObject::PermList(_))
            | Some(BindableObject::ClassList(_)) => None,
        }
    }

    pub fn get_list(&self, arg: &CascadeString) -> Vec<CascadeString> {
        match self.get_symbol(arg.as_ref()) {
            Some(BindableObject::TypeList(tl)) => {
                // TypeInstance::get_list() returns an error if the instance isn't a list.  We know
                // this instance is a list, because we only inserted lists into TypeList, but we
                // don't currently have a way to prove that to the type system.  Since we don't
                // return a Result here, we can't return an internal error, so just treat it as the
                // empty list instead.
                tl.get_list(self).unwrap_or(Vec::new()).to_vec()
            }
            Some(BindableObject::PermList(l)) | Some(BindableObject::ClassList(l)) => {
                l.iter().map(|i| CascadeString::from(i as &str)).collect()
            }
            // Unwrap() is safe here because all of the get_name_or_string() None cases are handled
            // in get_list()
            _ => {
                vec![self.get_name_or_string(arg).unwrap()]
            }
        }
    }

    // Get the bindable object for a symbol, with recursion to parent contexts
    fn get_symbol(&self, arg: &str) -> Option<&BindableObject<'a>> {
        self.symbols
            .get(&CascadeString::from(arg))
            .or_else(|| self.parent_context.and_then(|c| c.get_symbol(arg)))
    }

    pub fn symbol_is_arg(&self, arg: &str) -> bool {
        matches!(self.get_symbol(arg), Some(BindableObject::Argument(_)))
    }

    pub fn symbol_is_perm(&self, arg: &str) -> bool {
        matches!(self.get_symbol(arg), Some(BindableObject::PermList(_)))
    }

    pub fn insert_binding(&mut self, name: CascadeString, binding: BindableObject<'a>) {
        self.symbols.insert(name, binding);
    }

    // Resolve internal symbols based on the existing symbol table with one layer of indirection
    // This is always done on insertion with the resolved symbols stored, so the single layer
    // always resolves all the way down to the "real" objects, meaning there is no need for
    // recursion to handle symbols bound to other symbols bound to some real object
    // TODO: Make sure the resolved symbols are the same sort of symbol and error otherwise
    fn resolve_internal_symbols(&self, binding: BindableObject<'a>) -> BindableObject<'a> {
        match binding {
            BindableObject::Type(_) | BindableObject::TypeList(_) | BindableObject::Argument(_) => {
                binding
            }
            BindableObject::PermList(p) => BindableObject::PermList(
                p.iter()
                    .flat_map(|s| self.get_list(&CascadeString::from(s.clone())))
                    .map(|s| s.to_string())
                    .collect(),
            ),
            BindableObject::ClassList(c) => BindableObject::ClassList(
                c.iter()
                    .flat_map(|s| self.get_list(&CascadeString::from(s.clone())))
                    .map(|s| s.to_string())
                    .collect(),
            ),
            BindableObject::Class(c) => {
                match self.get_name_or_string(&CascadeString::from(&c as &str)) {
                    Some(s) => BindableObject::Class(s.to_string()),
                    None => BindableObject::ClassList(
                        self.get_list(&CascadeString::from(&c as &str))
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                }
            }
        }
    }

    pub fn insert_from_argument(
        &mut self,
        name: &CascadeString,
        arg: &Argument,
        class_perms: &ClassList,
        type_map: &'a TypeMap,
        file: &'a SimpleFile<String, String>,
    ) -> Result<(), CascadeErrors> {
        let arg = ArgForValidation::from(arg);
        let obj = match &arg {
            ArgForValidation::List(v) => {
                let arg_typeinfo_vec =
                    argument_to_typeinfo_vec(v, type_map, class_perms, &*self, Some(file))?;
                // TODO: classes
                let variant = type_slice_to_variant(&arg_typeinfo_vec, type_map)?;
                let arg_typeinstance = TypeInstance::new(&arg, variant, Some(file), &*self);
                if variant.is_perm(type_map) {
                    BindableObject::PermList(v.iter().map(|s| s.to_string()).collect())
                } else if variant.is_class(type_map) {
                    BindableObject::ClassList(v.iter().map(|s| s.to_string()).collect())
                } else {
                    BindableObject::TypeList(arg_typeinstance)
                }
            }
            _ => {
                let arg_typeinfo =
                    argument_to_typeinfo(&arg, type_map, class_perms, &*self, Some(file))?;
                let arg_typeinstance = TypeInstance::new(&arg, arg_typeinfo, Some(file), &*self);
                // TODO: classes
                if arg_typeinfo.is_perm(type_map) {
                    BindableObject::PermList(vec![arg_typeinstance
                        .get_name_or_string(&*self)?
                        .to_string()])
                } else if arg_typeinfo.is_class(type_map) {
                    BindableObject::Class(arg_typeinstance.get_name_or_string(&*self)?.to_string())
                } else {
                    BindableObject::Type(arg_typeinstance)
                }
            }
        };
        self.insert_binding(name.clone(), self.resolve_internal_symbols(obj));
        Ok(())
    }

    pub fn in_function_block(&self) -> bool {
        self.block_type == BlockType::Function
            || self
                .parent_context
                .map(|p| p.in_function_block())
                .unwrap_or(false)
    }

    pub fn in_annotation(&self) -> bool {
        self.block_type == BlockType::Annotation
    }

    pub fn get_parent_type_name(&self) -> Option<CascadeString> {
        self.parent_type.map(|t| t.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;

    #[test]
    fn test_symbol_in_context() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context = Context::new(BlockType::Domain, None, None);

        context.insert_binding(
            CascadeString::from("foo"),
            BindableObject::PermList(vec!["foo_str".to_string()]),
        );
        context.insert_binding(
            CascadeString::from("baz"),
            BindableObject::Type(TypeInstance::from(tm.get("domain").unwrap())),
        );

        assert_eq!(None, context.symbol_in_context("bar", &tm));
        let perm_symbol = context
            .symbol_in_context("foo", &tm)
            .expect("Symbol foo not found in context");
        assert_eq!(perm_symbol.name.to_string(), "perm".to_string());
        let type_symbol = context
            .symbol_in_context("baz", &tm)
            .expect("Symbol baz not found in context");
        assert_eq!(type_symbol.name.to_string(), "domain".to_string());
    }

    #[test]
    fn test_insert_from_argument() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context = Context::new(BlockType::Domain, None, None);
        let cl = ClassList::new();
        let file = SimpleFile::<String, String>::new("name".to_string(), "source".to_string());

        context
            .insert_from_argument(
                &CascadeString::from("foo"),
                &Argument::Var(CascadeString::from("resource")),
                &cl,
                &tm,
                &file,
            )
            .expect("Insert 'let foo = resource' failed");

        context
            .insert_from_argument(
                &CascadeString::from("bar"),
                &Argument::Var(CascadeString::from("foo")),
                &cl,
                &tm,
                &file,
            )
            .expect("Insert 'let bar = foo' failed");

        let val = context
            .symbol_in_context("bar", &tm)
            .expect("Bar not found in context");
        assert_eq!(val.name.to_string(), "resource".to_string());
    }

    #[test]
    fn test_drain_symbols() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context1 = Context::new(BlockType::Domain, tm.get("domain"), None);
        let mut context2 = Context::new(BlockType::Domain, tm.get("domain"), None);

        context2.insert_binding(
            CascadeString::new("foo".to_string(), 10..12),
            BindableObject::Type(TypeInstance::from(tm.get("domain").unwrap())),
        );

        context1.drain_symbols(&mut context2);

        assert_eq!(
            context1.symbol_in_context("foo", &tm).unwrap().name,
            "domain"
        );

        assert!(context2.symbol_in_context("foo", &tm).is_none());
    }

    #[test]
    fn test_convert_arg_this() {
        let tm = compile::get_built_in_types_map().unwrap();
        let context = Context::new(BlockType::Domain, tm.get("domain"), None);
        assert_eq!(&context.convert_arg_this("foo"), "foo");
        assert_eq!(&context.convert_arg_this("this"), "this");
        assert_eq!(&context.convert_arg_this("this.foo"), "domain.foo");
    }

    #[test]
    fn test_get_name_or_string() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context = Context::new(BlockType::Domain, tm.get("domain"), None);
        context.insert_binding(
            CascadeString::new("foo".to_string(), 10..12),
            BindableObject::Type(TypeInstance::from(tm.get("domain").unwrap())),
        );

        let foo_string = context
            .get_name_or_string(&CascadeString::new("foo".to_string(), 0..1))
            .unwrap();
        assert_eq!(foo_string.get_range(), None); // The range of the builtin domain
        assert_eq!(foo_string.as_ref(), "domain");

        let domain_string = context
            .get_name_or_string(&CascadeString::new("domain".to_string(), 1..2))
            .unwrap();
        assert_eq!(domain_string.get_range(), Some(1..2)); // The range of the reference to domain we looked up
        assert_eq!(domain_string.as_ref(), "domain");
    }

    #[test]
    fn test_nested_context() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut parent_context = Context::new(BlockType::Global, None, None);
        parent_context.insert_binding(
            CascadeString::new("foo".to_string(), 10..12),
            BindableObject::Type(TypeInstance::from(tm.get("domain").unwrap())),
        );
        let child_context = Context::new(BlockType::Domain, None, Some(&parent_context));
        assert_eq!(
            child_context.symbol_in_context("foo", &tm).unwrap().name,
            "domain"
        );
    }
}
