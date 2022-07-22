// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;
use std::iter;

use codespan_reporting::files::SimpleFile;

use crate::ast::{Argument, CascadeString};
use crate::internal_rep::{
    argument_to_typeinfo, argument_to_typeinfo_vec, type_slice_to_variant, ArgForValidation,
    ClassList, FunctionArgument, TypeInfo, TypeInstance, TypeMap,
};
use crate::CascadeErrors;

#[derive(Clone, Debug)]
pub enum BindableObject<'a> {
    Type(&'a TypeInfo),
    TypeList(Vec<&'a TypeInfo>),
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
    Global,
}

// Encapsulate all local context in a block's scope
#[derive(Clone, Debug)]
pub struct Context<'a> {
    symbols: BTreeMap<CascadeString, BindableObject<'a>>,
    type_map: &'a TypeMap,
    parent_type: Option<&'a TypeInfo>,
    block_type: BlockType,
}

impl<'a> Context<'a> {
    pub fn new(
        block_type: BlockType,
        types: &'a TypeMap,
        parent_type: Option<&'a TypeInfo>,
    ) -> Self {
        Context {
            symbols: BTreeMap::new(),
            type_map: types,
            parent_type,
            block_type,
        }
    }

    pub fn new_from_args(
        args: &[FunctionArgument<'a>],
        types: &'a TypeMap,
        parent_type: Option<&'a TypeInfo>,
    ) -> Self {
        let mut context = Context::new(BlockType::Function, types, parent_type);
        context.insert_function_args(args);
        context
    }

    pub fn insert_function_args(&mut self, args: &[FunctionArgument<'a>]) {
        for a in args {
            // a.name really should be an CascadeString rather than a String
            self.symbols.insert(
                CascadeString::from(a.name.as_ref()),
                BindableObject::Argument(a.clone()),
            );
        }
    }

    pub fn symbol_in_context(&self, arg: &str) -> Option<&'a TypeInfo> {
        let arg = self.convert_arg_this(arg);
        match self.symbols.get(&CascadeString::from(arg)) {
            Some(b) => match b {
                BindableObject::Type(t) => Some(t),
                // TypeList isn't natural to implement with the current API
                BindableObject::TypeList(_) => todo!(),
                BindableObject::PermList(_) => self.type_map.get("perm"),
                BindableObject::Class(_) | BindableObject::ClassList(_) => {
                    self.type_map.get("class")
                }
                BindableObject::Argument(a) => Some(a.param_type),
            },
            None => None,
        }
    }

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
    pub fn get_name_or_string(&self, arg: &str) -> Option<CascadeString> {
        match self.symbols.get(&CascadeString::from(arg)) {
            None => Some(CascadeString::from(arg)),
            Some(BindableObject::Type(t)) => Some(t.name.clone()),
            Some(BindableObject::Argument(_)) => Some(CascadeString::from(arg)),
            Some(BindableObject::Class(s)) => Some(CascadeString::from(s.as_ref())),
            Some(BindableObject::TypeList(_))
            | Some(BindableObject::PermList(_))
            | Some(BindableObject::ClassList(_)) => None,
        }
    }

    pub fn get_list(&self, arg: &str) -> Vec<CascadeString> {
        match self.symbols.get(&CascadeString::from(arg)) {
            Some(BindableObject::TypeList(tl)) => tl.iter().map(|t| t.name.clone()).collect(),
            Some(BindableObject::PermList(l)) | Some(BindableObject::ClassList(l)) => {
                l.iter().map(|i| CascadeString::from(i.as_ref())).collect()
            }
            // Unwrap() is safe here because all of the get_name_or_string() None cases are handled
            // in get_list()
            _ => vec![self.get_name_or_string(arg).unwrap()],
        }
    }

    pub fn symbol_is_arg(&self, arg: &str) -> bool {
        matches!(
            self.symbols.get(&CascadeString::from(arg)),
            Some(BindableObject::Argument(_))
        )
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
                    .flat_map(|s| self.get_list(s.as_ref()))
                    .map(|s| s.to_string())
                    .collect(),
            ),
            BindableObject::ClassList(c) => BindableObject::ClassList(
                c.iter()
                    .flat_map(|s| self.get_list(s.as_ref()))
                    .map(|s| s.to_string())
                    .collect(),
            ),
            BindableObject::Class(c) => match self.get_name_or_string(&c) {
                Some(s) => BindableObject::Class(s.to_string()),
                None => BindableObject::ClassList(
                    self.get_list(&c).iter().map(|s| s.to_string()).collect(),
                ),
            },
        }
    }

    pub fn insert_from_argument(
        &mut self,
        name: &CascadeString,
        arg: &Argument,
        class_perms: &ClassList,
        file: &SimpleFile<String, String>,
    ) -> Result<(), CascadeErrors> {
        let arg = ArgForValidation::from(arg);
        let obj = match &arg {
            ArgForValidation::List(v) => {
                let arg_typeinfo_vec =
                    argument_to_typeinfo_vec(v, self.type_map, class_perms, &*self, Some(file))?;
                // TODO: classes
                let variant = type_slice_to_variant(&arg_typeinfo_vec, self.type_map)?;
                if variant.is_perm(self.type_map) {
                    BindableObject::PermList(v.iter().map(|s| s.to_string()).collect())
                } else {
                    BindableObject::TypeList(arg_typeinfo_vec)
                }
            }
            _ => {
                let arg_typeinfo =
                    argument_to_typeinfo(&arg, self.type_map, class_perms, &*self, Some(file))?;
                let arg_typeinstance = TypeInstance::new(&arg, arg_typeinfo, Some(file), &*self);
                // TODO: classes
                if arg_typeinfo.is_perm(self.type_map) {
                    BindableObject::PermList(vec![arg_typeinstance
                        .get_name_or_string(&*self)?
                        .to_string()])
                } else if arg_typeinfo.is_class(self.type_map) {
                    BindableObject::Class(arg_typeinstance.get_name_or_string(&*self)?.to_string())
                } else {
                    BindableObject::Type(arg_typeinfo)
                }
            }
        };
        self.insert_binding(name.clone(), self.resolve_internal_symbols(obj));
        Ok(())
    }

    pub fn in_function_block(&self) -> bool {
        self.block_type == BlockType::Function
    }

    pub fn in_annotation(&self) -> bool {
        self.block_type == BlockType::Annotation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;

    #[test]
    fn test_symbol_in_context() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context = Context::new(BlockType::Domain, &tm, None);

        context.insert_binding(
            CascadeString::from("foo"),
            BindableObject::PermList(vec!["foo_str".to_string()]),
        );
        context.insert_binding(
            CascadeString::from("baz"),
            BindableObject::Type(tm.get("domain").unwrap()),
        );

        assert_eq!(None, context.symbol_in_context("bar"));
        let perm_symbol = context
            .symbol_in_context("foo")
            .expect("Symbol foo not found in context");
        assert_eq!(perm_symbol.name.to_string(), "perm".to_string());
        let type_symbol = context
            .symbol_in_context("baz")
            .expect("Symbol baz not found in context");
        assert_eq!(type_symbol.name.to_string(), "domain".to_string());
    }

    #[test]
    fn test_insert_from_argument() {
        let tm = compile::get_built_in_types_map().unwrap();
        let mut context = Context::new(BlockType::Domain, &tm, None);
        let cl = ClassList::new();
        let file = SimpleFile::<String, String>::new("name".to_string(), "source".to_string());

        context
            .insert_from_argument(
                &CascadeString::from("foo"),
                &Argument::Var(CascadeString::from("resource")),
                &cl,
                &file,
            )
            .expect("Insert 'let foo = resource' failed");

        context
            .insert_from_argument(
                &CascadeString::from("bar"),
                &Argument::Var(CascadeString::from("foo")),
                &cl,
                &file,
            )
            .expect("Insert 'let bar = foo' failed");

        let val = context
            .symbol_in_context("bar")
            .expect("Bar not found in context");
        assert_eq!(val.name.to_string(), "resource".to_string());
    }

    #[test]
    fn test_convert_arg_this() {
        let tm = compile::get_built_in_types_map().unwrap();
        let context = Context::new(BlockType::Domain, &tm, tm.get("domain"));
        assert_eq!(&context.convert_arg_this("foo"), "foo");
        assert_eq!(&context.convert_arg_this("this"), "this");
        assert_eq!(&context.convert_arg_this("this.foo"), "domain.foo");
    }
}
