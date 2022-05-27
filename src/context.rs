// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;

use codespan_reporting::files::SimpleFile;

use crate::ast::{Argument, CascadeString};
use crate::internal_rep::{
    argument_to_typeinfo, argument_to_typeinfo_vec, ArgForValidation, ClassList, FunctionArgument,
    TypeInfo, TypeInstance, TypeMap,
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

// Encapsulate all local context in a block's scope
#[derive(Clone, Debug)]
pub struct Context<'a> {
    symbols: BTreeMap<CascadeString, BindableObject<'a>>,
    type_map: &'a TypeMap,
}

impl<'a> Context<'a> {
    pub fn new(types: &'a TypeMap) -> Self {
        Context {
            symbols: BTreeMap::new(),
            type_map: types,
        }
    }

    pub fn new_from_args(args: &Vec<FunctionArgument<'a>>, types: &'a TypeMap) -> Self {
        let mut context = Context::new(types);
        context.insert_function_args(args);
        context
    }

    pub fn insert_function_args(&mut self, args: &Vec<FunctionArgument<'a>>) {
        for a in args {
            // a.name really should be an CascadeString rather than a String
            self.symbols.insert(
                CascadeString::from(a.name.as_ref()),
                BindableObject::Argument(a.clone()),
            );
        }
    }

    pub fn symbol_in_context(&self, arg: &str) -> Option<&'a TypeInfo> {
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

    pub fn insert_from_argument(
        &mut self,
        name: &CascadeString,
        arg: &Argument,
        class_perms: &ClassList,
        file: &SimpleFile<String, String>,
    ) -> Result<(), CascadeErrors> {
        let arg = ArgForValidation::from(arg);
        match &arg {
            ArgForValidation::List(v) => {
                let arg_typeinfo_vec =
                    argument_to_typeinfo_vec(v, self.type_map, class_perms, &*self, file)?;
                // TODO: classes and perms
                let obj = BindableObject::TypeList(arg_typeinfo_vec);
                self.insert_binding(name.clone(), obj);
            }
            _ => {
                let arg_typeinfo =
                    argument_to_typeinfo(&arg, self.type_map, class_perms, &*self, file)?;
                let arg_typeinstance = TypeInstance::new(&arg, arg_typeinfo, file);
                // TODO: classes
                let obj = if arg_typeinfo.is_perm(self.type_map) {
                    BindableObject::PermList(vec![arg_typeinstance
                        .get_name_or_string(&*self)?
                        .to_string()])
                } else if arg_typeinfo.is_class(self.type_map) {
                    BindableObject::Class(arg_typeinstance.get_name_or_string(&*self)?.to_string())
                } else {
                    BindableObject::Type(arg_typeinfo)
                };
                self.insert_binding(name.clone(), obj);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile;

    #[test]
    fn test_symbol_in_context() {
        let tm = compile::get_built_in_types_map();
        let mut context = Context::new(&tm);

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
}
