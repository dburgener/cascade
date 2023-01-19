// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::alias_map::{AliasMap, Declared};
use crate::ast::{Annotations, Argument, CascadeString, Module};
use crate::error::{CascadeErrors, ErrorItem};
use crate::internal_rep::{Annotated, AnnotationInfo, TypeInfo};

pub type ModuleMap<'a> = AliasMap<ValidatedModule<'a>>;

#[derive(Debug, Clone)]
pub struct ValidatedModule<'a> {
    pub name: CascadeString,
    pub annotations: BTreeSet<AnnotationInfo>,
    pub types: BTreeSet<&'a TypeInfo>,
    pub validated_modules: BTreeSet<&'a CascadeString>,
    declaration_file: Option<SimpleFile<String, String>>,
}

impl Declared for ValidatedModule<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.clone()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.name.get_range()
    }

    fn get_generic_name(&self) -> String {
        String::from("module")
    }
}

impl<'a> Annotated for &ValidatedModule<'a> {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo> {
        self.annotations.iter()
    }
}

impl<'a> Eq for ValidatedModule<'a> {}

impl<'a> Ord for ValidatedModule<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl<'a> PartialOrd for ValidatedModule<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.name.cmp(&other.name))
    }
}

impl<'a> PartialEq for ValidatedModule<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl<'a> ValidatedModule<'a> {
    pub fn new(
        name: CascadeString,
        types: BTreeSet<&'a TypeInfo>,
        validated_modules: BTreeSet<&'a CascadeString>,
        mod_decl: Option<&'a Module>,
        declaration_file: Option<SimpleFile<String, String>>,
    ) -> Result<ValidatedModule<'a>, CascadeErrors> {
        let mut module_annontations = BTreeSet::new();
        if let Some(md) = mod_decl {
            if let Some(ref df) = declaration_file {
                module_annontations = get_module_annotations(df, &md.annotations)?;
            }
        }
        Ok(ValidatedModule {
            name,
            annotations: module_annontations,
            types,
            validated_modules,
            declaration_file,
        })
    }
}

fn get_module_annotations(
    file: &SimpleFile<String, String>,
    annotations: &Annotations,
) -> Result<BTreeSet<AnnotationInfo>, ErrorItem> {
    let mut infos = BTreeSet::new();
    for annotation in annotations.annotations.iter() {
        match annotation.name.as_ref() {
            "alias" => {
                for arg in &annotation.arguments {
                    match arg {
                        Argument::Var(a) => {
                            infos.insert(AnnotationInfo::Alias(a.clone()));
                        }
                        _ => {
                            return Err(ErrorItem::make_compile_or_internal_error(
                                "Invalid alias",
                                Some(file),
                                annotation.name.get_range(),
                                "Alias name must be a symbol",
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Unknown annotation",
                    Some(file),
                    annotation.name.get_range(),
                    "The only valid annotation for modules is '@alias'",
                ));
            }
        }
    }
    Ok(infos)
}

pub type MachineMap<'a> = AliasMap<ValidatedMachine<'a>>;

#[derive(Debug, Clone)]
pub struct ValidatedMachine<'a> {
    pub name: CascadeString,
    pub modules: BTreeSet<&'a ValidatedModule<'a>>,
    pub configurations: BTreeMap<String, &'a Argument>,
    declaration_file: Option<SimpleFile<String, String>>,
}

impl Declared for ValidatedMachine<'_> {
    fn get_file(&self) -> Option<SimpleFile<String, String>> {
        self.declaration_file.clone()
    }

    fn get_name_range(&self) -> Option<Range<usize>> {
        self.name.get_range()
    }

    fn get_generic_name(&self) -> String {
        String::from("machine")
    }
}

impl<'a> ValidatedMachine<'a> {
    pub fn new(
        name: CascadeString,
        modules: BTreeSet<&'a ValidatedModule<'a>>,
        configurations: BTreeMap<String, &'a Argument>,
        declaration_file: Option<SimpleFile<String, String>>,
    ) -> Self {
        ValidatedMachine {
            name,
            modules,
            configurations,
            declaration_file,
        }
    }
}
