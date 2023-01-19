// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use std::collections::BTreeMap;
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::error::{CascadeErrors, ErrorItem, InternalError};

#[derive(Clone, Debug)]
pub struct AliasMap<T> {
    declarations: BTreeMap<String, T>,
    #[allow(dead_code)]
    aliases: BTreeMap<String, String>,
}

pub type AliasMapIter<'a, T> = std::collections::btree_map::Iter<'a, String, T>;
pub type AliasMapValues<'a, T> = std::collections::btree_map::Values<'a, String, T>;
pub type AliasMapValuesMut<'a, T> = std::collections::btree_map::ValuesMut<'a, String, T>;
pub type AliasMapIntoIter<T> = std::collections::btree_map::IntoIter<String, T>;

impl<T: Declared> AliasMap<T> {
    fn get_type_name<'a>(aliases: &'a BTreeMap<String, String>, key: &'a str) -> &'a str {
        if aliases.contains_key(key) {
            &aliases[key]
        } else {
            key
        }
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        let type_name = Self::get_type_name(&self.aliases, key);
        self.declarations.get(type_name)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        let type_name = Self::get_type_name(&self.aliases, key);
        self.declarations.get_mut(type_name)
    }

    pub fn new() -> Self {
        AliasMap {
            declarations: BTreeMap::new(),
            aliases: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: T) -> Result<(), CascadeErrors> {
        // try_insert() is nightly only.  Convert once stable.
        if let Some(orig_decl) = self.get(&key) {
            // If the file is None, this is a synthetic type, and we should have handled
            // the error earlier.
            let mut error = ErrorItem::make_compile_or_internal_error(
                "Duplicate declaration",
                value.get_file().as_ref(),
                value.get_name_range(),
                &format!(
                    "A {} named {} already exists",
                    value.get_generic_name(),
                    key
                ),
            );
            if let ErrorItem::Compile(e) = error {
                let (file, range) = match (orig_decl.get_file(), orig_decl.get_name_range()) {
                    (Some(file), Some(range)) => (file, range),
                    _ => {
                        // The previous one was a synthetic type.  We should have already errored
                        // out
                        return Err(ErrorItem::Internal(InternalError::new()).into());
                    }
                };
                error = ErrorItem::Compile(e.add_additional_message(
                    &file,
                    range,
                    "Already defined here",
                ));
            }
            return Err(error.into());
        }

        self.declarations.insert(key, value);
        Ok(())
    }

    pub fn values(&self) -> AliasMapValues<'_, T> {
        self.declarations.values()
    }

    pub fn values_mut(&mut self) -> AliasMapValuesMut<'_, T> {
        self.declarations.values_mut()
    }

    pub fn iter(&self) -> AliasMapIter<'_, T> {
        self.declarations.iter()
    }

    pub fn append(&mut self, other: &mut AliasMap<T>) {
        self.declarations.append(&mut other.declarations);
        self.aliases.append(&mut other.aliases);
    }

    pub fn set_aliases(&mut self, aliases: BTreeMap<String, String>) {
        self.aliases = aliases
    }

    // fallible extend, reject duplicates
    pub fn try_extend<I: IntoIterator<Item = (String, T)>>(
        &mut self,
        iter: I,
    ) -> Result<(), CascadeErrors> {
        for item in iter {
            self.insert(item.0, item.1)?;
        }
        Ok(())
    }
}

impl<T> Extend<(String, T)> for AliasMap<T> {
    fn extend<I: IntoIterator<Item = (String, T)>>(&mut self, iter: I) {
        self.declarations.extend(iter)
    }
}

impl<T> IntoIterator for AliasMap<T> {
    type Item = (String, T);
    type IntoIter = AliasMapIntoIter<T>;

    fn into_iter(self) -> AliasMapIntoIter<T> {
        self.declarations.into_iter()
    }
}

pub trait Declared {
    fn get_file(&self) -> Option<SimpleFile<String, String>>;
    fn get_name_range(&self) -> Option<Range<usize>>;
    fn get_generic_name(&self) -> String;
}
