// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
use crate::internal_rep::{FunctionArgument, TypeInfo};

// Encapsulate all local context in a block's scope
#[derive(Default)]
pub struct Context<'a, 'b> {
    args: Option<&'a [FunctionArgument<'b>]>,
}

impl<'a, 'b> From<&'a Vec<FunctionArgument<'b>>> for Context<'a, 'b> {
    fn from(args: &'a Vec<FunctionArgument<'b>>) -> Self {
        Context { args: Some(args) }
    }
}

impl<'b> Context<'_, 'b> {
    pub fn symbol_in_context(&self, arg: &str) -> Option<&'b TypeInfo> {
        match self.args {
            Some(args) => {
                for context_arg in args {
                    if arg == context_arg.name {
                        return Some(context_arg.param_type);
                    }
                }
                None
            }
            None => None,
        }
    }
}
