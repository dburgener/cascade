// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
pub const ALLOW_FUNCTION_NAME: &'static str = "allow";
pub const DONTAUDIT_FUNCTION_NAME: &'static str = "dontaudit";
pub const AUDITALLOW_FUNCTION_NAME: &'static str = "auditallow";
pub const NEVERALLOW_FUNCTION_NAME: &'static str = "neverallow";
pub const FILE_CONTEXT_FUNCTION_NAME: &'static str = "file_context";
pub const DOMTRANS_FUNCTION_NAME: &'static str = "domain_transition";

pub const AV_RULES: &'static [&'static str] = &[
    ALLOW_FUNCTION_NAME,
    DONTAUDIT_FUNCTION_NAME,
    AUDITALLOW_FUNCTION_NAME,
    NEVERALLOW_FUNCTION_NAME,
];

pub const BUILT_IN_TYPES: &'static [&'static str] = &[
    "domain",
    "resource",
    "path",
    "string",
    "obj_class",
    "perm",
    "context",
];
