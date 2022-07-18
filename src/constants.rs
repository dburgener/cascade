// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT
pub const ALLOW_FUNCTION_NAME: &str = "allow";
pub const DONTAUDIT_FUNCTION_NAME: &str = "dontaudit";
pub const AUDITALLOW_FUNCTION_NAME: &str = "auditallow";
pub const NEVERALLOW_FUNCTION_NAME: &str = "neverallow";
pub const FILE_CONTEXT_FUNCTION_NAME: &str = "file_context";
pub const DOMTRANS_FUNCTION_NAME: &str = "domain_transition";

pub const AV_RULES: &[&str] = &[
    ALLOW_FUNCTION_NAME,
    DONTAUDIT_FUNCTION_NAME,
    AUDITALLOW_FUNCTION_NAME,
    NEVERALLOW_FUNCTION_NAME,
];

pub const DOMAIN: &str = "domain";
pub const RESOURCE: &str = "resource";
pub const MODULE: &str = "module";
<<<<<<< HEAD
<<<<<<< HEAD
pub const PERM: &str = "perm";
pub const CLASS: &str = "obj_class";

pub const BUILT_IN_TYPES: &[&str] = &[DOMAIN, RESOURCE, MODULE, "path", "string", CLASS, PERM, "context"];
=======
=======
>>>>>>> 4aaf21a063a208249343acf92e65a2608784682a

pub const BUILT_IN_TYPES: &[&str] = &[
    DOMAIN,
    RESOURCE,
    MODULE,
    "path",
    "string",
    "obj_class",
    "perm",
    "context",
];
>>>>>>> 0072903... Update parser for module blocks and add tests for parsing modules
