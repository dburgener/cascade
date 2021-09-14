pub const ALLOW_FUNCTION_NAME: &'static str = "allow";
pub const DONTAUDIT_FUNCTION_NAME: &'static str = "dontaudit";
pub const AUDITALLOW_FUNCTION_NAME: &'static str = "auditallow";
pub const NEVERALLOW_FUNCTION_NAME: &'static str = "neverallow";
pub const FILE_CONTEXT_FUNCTION_NAME: &'static str = "file_context";

pub const AV_RULES: &'static [&'static str] = &[
    ALLOW_FUNCTION_NAME,
    DONTAUDIT_FUNCTION_NAME,
    AUDITALLOW_FUNCTION_NAME,
    NEVERALLOW_FUNCTION_NAME,
];
