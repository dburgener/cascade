use sexp::{atom_s, list, Atom, Sexp};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;

use crate::ast::{Argument, DeclaredArgument, FuncCall, FuncDecl, Statement, TypeDecl};
use crate::constants;
use crate::error::{HLLCompileError, HLLErrorItem, HLLErrors, HLLInternalError};

const DEFAULT_USER: &str = "system_u";
const DEFAULT_OBJECT_ROLE: &str = "object_r";
const DEFAULT_DOMAIN_ROLE: &str = "system_r";
const DEFAULT_MLS: &str = "s0";

#[derive(Clone, Debug)]
pub struct TypeInfo {
    pub name: String,
    pub inherits: Vec<String>,
    pub is_virtual: bool,
}

impl TypeInfo {
    pub fn new(td: &TypeDecl) -> TypeInfo {
        TypeInfo {
            name: td.name.clone(),
            inherits: td.inherits.clone(),
            is_virtual: td.is_virtual,
        }
    }

    pub fn make_built_in(name: String) -> TypeInfo {
        TypeInfo {
            name: name,
            inherits: Vec::new(),
            is_virtual: true,
        }
    }

    pub fn is_child_or_actual_type(
        &self,
        target: &TypeInfo,
        types: &HashMap<String, TypeInfo>,
    ) -> bool {
        if self.name == target.name {
            return true;
        }

        for parent in &self.inherits {
            let parent_typeinfo = match types.get(parent) {
                Some(t) => t,
                None => continue,
            };
            if parent_typeinfo.is_child_or_actual_type(target, types) {
                return true;
            }
        }
        return false;
    }

    // Get the type that cil is aware of that this ti falls into
    pub fn get_cil_type(&self) -> &str {
        for name_type in &["path", "string"] {
            if self.name == *name_type {
                return "name";
            }
        }
        if self.is_virtual {
            "attribute"
        } else {
            "type"
        }
    }
}

impl From<&TypeInfo> for sexp::Sexp {
    fn from(typeinfo: &TypeInfo) -> sexp::Sexp {
        let flavor = typeinfo.get_cil_type();
        list(&[atom_s(flavor), atom_s(&typeinfo.name)])
    }
}

// strings may be paths or strings
pub fn type_name_from_string(string: &str) -> String {
    if string.contains("/") {
        "path".to_string()
    } else {
        "string".to_string()
    }
}

fn arg_in_context<'a>(
    arg: &str,
    context: Option<&Vec<FunctionArgument<'a>>>,
) -> Option<&'a TypeInfo> {
    match context {
        Some(context) => {
            for context_arg in context {
                if arg == context_arg.name {
                    return Some(context_arg.param_type);
                }
            }
            None
        }
        None => None,
    }
}

fn typeinfo_from_string<'a>(
    s: &str,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
) -> Option<&'a TypeInfo> {
    if class_perms.is_class(s) {
        types.get("obj_class")
    } else if class_perms.is_perm(s) {
        types.get("perm")
    } else {
        types.get(s)
    }
}

fn argument_to_typeinfo<'a>(
    a: &Argument,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
    context: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<&'a TypeInfo, HLLErrorItem> {
    let t: Option<&TypeInfo> = match a {
        Argument::Var(s) => match arg_in_context(s, context) {
            Some(res) => Some(res),
            None => typeinfo_from_string(s, types, class_perms),
        },
        Argument::Quote(s) => types.get(&type_name_from_string(s)),
        Argument::List(_) => None,
    };

    t.ok_or(HLLErrorItem::Compile(HLLCompileError {
        filename: "TODO".to_string(),
        lineno: 0,
        msg: format!("{} is not a valid type", a),
    }))
}

fn argument_to_typeinfo_vec<'a>(
    arg: &Vec<String>,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
    context: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<Vec<&'a TypeInfo>, HLLErrorItem> {
    let mut ret = Vec::new();
    for s in arg {
        ret.push(argument_to_typeinfo(
            &Argument::Var(s.to_string()),
            types,
            class_perms,
            context,
        )?);
    }
    Ok(ret)
}

#[derive(Clone, Debug)]
pub enum AvRuleFlavor {
    Allow,
    Dontaudit,
    Auditallow,
    Neverallow,
}

#[derive(Clone, Debug)]
pub struct AvRule<'a> {
    pub av_rule_flavor: AvRuleFlavor,
    pub source: &'a TypeInfo,
    pub target: &'a TypeInfo,
    pub class: &'a str,
    pub perms: Vec<&'a str>,
}

impl From<&AvRule<'_>> for sexp::Sexp {
    fn from(rule: &AvRule) -> sexp::Sexp {
        let mut ret = Vec::new();

        ret.push(match rule.av_rule_flavor {
            AvRuleFlavor::Allow => Sexp::Atom(Atom::S(constants::ALLOW_FUNCTION_NAME.to_string())),
            AvRuleFlavor::Dontaudit => {
                Sexp::Atom(Atom::S(constants::DONTAUDIT_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Auditallow => {
                Sexp::Atom(Atom::S(constants::AUDITALLOW_FUNCTION_NAME.to_string()))
            }
            AvRuleFlavor::Neverallow => {
                Sexp::Atom(Atom::S(constants::NEVERALLOW_FUNCTION_NAME.to_string()))
            }
        });

        ret.push(Sexp::Atom(Atom::S(rule.source.name.clone())));
        ret.push(Sexp::Atom(Atom::S(rule.target.name.clone())));

        let mut classpermset = vec![Sexp::Atom(Atom::S(rule.class.to_string()))];

        let perms = rule
            .perms
            .iter()
            .map(|p| Sexp::Atom(Atom::S(p.to_string())))
            .collect();

        classpermset.push(Sexp::List(perms));

        ret.push(Sexp::List(classpermset));

        Sexp::List(ret)
    }
}

#[derive(Copy, Clone)]
pub struct Context<'a> {
    user: &'a str,
    role: &'a str,
    setype: &'a str,
    mls_low: &'a str,
    mls_high: &'a str,
}

impl Context<'_> {
    // All fields except setype is optional.  User and role are replaced with defaults if set to None
    pub fn new<'a>(
        is_domain: bool,
        u: Option<&'a str>,
        r: Option<&'a str>,
        t: &'a str,
        ml: Option<&'a str>,
        mh: Option<&'a str>,
    ) -> Context<'a> {
        Context {
            user: u.unwrap_or(DEFAULT_USER),
            role: r.unwrap_or(if is_domain {
                DEFAULT_DOMAIN_ROLE
            } else {
                DEFAULT_OBJECT_ROLE
            }),
            setype: t,
            mls_low: ml.unwrap_or(DEFAULT_MLS),
            mls_high: mh.unwrap_or(DEFAULT_MLS),
        }
    }
}

impl From<Context<'_>> for sexp::Sexp {
    fn from(c: Context) -> sexp::Sexp {
        let mls_range = Sexp::List(vec![
            Sexp::List(vec![atom_s(c.mls_low)]),
            Sexp::List(vec![atom_s(c.mls_high)]),
        ]);
        Sexp::List(vec![
            atom_s(c.user),
            atom_s(c.role),
            atom_s(c.setype),
            mls_range,
        ])
    }
}

pub struct Sid<'a> {
    name: &'a str,
    context: Context<'a>,
}

impl<'a> Sid<'a> {
    pub fn new(name: &'a str, context: Context<'a>) -> Self {
        Sid {
            name: name,
            context: context,
        }
    }

    fn get_sid_statement(&self) -> Sexp {
        Sexp::List(vec![atom_s("sid"), atom_s(self.name)])
    }

    fn get_sidcontext_statement(&self) -> Sexp {
        Sexp::List(vec![
            atom_s("sidcontext"),
            atom_s(self.name),
            Sexp::from(self.context),
        ])
    }

    fn get_name_as_sexp_atom(&self) -> Sexp {
        atom_s(self.name)
    }
}

pub fn generate_sid_rules(sids: Vec<Sid>) -> Vec<Sexp> {
    let mut ret = Vec::new();
    let mut order = Vec::new();
    for s in sids {
        ret.push(s.get_sid_statement());
        ret.push(s.get_sidcontext_statement());
        order.push(s.get_name_as_sexp_atom());
    }
    ret.push(Sexp::List(vec![atom_s("sidorder"), Sexp::List(order)]));
    ret
}

pub struct Class<'a> {
    pub name: &'a str,
    pub perms: Vec<&'a str>,
}

impl From<&Class<'_>> for sexp::Sexp {
    fn from(c: &Class) -> sexp::Sexp {
        list(&[
            atom_s("class"),
            atom_s(c.name),
            Sexp::List(c.perms.iter().map(|p| atom_s(p)).collect()),
        ])
    }
}

impl<'a> Class<'a> {
    pub fn new(name: &'a str, perms: Vec<&'a str>) -> Self {
        Class {
            name: name,
            perms: perms,
        }
    }

    pub fn contains_perm(&self, perm: &str) -> bool {
        for p in &self.perms {
            if *p == perm {
                return true;
            }
        }
        false
    }
}

pub struct ClassList<'a> {
    pub classes: HashMap<&'a str, Class<'a>>,
}

impl<'a> ClassList<'a> {
    pub fn new() -> Self {
        ClassList {
            classes: HashMap::new(),
        }
    }

    pub fn add_class(&mut self, name: &'a str, perms: Vec<&'a str>) {
        self.classes.insert(name, Class::new(name, perms));
    }

    pub fn generate_class_perm_cil(&self) -> Vec<Sexp> {
        let mut ret: Vec<Sexp> = self.classes.values().map(|c| Sexp::from(c)).collect();

        let classorder = list(&[
            atom_s("classorder"),
            Sexp::List(self.classes.values().map(|c| atom_s(c.name)).collect()),
        ]);

        ret.push(classorder);

        ret
    }

    // In base SELinux, object classes with more than 31 permissions, have a second object class
    // for overflow permissions.  In HLL, we treat all of those the same.  This function needs to
    // handle that conversion in lookups.  If a permission wasn't found for capability, we check
    // capability2
    pub fn verify_permission(&self, class: &str, permission: &str) -> Result<(), HLLCompileError> {
        let class_struct = match self.classes.get(class) {
            Some(c) => c,
            None => {
                return Err(HLLCompileError {
                    msg: format!("No such object class: {}", class),
                    lineno: 0,
                    filename: "TODO".to_string(),
                })
            }
        };

        if class_struct.perms.contains(&permission) {
            return Ok(());
        } else {
            match class {
                "capability" => {
                    return self.verify_permission("capability2", permission);
                }
                "process" => {
                    return self.verify_permission("process2", permission);
                }
                "cap_userns" => {
                    return self.verify_permission("cap2_userns", permission);
                }
                _ => (),
            }

            return Err(HLLCompileError {
                msg: format!(
                    "Permission {} is not defined for object class {}",
                    permission, class
                ),
                lineno: 0,
                filename: "TODO".to_string(),
            });
        }
    }

    pub fn is_class(&self, class: &str) -> bool {
        self.classes.get(class).is_some()
    }

    pub fn is_perm(&self, perm: &str) -> bool {
        for class in self.classes.values() {
            if class.contains_perm(perm) {
                return true;
            }
        }
        false
    }
}

// TODO: This can be converted into a TryFrom for more compile time gaurantees
fn call_to_av_rule<'a>(
    c: &'a FuncCall,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
    args: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<AvRule<'a>, HLLErrors> {
    let flavor = match c.name.as_str() {
        constants::ALLOW_FUNCTION_NAME => AvRuleFlavor::Allow,
        constants::DONTAUDIT_FUNCTION_NAME => AvRuleFlavor::Dontaudit,
        constants::AUDITALLOW_FUNCTION_NAME => AvRuleFlavor::Auditallow,
        constants::NEVERALLOW_FUNCTION_NAME => AvRuleFlavor::Neverallow,
        _ => return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {}))),
    };

    let target_args = vec![
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: "domain".to_string(),
                is_list_param: false,
                name: "source".to_string(),
            },
            types,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: "resource".to_string(),
                is_list_param: false,
                name: "target".to_string(),
            },
            types,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: "obj_class".to_string(),
                is_list_param: false,
                name: "class".to_string(),
            },
            types,
        )?,
        FunctionArgument::new(
            &DeclaredArgument {
                param_type: "perm".to_string(),
                is_list_param: true,
                name: "class".to_string(),
            },
            types,
        )?,
    ];

    let validated_args = validate_arguments(c, &target_args, types, class_perms, args)?;
    let mut args_iter = validated_args.iter();

    let source = args_iter
        .next()
        .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
        .type_info;
    let target = args_iter
        .next()
        .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
        .type_info;
    let class = args_iter
        .next()
        .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
        .get_name_or_string()?;
    let perms = args_iter
        .next()
        .ok_or(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})))?
        .get_list()?;

    if args_iter.next().is_some() {
        return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {})));
    }

    // TODO: Validate number of args, lack of class_name
    Ok(AvRule {
        av_rule_flavor: flavor,
        source: source,
        target: target,
        class: class,
        perms: perms,
    })
}

#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    pub name: String,
    pub args: Vec<FunctionArgument<'a>>,
    pub original_body: &'a Vec<Statement>,
    pub body: Option<Vec<ValidatedStatement<'a>>>,
}

impl<'a> FunctionInfo<'a> {
    pub fn new(
        funcdecl: &'a FuncDecl,
        types: &'a HashMap<String, TypeInfo>,
        parent_type: Option<&'a TypeInfo>,
    ) -> Result<FunctionInfo<'a>, HLLErrors> {
        let mut args = Vec::new();
        let mut errors = HLLErrors::new();

        // All member functions automatically have "this" available as a reference to their type
        match parent_type {
            Some(parent_type) => args.push(FunctionArgument::new_this_argument(parent_type)),
            None => (),
        }

        for a in &funcdecl.args {
            match FunctionArgument::new(&a, types) {
                Ok(a) => args.push(a),
                Err(e) => errors.add_error(e),
            }
        }

        errors.into_result(FunctionInfo {
            name: funcdecl.get_cil_name(),
            args: args,
            original_body: &funcdecl.body,
            body: None,
        })
    }

    pub fn validate_body(
        &mut self,
        functions: &'a HashMap<String, FunctionInfo>,
        types: &'a HashMap<String, TypeInfo>,
        class_perms: &'a ClassList,
    ) -> Result<(), HLLErrors> {
        let mut new_body = Vec::new();
        let mut errors = HLLErrors::new();

        for statement in self.original_body {
            match ValidatedStatement::new(statement, functions, types, class_perms, &self.args) {
                Ok(s) => new_body.push(s),
                Err(mut e) => errors.append(&mut e),
            }
        }
        self.body = Some(new_body);
        errors.into_result(())
    }
}

impl TryFrom<&FunctionInfo<'_>> for sexp::Sexp {
    type Error = HLLErrorItem;

    fn try_from(f: &FunctionInfo) -> Result<sexp::Sexp, HLLErrorItem> {
        let mut macro_cil = vec![
            atom_s("macro"),
            atom_s(&f.name),
            Sexp::List(f.args.iter().map(|a| Sexp::from(a)).collect()),
        ];
        match &f.body {
            None => return Err(HLLErrorItem::Internal(HLLInternalError {})),
            Some(statements) => {
                for statement in statements {
                    match statement {
                        ValidatedStatement::Call(c) => macro_cil.push(Sexp::from(&**c)),
                        ValidatedStatement::AvRule(a) => macro_cil.push(Sexp::from(&*a)),
                    }
                }
            }
        }
        Ok(Sexp::List(macro_cil))
    }
}

#[derive(Debug, Clone)]
pub struct FunctionArgument<'a> {
    pub param_type: &'a TypeInfo,
    pub name: String,
    pub is_list_param: bool,
}

impl<'a> FunctionArgument<'a> {
    pub fn new(
        declared_arg: &DeclaredArgument,
        types: &'a HashMap<String, TypeInfo>,
    ) -> Result<Self, HLLErrorItem> {
        let param_type = match types.get(&declared_arg.param_type) {
            Some(ti) => ti,
            None => {
                return Err(HLLErrorItem::Compile(HLLCompileError {
                    filename: "TODO".to_string(),
                    lineno: 0,
                    msg: format!("No such type or attribute: {}", &declared_arg.param_type),
                }));
            }
        };

        // TODO list parameters

        Ok(FunctionArgument {
            param_type: param_type,
            name: declared_arg.name.clone(),
            is_list_param: declared_arg.is_list_param,
        })
    }

    pub fn new_this_argument(parent_type: &'a TypeInfo) -> Self {
        FunctionArgument {
            param_type: parent_type,
            name: "this".to_string(),
            is_list_param: false,
        }
    }
}

impl From<&FunctionArgument<'_>> for sexp::Sexp {
    fn from(f: &FunctionArgument) -> sexp::Sexp {
        list(&[atom_s(f.param_type.get_cil_type()), atom_s(&f.name)])
    }
}

impl fmt::Display for FunctionArgument<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.param_type.name)
    }
}

#[derive(Debug, Clone)]
pub enum ValidatedStatement<'a> {
    Call(Box<ValidatedCall>),
    AvRule(AvRule<'a>),
}

impl<'a> ValidatedStatement<'a> {
    pub fn new(
        statement: &'a Statement,
        functions: &HashMap<String, FunctionInfo>,
        types: &'a HashMap<String, TypeInfo>,
        class_perms: &ClassList<'a>,
        args: &Vec<FunctionArgument<'a>>,
    ) -> Result<ValidatedStatement<'a>, HLLErrors> {
        match statement {
            Statement::Call(c) => {
                if c.is_builtin() {
                    return Ok(ValidatedStatement::AvRule(call_to_av_rule(
                        c,
                        types,
                        class_perms,
                        Some(args),
                    )?));
                } else {
                    return Ok(ValidatedStatement::Call(Box::new(ValidatedCall::new(
                        c,
                        functions,
                        types,
                        class_perms,
                        Some(args),
                    )?)));
                }
            }
        }
    }
}

impl From<&ValidatedStatement<'_>> for sexp::Sexp {
    fn from(statement: &ValidatedStatement) -> sexp::Sexp {
        match statement {
            ValidatedStatement::Call(c) => Sexp::from(&**c),
            ValidatedStatement::AvRule(a) => Sexp::from(a),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedCall {
    cil_name: String,
    args: Vec<String>,
}

impl ValidatedCall {
    fn new(
        call: &FuncCall,
        functions: &HashMap<String, FunctionInfo>,
        types: &HashMap<String, TypeInfo>,
        class_perms: &ClassList,
        parent_args: Option<&Vec<FunctionArgument>>,
    ) -> Result<ValidatedCall, HLLErrors> {
        let cil_name = call.get_cil_name();
        let function_info = match functions.get(&cil_name) {
            Some(function_info) => function_info,
            None => {
                return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
                    filename: "TODO".to_string(),
                    lineno: 0,
                    msg: format!("No such function: {}", cil_name),
                })));
            }
        };

        // Each argument must match the type the function signature expects
        let mut args = Vec::new();

        for arg in validate_arguments(call, &function_info.args, types, class_perms, parent_args)? {
            args.push(arg.get_name_or_string()?.to_string());
        }

        Ok(ValidatedCall {
            cil_name: cil_name,
            args: args,
        })
    }
}

// Some TypeInfos have a string associated with a particular instance.  Most are just the TypeInfo
#[derive(Clone, Debug)]
enum TypeValue<'a> {
    Str(&'a str),
    Vector(Vec<&'a str>),
    SEType,
}

#[derive(Clone, Debug)]
struct TypeInstance<'a> {
    instance_value: TypeValue<'a>,
    pub type_info: &'a TypeInfo,
}

impl<'a> TypeInstance<'a> {
    fn get_name_or_string(&self) -> Result<&'a str, HLLErrorItem> {
        match &self.instance_value {
            TypeValue::Str(s) => Ok(&s),
            TypeValue::Vector(_) => Err(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: format!("Unexpected list"),
            })),
            TypeValue::SEType => Ok(&self.type_info.name),
        }
    }

    fn get_list(&self) -> Result<Vec<&'a str>, HLLErrorItem> {
        match &self.instance_value {
            TypeValue::Vector(v) => Ok(v.clone()),
            _ => Err(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: format!("Expected list"),
            })),
        }
    }

    fn new(arg: &'a Argument, ti: &'a TypeInfo) -> Self {
        let instance_value = match arg {
            Argument::Var(_) => TypeValue::SEType, // TODO: This may not hold if this is an argument name
            Argument::List(vec) => TypeValue::Vector(vec.iter().map(|s| s as &str).collect()),
            Argument::Quote(q) => TypeValue::Str(q),
        };

        TypeInstance {
            instance_value: instance_value,
            type_info: &ti,
        }
    }
}

fn validate_arguments<'a>(
    call: &'a FuncCall,
    function_args: &Vec<FunctionArgument>,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
    parent_args: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<Vec<TypeInstance<'a>>, HLLErrors> {
    // Some functions start with an implicit "this" argument.  If it does, skip it
    let function_args_iter = function_args.iter().skip_while(|a| a.name == "this");

    if function_args_iter.clone().count() != call.args.len() {
        return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
            filename: "TODO".to_string(),
            lineno: 0,
            msg: format!(
                "Function {} expected {} arguments, got {}",
                call.get_display_name(),
                function_args.len(),
                call.args.len()
            ),
        })));
    }

    let mut args = Vec::new();
    for (a, fa) in call.args.iter().zip(function_args_iter) {
        args.push(validate_argument(a, fa, types, class_perms, parent_args)?);
    }
    Ok(args)
}

fn validate_argument<'a>(
    arg: &'a Argument,
    target_argument: &FunctionArgument,
    types: &'a HashMap<String, TypeInfo>,
    class_perms: &ClassList,
    args: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<TypeInstance<'a>, HLLErrorItem> {
    match arg {
        Argument::List(v) => {
            if !target_argument.is_list_param {
                return Err(HLLErrorItem::Compile(HLLCompileError {
                    filename: "TODO".to_string(),
                    lineno: 0,
                    msg: format!("Unexpected list: {}", arg),
                }));
            }
            let target_ti = match types.get(&target_argument.param_type.name) {
                Some(t) => t,
                None => return Err(HLLErrorItem::Internal(HLLInternalError {})),
            };
            let arg_typeinfo_vec = argument_to_typeinfo_vec(v, types, class_perms, args)?;

            for arg in arg_typeinfo_vec {
                if !arg.is_child_or_actual_type(target_argument.param_type, types) {
                    return Err(HLLErrorItem::Compile(HLLCompileError {
                        filename: "TODO".to_string(),
                        lineno: 0,
                        msg: format!(
                            "Expected type inheriting {}, got {}",
                            target_ti.name, arg.name
                        ),
                    }));
                }
            }
            Ok(TypeInstance::new(arg, &target_ti))
        }
        _ => {
            if target_argument.is_list_param {
                return Err(HLLErrorItem::Compile(HLLCompileError {
                    filename: "TODO".to_string(),
                    lineno: 0,
                    msg: format!("Expected list, got {}", arg),
                }));
            }
            let arg_typeinfo = argument_to_typeinfo(arg, types, class_perms, args)?;

            if arg_typeinfo.is_child_or_actual_type(target_argument.param_type, types) {
                Ok(TypeInstance::new(arg, &arg_typeinfo))
            } else {
                Err(HLLErrorItem::Compile(HLLCompileError {
                    filename: "TODO".to_string(),
                    lineno: 0,
                    msg: format!(
                        "Expected type inheriting {}, got {}",
                        target_argument.param_type.name, arg_typeinfo.name
                    ),
                }))
            }
        }
    }
}

impl From<&ValidatedCall> for sexp::Sexp {
    fn from(call: &ValidatedCall) -> sexp::Sexp {
        let args = call.args.iter().map(|a| atom_s(a)).collect::<Vec<Sexp>>();

        Sexp::List(vec![
            atom_s("call"),
            atom_s(&call.cil_name),
            Sexp::List(args),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::TypeDecl;
    use crate::internal_rep::TypeInfo;

    #[test]
    fn generate_cil_for_av_rule_test() {
        let cil_sexp = Sexp::from(&AvRule {
            av_rule_flavor: AvRuleFlavor::Allow,
            source: &TypeInfo::new(&TypeDecl::new("foo".to_string(), Vec::new(), Vec::new())),
            target: &TypeInfo::new(&TypeDecl::new("bar".to_string(), Vec::new(), Vec::new())),
            class: "file",
            perms: vec!["read", "getattr"],
        });

        let cil_expected = "(allow foo bar (file (read getattr)))";

        assert_eq!(cil_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context() {
        let context_sexp = Sexp::from(Context::new(
            true,
            Some("u"),
            Some("r"),
            "t",
            Some("s0"),
            Some("s0"),
        ));
        let cil_expected = "(u r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn sexp_from_context_defaults() {
        let context_sexp = Sexp::from(Context::new(true, None, None, "t", None, None));
        let cil_expected = "(system_u system_r t ((s0) (s0)))";
        assert_eq!(context_sexp.to_string(), cil_expected.to_string());
    }

    #[test]
    fn generate_sid_rules_test() {
        let sid1 = Sid::new("foo", Context::new(true, None, None, "foo_t", None, None));
        let sid2 = Sid::new("bar", Context::new(false, None, None, "bar_t", None, None));

        let rules = generate_sid_rules(vec![sid1, sid2]);
        let cil_expected = vec![
            "(sid foo)",
            "(sidcontext foo (system_u system_r foo_t ((s0) (s0))))",
            "(sid bar)",
            "(sidcontext bar (system_u object_r bar_t ((s0) (s0))))",
            "(sidorder (foo bar))",
        ];
        assert_eq!(rules.len(), cil_expected.len());
        let mut iter = rules.iter().zip(cil_expected.iter());
        while let Some(i) = iter.next() {
            assert_eq!(i.0.to_string(), i.1.to_string());
        }
    }

    #[test]
    fn classlist_test() {
        let mut classlist = ClassList::new();
        classlist.add_class("file", vec!["read", "write"]);
        classlist.add_class("capability", vec!["mac_override", "mac_admin"]);

        assert!(classlist.is_class("file"));
        assert!(classlist.is_class("capability"));
        assert!(!classlist.is_class("foo"));
        assert!(classlist.is_perm("read"));
        assert!(!classlist.is_perm("bar"));

        let cil = classlist.generate_class_perm_cil();

        assert_eq!(cil.len(), 3);
        // generate_class_perm_cil() doesn't provide an ordering guarantee
        let cil = Sexp::List(cil).to_string();
        assert!(cil.contains("(class capability (mac_override mac_admin))"));
        assert!(cil.contains("(class file (read write))"));
        assert!(
            cil.contains("(classorder (capability file))")
                || cil.contains("(classorder (file capability))")
        );
    }

    #[test]
    fn verify_permissions_test() {
        let mut classlist = ClassList::new();
        classlist.add_class("foo", vec!["bar", "baz"]);
        classlist.add_class("capability", vec!["cap_foo"]);
        classlist.add_class("capability2", vec!["cap_bar"]);
        classlist.add_class("process", vec!["not_foo"]);
        classlist.add_class("process2", vec!["foo"]);

        assert!(classlist.verify_permission("foo", "bar").is_ok());
        assert!(classlist.verify_permission("foo", "baz").is_ok());
        assert!(classlist.verify_permission("capability", "cap_bar").is_ok());
        assert!(classlist.verify_permission("process", "foo").is_ok());

        match classlist.verify_permission("bar", "baz") {
            Ok(_) => panic!("Nonexistent class verified"),
            Err(e) => assert!(e.msg.contains("No such object class")),
        }

        match classlist.verify_permission("foo", "cap_bar") {
            Ok(_) => panic!("Nonexistent permission verified"),
            Err(e) => assert!(e.msg.contains("cap_bar is not defined for")),
        }
    }
}
