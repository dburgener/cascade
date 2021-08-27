use std::collections::HashMap;

use sexp::{atom_s, list, Atom, Sexp};
use std::collections::HashMap;
use std::convert::TryFrom;

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
}

impl From<&TypeInfo> for sexp::Sexp {
    fn from(typeinfo: &TypeInfo) -> sexp::Sexp {
        let flavor = if typeinfo.is_virtual {
            "attribute"
        } else {
            "type"
        };
        list(&[atom_s(flavor), atom_s(&typeinfo.name)])
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

fn argument_to_typeinfo<'a>(
    a: &Argument,
    types: &'a HashMap<String, TypeInfo>,
    context: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<&'a TypeInfo, HLLErrorItem> {
    // TODO: Handle the "this" keyword
    let t: Option<&TypeInfo> = match a {
        Argument::Var(s) => match arg_in_context(s, context) {
            Some(res) => Some(res),
            None => types.get(s),
        },
        _ => None,
    };

    t.ok_or(HLLErrorItem::Compile(HLLCompileError {
        filename: "TODO".to_string(),
        lineno: 0,
        msg: format!("{} is not a valid type", a),
    }))
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
}

// TODO: This can be converted into a TryFrom for more compile time gaurantees
fn call_to_av_rule<'a>(
    c: &'a FuncCall,
    types: &'a HashMap<String, TypeInfo>,
    args: Option<&Vec<FunctionArgument<'a>>>,
) -> Result<AvRule<'a>, HLLErrors> {
    let flavor = match c.name.as_str() {
        constants::ALLOW_FUNCTION_NAME => AvRuleFlavor::Allow,
        constants::DONTAUDIT_FUNCTION_NAME => AvRuleFlavor::Dontaudit,
        constants::AUDITALLOW_FUNCTION_NAME => AvRuleFlavor::Auditallow,
        constants::NEVERALLOW_FUNCTION_NAME => AvRuleFlavor::Neverallow,
        _ => return Err(HLLErrors::from(HLLErrorItem::Internal(HLLInternalError {}))),
    };

    if c.args.len() != 4 {
        return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
            filename: "TODO".to_string(),
            lineno: 0,
            msg: format!(
                "Expected 4 args to built in function {}.  Got {}.",
                c.name.as_str(),
                c.args.len()
            ),
        })));
    }

    let source = argument_to_typeinfo(&c.args[0], types, args)?;
    let target = argument_to_typeinfo(&c.args[1], types, args)?;
    let class = match &c.args[2] {
        Argument::Var(s) => s,
        a => {
            return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: format!("Expected an object class, got {:?}", a),
            })))
        }
    };
    let perms = match &c.args[3] {
        Argument::List(l) => l.iter().map(|s| s as &str).collect(),
        // TODO, a Var can probably be coerced.  This is the @makelist annotation case
        p => {
            return Err(HLLErrors::from(HLLErrorItem::Compile(HLLCompileError {
                filename: "TODO".to_string(),
                lineno: 0,
                msg: format!("Expected a list of permissions, got {:?}", p),
            })))
        }
    };

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
    ) -> Result<(), HLLErrors> {
        let mut new_body = Vec::new();
        let mut errors = HLLErrors::new();

        for statement in self.original_body {
            match ValidatedStatement::new(statement, functions, types, &self.args) {
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
            is_list_param: false, //TODO
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
        list(&[Sexp::from(f.param_type), atom_s(&f.name)])
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
        args: &Vec<FunctionArgument<'a>>,
    ) -> Result<ValidatedStatement<'a>, HLLErrors> {
        match statement {
            Statement::Call(c) => {
                if c.is_builtin() {
                    return Ok(ValidatedStatement::AvRule(call_to_av_rule(
                        c,
                        types,
                        Some(args),
                    )?));
                } else {
                    return Ok(ValidatedStatement::Call(Box::new(ValidatedCall::new(
                        c,
                        functions,
                        types,
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
        let mut function_args_iter = function_info.args.iter();
        function_args_iter.next(); // The first argument to function_info.args is the implicit 'this'
        for (a, fa) in call.args.iter().zip(function_args_iter) {
            args.push(validate_argument(a, fa, types, parent_args)?);
        }

        Ok(ValidatedCall {
            cil_name: cil_name,
            args: args,
        })
    }
}

fn validate_argument(
    arg: &Argument,
    target_argument: &FunctionArgument,
    types: &HashMap<String, TypeInfo>,
    args: Option<&Vec<FunctionArgument>>,
) -> Result<String, HLLErrorItem> {
    let arg_typeinfo = argument_to_typeinfo(arg, types, args)?;

    if arg_typeinfo.is_child_or_actual_type(target_argument.param_type, types) {
        Ok(arg_typeinfo.name.clone())
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

        let cil = classlist.generate_class_perm_cil();

        assert_eq!(cil.len(), 3);
        assert_eq!(cil[0].to_string(), "(class file (read write))".to_string());
        assert_eq!(
            cil[1].to_string(),
            "(class capability (mac_override mac_admin))".to_string()
        );
        assert_eq!(cil[2].to_string(), "(classorder (file capability))");
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
