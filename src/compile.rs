use std::error::Error;
use std::collections::{HashMap, HashSet};
use sexp::{Sexp, Atom};

use crate::ast::{Policy, Expression, Declaration, Statement, FuncCall, Argument};
use crate::internal_rep::{TypeInfo,AvRuleFlavor, AvRule};

pub fn compile(p: &Policy) -> Result<sexp::Sexp, Box<dyn Error>> {
    let type_map = build_type_map(p);
    let type_decl_list = organize_type_map(&type_map)?;

    let av_rules = do_rules_pass(&type_map, &p.exprs)?;

    // TODO: The rest of compilation
    let cil_types = type_list_to_sexp(type_decl_list);
    let cil_av_rules = av_list_to_sexp(av_rules);
    let mut ret = cil_types;
    ret.extend(cil_av_rules.iter().cloned());
    Ok(Sexp::List(ret))
}

// TODO: Currently is domains only
fn build_type_map(p: &Policy) -> HashMap<String, TypeInfo> {
    let mut decl_map: HashMap<String, TypeInfo> = HashMap::new();
    // TODO: This only allows domain declarations at the top level.  Is that okay?  I'm too tired
    // to think about it
    for e in &p.exprs {
        let d = match e {
            Expression::Decl(d) => d,
            _ => continue,
        };
        match d {
            Declaration::Type(t) => { decl_map.insert(t.name.clone(), TypeInfo::new(&**t)) },
            Declaration::Func(_) => continue,
        };
    }

    decl_map
}

//TODO: Centralize Error handling
use std::fmt;

#[derive(Clone, Debug)]
struct HLLCompileError {}

impl fmt::Display for HLLCompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TODO")
    }
}

impl Error for HLLCompileError {}

// This function validates that the relationships in the HashMap are valid, and organizes a Vector
// of type declarations in a reasonable order to be output into CIL.
// In order to be valid, the types must meet the following properties:
// 1. All types have at least one parent
// 2. All listed parents are themselves types (or "domain" or "resource")
// 3. No cycles exist
fn organize_type_map<'a>(types: &'a HashMap<String, TypeInfo>) -> Result<Vec<&'a TypeInfo>, Box<dyn Error>> {
    // TODO: Check what sort of type this is and convert to something more suitable like a vector
    let mut tmp_type_names: HashSet<&String> = types.keys().collect();

    let mut out: Vec<&TypeInfo> = Vec::new();

    while !tmp_type_names.is_empty() {
        let mut current_pass_types: Vec<&TypeInfo> = Vec::new();

        for t in &tmp_type_names {
            let mut wait = false;
            let ti = types.get(*t).unwrap(); // will always be Some
            // TODO: Do we need to consider the case when inherits is empty?  Theoretically it
            // should have always been populated with at least domain or resource by the parser.
            // Should probably return an internal error if that hasn't happened
            for key in &ti.inherits {
                if key != "domain" && key != "resource" && out.iter().any(|&x| &x.name == key) {
                    wait = true;
                    continue;
                }
            }
            if !wait {
                // This means all the parents are previously listed
                current_pass_types.push(ti);
            }
        }
        if current_pass_types.is_empty() && !tmp_type_names.is_empty() {
            // We can't satify the parents for all types
            // TODO: Better error handling
            return Err(Box::new(HLLCompileError {}));
        }
        for t in &current_pass_types {
            tmp_type_names.remove(&t.name);
        }
        out.append(&mut current_pass_types);
    }
    Ok(out)
}

fn do_rules_pass<'a>(types: &'a HashMap<String, TypeInfo>, exprs: &'a Vec<Expression>) -> Result<Vec<AvRule<'a>>, Box<dyn Error>> {
    let mut ret: Vec<AvRule> = Vec::new();
    for e in exprs {
        match e {
            Expression::Stmt(Statement::Call(c)) => {
                if c.is_builtin() {
                    let av_rule = call_to_av_rule(&**c, types)?;
                    ret.push(av_rule);
                }
            },
            Expression::Decl(Declaration::Type(t)) => {
                let child_rules = do_rules_pass(types, &t.expressions)?;
                ret.extend(child_rules.iter().cloned());
            },
            _ => continue,
        }
    }
    Ok(ret)
}

fn argument_to_typeinfo<'a>(a: &Argument, types: &'a HashMap<String, TypeInfo>) -> Result<&'a TypeInfo, Box<dyn Error>> {
    // TODO: Handle the "this" keyword
    let t: Option<&TypeInfo> = match a {
        Argument::Var(s) => types.get(s),
        _ => None,
    };

    t.ok_or(Box::new(HLLCompileError {}))
}

fn call_to_av_rule<'a>(c: &'a FuncCall, types: &'a HashMap<String, TypeInfo>) -> Result<AvRule<'a>, Box<dyn Error>> {
    let flavor = match c.name.as_str() {
        "allow" => AvRuleFlavor::Allow,
        "dontaudit" => AvRuleFlavor::Dontaudit,
        "Auditallow" => AvRuleFlavor::Auditallow,
        "Neverallow" => AvRuleFlavor::Neverallow,
        _ => return Err(Box::new(HLLCompileError {})),
    };

    let source = argument_to_typeinfo(&c.args[0], types)?;
    let target = argument_to_typeinfo(&c.args[1], types)?;
    let class = match &c.args[2] {
        Argument::Var(s) => s,
        _ => return Err(Box::new(HLLCompileError {})),
    };
    let perms = match &c.args[3] {
        Argument::List(l) => l.iter().map(|s| s as &str).collect(),
        _ => return Err(Box::new(HLLCompileError {})),
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

fn type_list_to_sexp(types: Vec<&TypeInfo>) -> Vec<sexp::Sexp> {
    let mut ret: Vec<sexp::Sexp> = Vec::new();
    for t in types {
        ret.push(Sexp::List(vec![Sexp::Atom(Atom::S("type".to_string())),
                                Sexp::Atom(Atom::S(t.name.clone()))]))
    }
    ret
}

fn av_list_to_sexp<'a, T>(av_rules: T) -> Vec<sexp::Sexp>
    where T: IntoIterator<Item = AvRule<'a>>
{
    av_rules.into_iter().map(|r| Sexp::from(r)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Policy, Expression, Declaration, TypeDecl};
    use crate::internal_rep::{TypeInfo};

    #[test]
    fn build_type_map_test() {
        let mut exprs = Vec::new();
        exprs.push(Expression::Decl(Declaration::Type(Box::new(TypeDecl::new("foo".to_string(), vec!["domain".to_string()], Vec::new())))));
        let p = Policy::new(exprs);
        let types = build_type_map(&p);
        match types.get("foo") {
            Some(foo) => assert_eq!(foo.name, "foo"),
            None => panic!("Foo is not in hash map"),
        }
    }

    #[test]
    fn organize_type_map_test() {
        let mut types: HashMap<String, TypeInfo>  = HashMap::new();
        let foo_type = TypeInfo::new(&TypeDecl::new("foo".to_string(), vec!["domain".to_string()], Vec::new()));
        let bar_type = TypeInfo::new(&TypeDecl::new("bar".to_string(), vec!["domain".to_string(), "foo".to_string()], Vec::new()));
        let baz_type = TypeInfo::new(&TypeDecl::new("baz".to_string(), vec!["domain".to_string(), "foo".to_string(), "bar".to_string()], Vec::new()));
        types.insert("foo".to_string(), foo_type);
        types.insert("bar".to_string(), bar_type);
        types.insert("baz".to_string(), baz_type);

        let type_vec = organize_type_map(&types).unwrap();
        //assert_eq!(types.name, "domain");
        //assert_eq!(*types.parent, None);
        //assert_eq!(types.children.len(), 1);
        //assert_eq!(types.children[0].name, "foo");
        // TODO: This is hard to satisfy the borrow checker with.  Let's get everything else
        // working and come back to it
        //assert_eq!(*types.children[0].parent, Some(types));
        //assert_eq!(types.children[0].children.len(), 0);
    }
}
