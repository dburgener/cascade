use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use codespan_reporting::files::SimpleFile;

use crate::ast::{Annotation, Annotations, Argument, CascadeString};
use crate::error::ErrorItem;
use crate::warning::{Warning, Warnings, WithWarnings};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssociatedResource {
    name: CascadeString,
    doms: BTreeSet<Option<CascadeString>>,
    ranges: BTreeMap<String, Range<usize>>,
}

impl AssociatedResource {
    // Unlike most get_range() functions, this one takes an argument.  An AssociatedResource
    // possibly contains information about various associated points, so we need to know the name
    // of the resource we want the range for
    pub fn get_range(&self, resource_name: &str) -> Option<Range<usize>> {
        self.ranges.get(resource_name).cloned()
    }

    pub fn name(&self) -> &CascadeString {
        &self.name
    }

    pub fn get_class_names(&self) -> Vec<String> {
        self.doms
            .iter()
            .map(|d| match d {
                Some(d) => {
                    format!("{}.{}", d, &self.name)
                }
                None => self.name.to_string(),
            })
            .collect()
    }

    pub fn basename(&self) -> &str {
        self.name.as_ref()
    }

    // Return true if type_name is one of the resources that have been combined in this
    // AssociatedResource
    pub fn string_is_instance(&self, type_name: &CascadeString) -> bool {
        match type_name.as_ref().split_once('.') {
            Some((dom, res)) => {
                res == self.name && self.doms.contains(&Some(CascadeString::from(dom)))
            }
            None => type_name == &self.name && self.doms.contains(&None),
        }
    }
}

impl From<&CascadeString> for AssociatedResource {
    fn from(cs: &CascadeString) -> Self {
        let mut ranges = BTreeMap::new();
        // If the range is None, we just don't store it and later map lookups will return None,
        // which is exactly what we want
        if let Some(range) = cs.get_range() {
            ranges.insert(cs.to_string(), range);
        }

        match cs.as_ref().split_once('.') {
            Some((dom, res)) => AssociatedResource {
                name: res.into(),
                doms: [Some(dom.into())].into(),
                ranges,
            },
            None => AssociatedResource {
                name: cs.clone(),
                doms: [None].into(),
                ranges,
            },
        }
    }
}

impl From<CascadeString> for AssociatedResource {
    fn from(cs: CascadeString) -> Self {
        (&cs).into()
    }
}

impl PartialOrd for AssociatedResource {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssociatedResource {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Associated {
    pub resources: BTreeSet<AssociatedResource>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InsertExtendTiming {
    All,
    Early,
    Late,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnnotationInfo {
    MakeList,
    Associate(Associated),
    NestAssociate(Associated),
    Alias(CascadeString),
    // Inherit isn't exposed to users, who should use the "inherits type" syntax, but its helpful
    // internally to track inherits on extends as annotations
    Inherit(Vec<CascadeString>),
    Derive(Vec<Argument>),
    NoDerive,
}

impl AnnotationInfo {
    // All data should exactly break into three sets: a.difference(b), b.difference(a) and
    // a.intersection(b) (which is equivalent to b.intersection(a))

    // Returns a single AnnotationInfo containing any overlap, if it exists
    pub fn intersection(&self, other: &AnnotationInfo) -> Option<AnnotationInfo> {
        use AnnotationInfo::*;
        match (self, other) {
            (MakeList, MakeList) => Some(AnnotationInfo::MakeList),
            (NoDerive, NoDerive) => Some(AnnotationInfo::NoDerive),
            (Associate(left), Associate(right)) | (NestAssociate(left), NestAssociate(right)) => {
                let mut intersect: BTreeSet<AssociatedResource> = BTreeSet::new();
                for l_res in &left.resources {
                    for r_res in &right.resources {
                        if l_res.name == r_res.name {
                            // TODO: The whole below should probably be in an impl in
                            // AssociatedResource.  That allows at least ranges to become private
                            let mut unioned_ranges = BTreeMap::new();
                            for (key, val) in &l_res.ranges {
                                if r_res.ranges.contains_key(key as &String) {
                                    // TODO: I think this could result in weird error messages.
                                    // We're just keeping the left and discarding the right.  I'm
                                    // not 100% sure how much that matters, but if there's
                                    // something wrong with right and not left, the error would be
                                    // confusing.  Probably the common case is just "there is a
                                    // parent named this", and so it doesn't overly matter if we
                                    // point at right or left...
                                    unioned_ranges.insert(key.to_string(), val.clone());
                                }
                            }
                            // TODO: Do we need to worry about insert failing?
                            intersect.insert(AssociatedResource {
                                name: l_res.name.clone(),
                                doms: l_res.doms.union(&r_res.doms).cloned().collect(),
                                ranges: unioned_ranges,
                            });
                        }
                    }
                }
                if intersect.is_empty() {
                    None
                } else {
                    match self {
                        Associate(_) => Some(Associate(Associated {
                            resources: intersect,
                        })),
                        NestAssociate(_) => Some(NestAssociate(Associated {
                            resources: intersect,
                        })),
                        _ => {
                            // impossible
                            None
                        }
                    }
                }
            }
            (Alias(left), Alias(right)) => {
                if left == right {
                    Some(Alias(left.clone()))
                } else {
                    None
                }
            }
            // Treat all @derives as unique, because they require special processing later
            (Derive(_), Derive(_)) => None,
            // These should be filtered earlier and never processed here
            (Inherit(_), Inherit(_)) => None,
            // Enumerate the non-equal cases explicitly so that we get non-exhaustive match errors
            // when updating the enum
            (MakeList, _)
            | (Associate(_), _)
            | (NestAssociate(_), _)
            | (Alias(_), _)
            | (Inherit(_), _)
            | (Derive(_), _)
            | (NoDerive, _) => None,
        }
    }

    // Returns an AnnotationInfo with only the portion in self but not other.
    pub fn difference(&self, other: &AnnotationInfo) -> Option<AnnotationInfo> {
        use AnnotationInfo::*;
        match (self, other) {
            (MakeList, MakeList) => None,
            (NoDerive, NoDerive) => None,
            (Associate(left), Associate(right)) | (NestAssociate(left), NestAssociate(right)) => {
                let difference: BTreeSet<AssociatedResource> = left
                    .resources
                    .iter()
                    .filter(|l_res| !right.resources.iter().any(|r_res| r_res.name == l_res.name))
                    .cloned()
                    .collect();

                if difference.is_empty() {
                    None
                } else {
                    match self {
                        Associate(_) => Some(Associate(Associated {
                            resources: difference,
                        })),
                        NestAssociate(_) => Some(NestAssociate(Associated {
                            resources: difference,
                        })),
                        _ => {
                            //impossible
                            None
                        }
                    }
                }
            }
            (Alias(left), Alias(right)) => {
                if left == right {
                    None
                } else {
                    Some(Alias(left.clone()))
                }
            }
            // No need to special handle Derive/Derive.  Derives are always considered disjoint
            (Derive(_), _)
            | (MakeList, _)
            | (Associate(_), _)
            | (NestAssociate(_), _)
            | (Alias(_), _)
            | (NoDerive, _)
            | (Inherit(_), _) => Some(self.clone()),
        }
    }

    pub fn insert_timing(&self) -> InsertExtendTiming {
        match self {
            AnnotationInfo::Associate(_) => InsertExtendTiming::All,
            AnnotationInfo::NestAssociate(_) => InsertExtendTiming::Early,
            // Inherit is Early, but note that it may also be set on an associated resource, in
            // which case it also has special handling in create_synthetic resource.  The "Early"
            // handling handles regular types
            AnnotationInfo::Inherit(_) => InsertExtendTiming::Early,
            AnnotationInfo::Derive(_) => InsertExtendTiming::Late,
            AnnotationInfo::NoDerive => InsertExtendTiming::Late,
            AnnotationInfo::MakeList => InsertExtendTiming::Late,
            AnnotationInfo::Alias(_) => InsertExtendTiming::Late,
        }
    }

    pub fn as_inherit(&self) -> Option<&Vec<CascadeString>> {
        if let AnnotationInfo::Inherit(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

pub trait Annotated {
    fn get_annotations(&self) -> std::collections::btree_set::Iter<AnnotationInfo>;
}

fn get_associate(
    file: &SimpleFile<String, String>,
    annotation_name_range: Option<Range<usize>>,
    annotation: &Annotation,
) -> Result<AnnotationInfo, ErrorItem> {
    let mut args = annotation.arguments.iter();

    let res_list = match args.next() {
        None => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Missing resource list as first argument",
                Some(file),
                annotation_name_range,
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
        Some(Argument::List(l)) => l,
        Some(a) => {
            return Err(ErrorItem::make_compile_or_internal_error(
                "Invalid argument type",
                Some(file),
                a.get_range(),
                "You must use a set of resource names, enclosed by square brackets, as first argument.",
            ));
        }
    };

    if let Some(a) = args.next() {
        return Err(ErrorItem::make_compile_or_internal_error(
            "Superfluous argument",
            Some(file),
            a.get_range(),
            "There must be only one argument.",
        ));
    }

    Ok(AnnotationInfo::Associate(Associated {
        // Checks for duplicate resources.
        resources: res_list.iter().try_fold(BTreeSet::new(), |mut s, e| {
            if !s.insert(e.into()) {
                Err(ErrorItem::make_compile_or_internal_error(
                    "Duplicate resource",
                    Some(file),
                    e.get_range(),
                    "Only unique resource names are valid.",
                ))
            } else {
                Ok(s)
            }
        })?,
    }))
}

pub fn get_type_annotations(
    file: &SimpleFile<String, String>,
    annotations: &Annotations,
) -> Result<WithWarnings<BTreeSet<AnnotationInfo>>, ErrorItem> {
    let mut infos = BTreeSet::new();
    let mut warnings = Warnings::new();

    // Only allow a set of specific annotation names and strictly check their arguments.
    // TODO: Add tests to verify these checks.
    for annotation in annotations.annotations.iter() {
        match annotation.name.as_ref() {
            "makelist" => {
                // TODO: Check arguments
                // Multiple @makelist annotations doesn't make sense.
                if !infos.insert(AnnotationInfo::MakeList) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Multiple @makelist annotations",
                        Some(file),
                        annotation.name.get_range(),
                        "You need to remove duplicated @makelist annotations.",
                    ));
                }
            }
            "associate" => {
                // Multiple @associate annotations doesn't make sense.
                if !infos.insert(get_associate(
                    file,
                    annotation.name.get_range(),
                    annotation,
                )?) {
                    return Err(ErrorItem::make_compile_or_internal_error(
                        "Multiple @associate annotations",
                        Some(file),
                        annotation.name.get_range(),
                        "You need to remove duplicated @associate annotations.",
                    ));
                }
            }
            "alias" => {
                for a in &annotation.arguments {
                    match a {
                        Argument::Var(a) => {
                            infos.insert(AnnotationInfo::Alias(a.clone()));
                        }
                        _ => {
                            return Err(ErrorItem::make_compile_or_internal_error(
                                "Invalid alias",
                                Some(file),
                                a.get_range(),
                                "This must be a symbol",
                            ));
                        }
                    }
                }
            }
            "derive" => {
                // Arguments are validated at function creation time
                infos.insert(AnnotationInfo::Derive(annotation.arguments.clone()));
            }
            "noderive" => {
                // Do not implicit derive for this type
                infos.insert(AnnotationInfo::NoDerive);
            }
            "hint" => {
                // If get_range() is none, we generated a synthetic hint.  This could be because of
                // inheritance, in which case there was a warning on the parent.  Otherwise, if we
                // generated a synthetic hint for some reason, we can always generate it
                // differently if the signature changes, and the point of the warning is to not
                // rely on any existing signature.  So a warning is only necessary if the hint is
                // actually in source.
                if let Some(range) = annotation.name.get_range() {
                    warnings.push(Warning::new("The hint annotation is not yet supported",
                                  file,
                                  range,
                                  "The signature expected by this annotation may change without warning, and it is currently not functional."));
                }
            }
            _ => {
                return Err(ErrorItem::make_compile_or_internal_error(
                    "Unknown annotation",
                    Some(file),
                    annotation.name.get_range(),
                    "This is not a valid annotation name.",
                ));
            }
        }
    }
    Ok(WithWarnings::new(infos, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ar_string_is_instance_test() {
        let foo_bar = CascadeString::from("foo.bar");
        let bar = CascadeString::from("bar");
        let foo = CascadeString::from("foo");
        let ar = AssociatedResource::from(&foo_bar);

        assert!(ar.string_is_instance(&foo_bar));
        assert!(!ar.string_is_instance(&bar));
        assert!(!ar.string_is_instance(&foo));
    }
}
