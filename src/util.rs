// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, BTreeSet};

// BTreeMap::append overwrites the original key if appending a duplicate
// Something that we do a few times in Cascade is to have a BTreeMap<K, BTreeSet<V>>, and in that
// case, we would like to insert the values from other::V into self::V on key collision
pub fn append_set_map<K: std::cmp::Ord, V: std::cmp::Ord>(
    orig: &mut BTreeMap<K, BTreeSet<V>>,
    other: &mut BTreeMap<K, BTreeSet<V>>,
) {
    while let Some((k, mut v)) = other.pop_first() {
        match orig.get_mut(&k) {
            Some(val) => val.append(&mut v),
            None => {
                orig.insert(k, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_set_map_test() {
        let mut map1 = BTreeMap::new();
        map1.insert("foo", BTreeSet::from(["a", "b"]));
        map1.insert("bar", BTreeSet::from(["c", "d"]));
        let mut map2 = BTreeMap::new();
        map2.insert("foo", BTreeSet::from(["e", "f"]));
        map2.insert("baz", BTreeSet::from(["g", "h"]));

        append_set_map(&mut map1, &mut map2);

        assert!(map2.is_empty());

        let mut expected_result = BTreeMap::new();
        expected_result.insert("foo", BTreeSet::from(["a", "b", "e", "f"]));
        expected_result.insert("bar", BTreeSet::from(["c", "d"]));
        expected_result.insert("baz", BTreeSet::from(["g", "h"]));
        assert_eq!(map1, expected_result);
    }
}
