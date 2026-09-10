//! A minimal interior-mutable name-prefix table.
//!
//! Replaces `ndn_store::NameTrie` so the coding **codec core carries no forwarder-stack
//! dependency** (see crates/ndn-radio-hal/PORTING.md). The only user is the coding-policy
//! table, which holds a handful of prefixes, so a linear longest-prefix-match is more than
//! adequate and keeps this dependency-free.

use std::sync::Mutex;

use ndn_foundation_types::Name;

/// One name-keyed table with exact and longest-prefix-match lookup. Interior-mutable
/// (`insert`/`remove` take `&self`) to match the call sites that hold it behind `&`.
pub(crate) struct NameTrie<V> {
    entries: Mutex<Vec<(Name, V)>>,
}

impl<V> Default for NameTrie<V> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }
}

impl<V: Clone> NameTrie<V> {
    /// Insert or replace the value at an exact prefix.
    pub(crate) fn insert(&self, prefix: &Name, value: V) {
        let mut g = self.entries.lock().unwrap();
        if let Some(e) = g.iter_mut().find(|(n, _)| n == prefix) {
            e.1 = value;
        } else {
            g.push((prefix.clone(), value));
        }
    }

    /// Remove the entry at an exact prefix, if any.
    pub(crate) fn remove(&self, prefix: &Name) {
        self.entries.lock().unwrap().retain(|(n, _)| n != prefix);
    }

    /// Exact-match lookup.
    pub(crate) fn get(&self, name: &Name) -> Option<V> {
        let g = self.entries.lock().unwrap();
        g.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
    }

    /// Longest-prefix match: the entry whose prefix covers `name` with the most components.
    pub(crate) fn lpm(&self, name: &Name) -> Option<V> {
        let g = self.entries.lock().unwrap();
        g.iter()
            .filter(|(n, _)| name.has_prefix(n))
            .max_by_key(|(n, _)| n.len())
            .map(|(_, v)| v.clone())
    }

    /// All (prefix, value) pairs, in no particular order.
    pub(crate) fn dump(&self) -> Vec<(Name, V)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect()
    }
}
