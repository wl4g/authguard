use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ldap3::SearchEntry;

#[derive(Clone)]
pub(super) struct LdapSearchRequest {
    pub(super) base_dn: String,
    pub(super) filter: String,
    pub(super) attributes: Vec<String>,
    pub(super) page_size: u32,
    pub(super) cookie: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LdapSearchPage {
    pub(super) entries: Vec<LdapEntry>,
    pub(super) next_cookie: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LdapEntry {
    pub(super) dn: String,
    pub(super) attributes: BTreeMap<String, Vec<String>>,
}

impl LdapEntry {
    pub(super) fn from_search_entry(entry: SearchEntry) -> Self {
        let mut attributes = BTreeMap::<String, Vec<String>>::new();
        for (name, values) in entry.attrs {
            attributes.entry(name.to_ascii_lowercase()).or_default().extend(values);
        }
        for (name, values) in entry.bin_attrs {
            attributes
                .entry(name.to_ascii_lowercase())
                .or_default()
                .extend(values.into_iter().map(|value| URL_SAFE_NO_PAD.encode(value)));
        }
        Self { dn: entry.dn, attributes }
    }

    pub(super) fn first(&self, attribute: &str) -> Option<&str> {
        self.attributes
            .get(&attribute.to_ascii_lowercase())
            .and_then(|values| values.first())
            .map(String::as_str)
    }
}
