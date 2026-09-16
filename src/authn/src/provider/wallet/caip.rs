use super::WalletProviderError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CaipAccount {
    pub namespace: String,
    pub reference: String,
    pub address: String,
}

// https://docs.reown.com/appkit/react/core/siwx
// https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md
impl CaipAccount {
    pub(super) fn parse(value: &str) -> Result<Self, WalletProviderError> {
        let mut components = value.split(':');
        let namespace = components.next().unwrap_or_default();
        let reference = components.next().unwrap_or_default();
        let address = components.next().unwrap_or_default();
        if components.next().is_some()
            || namespace.is_empty()
            || reference.is_empty()
            || address.is_empty()
            || !(3..=8).contains(&namespace.len())
            || reference.len() > 32
            || address.len() > 128
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !reference.bytes().all(caip_component)
            || !address.bytes().all(caip_address)
        {
            return Err(WalletProviderError::InvalidAccount);
        }
        Ok(Self {
            namespace: namespace.to_string(),
            reference: reference.to_string(),
            address: address.to_string(),
        })
    }

    pub(super) fn canonical(&self) -> String {
        format!("{}:{}:{}", self.namespace, self.reference, self.address)
    }
}

fn caip_component(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn caip_address(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'%')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_multichain_accounts_without_losing_chain() {
        for account in [
            "eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "solana:mainnet:GwAF45zjfyGzUbd3i3hXxzGeuchzEZXwpRYHZM5912F1",
            "bip122:000000000019d6689c085ae165831e93:1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        ] {
            assert_eq!(CaipAccount::parse(account).expect("CAIP-10").canonical(), account);
        }
        assert!(CaipAccount::parse("0xdeadbeef").is_err());
        assert!(CaipAccount::parse("ev:1:address").is_err());
        assert!(CaipAccount::parse(&format!("eip155:1:{}", "a".repeat(129))).is_err());
    }
}
