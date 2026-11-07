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
