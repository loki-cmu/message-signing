mod kms;

use crate::kms::{create_address_tron, generate_xprv, generate_xpub, ChainType};

#[test]
fn test_create_eth_address() {
    let mnemonic_words =
        "list build regret beach net symptom pilot child all hazard endless powder";

    let child_path = "m/44'/195'/0'/0";
    let _xprv = generate_xprv(mnemonic_words, child_path).expect("Failed to generate xprv");
    let xpub = generate_xpub(mnemonic_words, child_path).expect("Failed to generate xpub");

    let chain_type: u32 = ChainType::Tron as u32;
    assert_eq!(chain_type, 195);

    let address = create_address_tron(&xpub, 0).unwrap();
    assert_eq!("TKdAp53XCQfqraaBQ9aZeGtG5DqEMqozoz", address);
}
