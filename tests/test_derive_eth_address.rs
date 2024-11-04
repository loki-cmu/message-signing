mod kms;

use crate::kms::{create_address_eth, generate_xprv, generate_xpub, ChainType};

#[test]
fn test_create_eth_address() {
    let mnemonic_words =
        "list build regret beach net symptom pilot child all hazard endless powder";

    let child_path = "m/44'/60'/0'/0";
    let _xprv = generate_xprv(mnemonic_words, child_path).expect("Failed to generate xprv");
    let xpub = generate_xpub(mnemonic_words, child_path).expect("Failed to generate xpub");

    let chain_type: u32 = ChainType::Ethereum as u32;
    assert_eq!(chain_type, 60);

    let address = create_address_eth(&xpub, 0).unwrap();
    assert_eq!("0xfecc791a81cdc179c4d8996eab73dbe22a255fdf", address);
}
