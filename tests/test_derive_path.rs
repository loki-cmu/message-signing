use bip39::{Language, Mnemonic};
use bitcoin::address::Address;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::CompressedPublicKey;
use bitcoin::network::Network;
use bitcoin::secp256k1::Secp256k1;

use base64::{engine::general_purpose::STANDARD, Engine};
use message_signing::bitcoin_message_sign::{sign, verify};

#[test]
fn test_derive_84_pubkey() {
    let mnemonic_words =
        "list build regret beach net symptom pilot child all hazard endless powder";
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_words).unwrap();
    let seed = mnemonic.to_seed("");

    assert_eq!(
        [
            233, 145, 112, 170, 205, 195, 105, 177, 47, 42, 24, 200, 243, 127, 116, 188, 174, 198,
            60, 133, 10, 196, 107, 206, 161, 204, 123, 67, 213, 236, 245, 220, 219, 154, 4, 14, 90,
            113, 237, 192, 29, 180, 164, 144, 75, 105, 234, 0, 150, 233, 22, 155, 237, 165, 89,
            115, 178, 200, 128, 139, 184, 95, 190, 45,
        ],
        seed
    );

    let secp = Secp256k1::new();
    let master_x_private_key = Xpriv::new_master(Network::Testnet, &seed);
    assert!(master_x_private_key.is_ok());

    let master_x_private_key = master_x_private_key.unwrap();
    let path = "m/84'/1'/0'/0/0".parse::<DerivationPath>().unwrap();

    let x_private_key = master_x_private_key.derive_priv(&secp, &path).unwrap();
    let x_private_str = x_private_key.to_string();
    let x_public_key = Xpub::from_priv(&secp, &x_private_key);
    let x_public_str = x_public_key.to_string();
    assert_eq!(
        "tprv8kMTe6rSuFZ2N49r6pahMEJSKj6F4DL3jnEmuoySkPVaxCAgD31dRwFaf2W3CBbzBL61xN2ZgNUz1y6vodzhvQRmAuq6WVFzABFjurs2GyX",
        x_private_str
    );
    assert_eq!(
        "tpubDH3VnWth3dEhFXBdzUFHkdxYtkcBDYWxK5qZCL1kAfHyngRSqRqDcRsSqBPbKTMGMh7TDibQUdwvNMynFu8iYPauSShm6m8R13LYzWDJdAR",
        x_public_str
    );
    let compressed_public_key = CompressedPublicKey(x_public_key.public_key);
    let address = Address::p2wpkh(&compressed_public_key, Network::Testnet);
    assert_eq!(
        "tb1q9g6jnlgxu6altezjplk7eyle04qnhrvgadrr65",
        address.to_string()
    );

    let message = b"test";
    let secret_bytes = x_private_key.private_key.secret_bytes();
    let signature = sign(&Secp256k1::new(), message.as_slice(), secret_bytes).unwrap();

    // dbg!(signature.serialize_compact());

    let signature_base64 = STANDARD.encode(signature.serialize_compact());

    assert_eq!(
        "W7n1F5qyfX+pa+F/nHH6wjotPjY9fV+GFu27W2Q5y4UkOyz1ckYKtbRMdOsL3JbjtOJ7L+dRKOZK4klZfzcSdA==",
        signature_base64
    );

    let result = verify(
        &Secp256k1::new(),
        message.as_slice(),
        signature.serialize_compact(),
        x_public_key.public_key.serialize(),
    );
    assert!(result.is_ok());
}
