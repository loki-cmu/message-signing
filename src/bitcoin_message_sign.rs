use crate::error::SigningError;
use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::{
    bip32::Xpriv,
    secp256k1::{
        ecdsa::{self, RecoveryId},
        Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification,
    },
    Address, CompressedPublicKey, Network,
};
use bitcoin_hashes::{sha256, Hash};
use core::str::FromStr;

/// Signs a message using the provided secret key.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `msg` - The message to be signed as a byte slice.
/// * `seckey` - The secret key as a 32-byte array.
///
/// # Returns
///
/// Returns a Result containing the ECDSA signature or an error.
pub fn sign<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: [u8; 32],
) -> Result<ecdsa::Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa(&msg, &seckey))
}

/// Verifies an ECDSA signature for a given message and public key.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `msg` - The message that was signed as a byte slice.
/// * `sig` - The ECDSA signature as a 64-byte array.
/// * `pubkey` - The public key as a 33-byte array.
///
/// # Returns
///
/// Returns a Result containing a boolean indicating whether the signature is valid or an error.
pub fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: [u8; 64],
    pubkey: [u8; 33],
) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let sig = ecdsa::Signature::from_compact(&sig)?;
    let pubkey = PublicKey::from_slice(&pubkey)?;

    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

/// Signs a message using the provided secret key and returns a recoverable signature.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `msg` - The message to be signed as a byte slice.
/// * `seckey` - The secret key as a 32-byte array.
///
/// # Returns
///
/// Returns a Result containing the ECDSA recoverable signature or an error.
pub fn sign_recoverable<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    seckey: [u8; 32],
) -> Result<ecdsa::RecoverableSignature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign_ecdsa_recoverable(&msg, &seckey))
}

/// Verifies a recoverable ECDSA signature for a given message.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `msg` - The message that was signed as a byte slice.
/// * `sig_recover` - The recoverable ECDSA signature.
///
/// # Returns
///
/// Returns a Result containing a boolean indicating whether the signature is valid or an error.
pub fn verify_recoverable<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig_recover: ecdsa::RecoverableSignature,
) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_digest_slice(msg.as_ref())?;
    let pubkey = secp.recover_ecdsa(&msg, &sig_recover)?;
    let sig = sig_recover.to_standard();
    Ok(secp.verify_ecdsa(&msg, &sig, &pubkey).is_ok())
}

/*
0 Legacy (P2PKH)
4 Nested SegWit (P2SH)
8 Native SegWit (Bech32)
 */
const SCRIPT_TYPE_INFO_P2PKH: u8 = 0;
const SCRIPT_TYPE_INFO_P2SH: u8 = 4;
const SCRIPT_TYPE_INFO_BECH32: u8 = 8;

/// Signs a message using the provided secret key in a readable format and returns the signature as a Base64-encoded string.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `msg` - The message to be signed as a string.
/// * `seckey` - The secret key in a readable format (e.g., a string representation of an extended private key).
/// * `script_type_info` - An identifier for the script type used for the address:
///   - `0` for Legacy (P2PKH)
///   - `4` for Nested SegWit (P2SH)
///   - `8` for Native SegWit
/// # Returns
///
/// Returns a Result containing the Base64-encoded ECDSA signature or an error.
pub fn sign_readable<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &str,
    seckey: &str,
    script_type_info: u8,
) -> Result<String, Error> {
    let msg = sha256::Hash::hash(msg.as_bytes());
    let msg = Message::from_digest_slice(msg.as_ref())?;

    let x_private_key = Xpriv::from_str(seckey).map_err(|_| Error::InvalidSecretKey)?;
    let sig = secp.sign_ecdsa_recoverable(&msg, &x_private_key.private_key);

    // let script_type_info: u8 = 8;
    let (recover_id, serialized_sig) = sig.serialize_compact();
    let joint_sig = combine_signature_bytes(recover_id.to_i32(), script_type_info, serialized_sig);
    Ok(STANDARD.encode(&joint_sig))
}

fn combine_signature_bytes(recid: i32, script_type_info: u8, serialized_sig: [u8; 64]) -> Vec<u8> {
    // signature = bytes([recid + script_type_info]) + signature[1:]

    // Convert recid to a byte array (4 bytes for i32)
    let recid_bytes: [u8; 4] = recid.to_le_bytes(); // or to_be_bytes() depending on endianness

    // 4 bytes for recid, 1 byte for script_type_info, 64 bytes for serialized_sig
    let mut merged: Vec<u8> = Vec::with_capacity(4 + 1 + 64);

    merged.extend_from_slice(recid_bytes.as_slice());
    merged.push(script_type_info);
    merged.extend_from_slice(&serialized_sig);

    merged
}

fn split_signature_bytes(merged: &[u8]) -> Result<(i32, u8, [u8; 64]), &'static str> {
    // Check if the merged slice has the correct length
    if merged.len() != 69 {
        // 4 bytes for recid, 1 byte for script_type_info, 64 bytes for serialized_sig
        return Err("Invalid merged signature length");
    }

    // Extract recid (first 4 bytes)
    let recid_bytes = &merged[0..4];
    let recid = i32::from_le_bytes(
        recid_bytes
            .try_into()
            .map_err(|_| "Failed to convert recid bytes")?,
    );

    // Extract script_type_info (next byte)
    let script_type_info = merged[4];

    // Extract serialized_sig (last 64 bytes)
    let serialized_sig = merged[5..69]
        .try_into()
        .map_err(|_| "Failed to convert serialized_sig bytes")?;

    Ok((recid, script_type_info, serialized_sig))
}

/// Verifies a signature for a given message and address in a readable format.
///
/// # Arguments
///
/// * `secp` - A reference to the Secp256k1 context.
/// * `address` - The address to derive the public key from.
/// * `msg` - The message that was signed as a string.
/// * `sig` - The signature as a Base64-encoded string.
///
/// # Returns
///
/// Returns a Result containing a boolean indicating whether the signature is valid or an error.
pub fn verify_readable<C: Verification>(
    secp: &Secp256k1<C>,
    address: &str,
    msg: &str,
    sig: &str,
    network: &str,
) -> Result<bool, SigningError> {
    // TODO: Validate the address format

    let network = Network::from_str(network).map_err(|_| SigningError::InvalidNetwork)?;

    let sig_bytes_full = STANDARD
        .decode(sig)
        .map_err(SigningError::Base64DecodeError)?;

    let (recover_id, script_type_info, sig_bytes) = split_signature_bytes(&sig_bytes_full)
        .map_err(|err_str| SigningError::InvalidSignatureLength(err_str.to_string()))?;
    let sig_recover = ecdsa::RecoverableSignature::from_compact(
        &sig_bytes,
        RecoveryId::from_i32(recover_id).unwrap(),
    )
    .map_err(SigningError::InvalidSignature)?;

    // Hash the message
    let msg_hash = sha256::Hash::hash(msg.as_bytes());
    let msg = Message::from_digest_slice(msg_hash.as_ref())?;

    let public_key = secp.recover_ecdsa(&msg, &sig_recover)?;

    let expected_address = public_key_to_address(&public_key, network, script_type_info);
    if address != expected_address {
        dbg!(expected_address);
        return Err(SigningError::AddressDoesNotMatch);
    }

    // Verify the signature
    let sig = sig_recover.to_standard();
    Ok(secp.verify_ecdsa(&msg, &sig, &public_key).is_ok())
}

fn public_key_to_address(public_key: &PublicKey, network: Network, script_type_info: u8) -> String {
    let compressed_public_key = CompressedPublicKey(*public_key);
    match script_type_info {
        SCRIPT_TYPE_INFO_P2PKH => Address::p2pkh(compressed_public_key, network).to_string(),
        SCRIPT_TYPE_INFO_P2SH => Address::p2shwpkh(&compressed_public_key, network).to_string(),
        SCRIPT_TYPE_INFO_BECH32 => Address::p2wpkh(&compressed_public_key, network).to_string(),
        _ => {
            panic!("Invalid script type info");
        }
    }
}

/// Determines the script type information based on the provided address.
///
/// # Arguments
///
/// * `address` - The address to be evaluated.
///
/// # Returns
///
/// script_type_info as u8 or an error if the address format is invalid.
pub fn address_to_script_type_info(address: &str) -> Result<u8, SigningError> {
    if address.starts_with("1") {
        Ok(SCRIPT_TYPE_INFO_P2PKH)
    } else if address.starts_with("bc1") || address.starts_with("tb1") {
        Ok(SCRIPT_TYPE_INFO_BECH32)
    } else if address.starts_with("3") {
        Ok(SCRIPT_TYPE_INFO_P2SH)
    } else {
        Err(SigningError::InvalidAddressFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn test_sign_and_verify() {
        let secp = Secp256k1::new();

        let seckey = [
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ];
        let pubkey = [
            2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91,
            141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
        ];
        let msg = b"This is some message";

        let signature = sign(&secp, msg, seckey).unwrap();

        let serialize_sig = signature.serialize_compact();

        assert!(verify(&secp, msg, serialize_sig, pubkey).unwrap());
    }

    #[test]
    fn test_invalid_signature() {
        let secp = Secp256k1::new();

        let seckey = [
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ];
        let pubkey = [
            2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91,
            141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
        ];
        let msg = b"This is some message";

        let signature = sign(&secp, msg, seckey).unwrap();
        let serialize_sig = signature.serialize_compact();

        // Modify the message
        let invalid_msg = b"Invalid message";

        // Verify the signature with the modified message
        let is_valid =
            verify(&secp, invalid_msg, serialize_sig, pubkey).expect("Failed to verify signature");

        assert!(!is_valid, "The signature should be invalid");
    }

    #[test]
    fn test_sign_recoverable_and_verify() {
        let secp = Secp256k1::new();

        let seckey = [
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ];
        let _pubkey = [
            2, 29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231, 245, 41, 91,
            141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
        ];
        let msg = b"This is some message";

        let signature = sign_recoverable(&secp, msg, seckey).unwrap();

        assert!(verify_recoverable(&secp, msg, signature).unwrap());
    }

    #[test]
    fn test_readable_private_key_sign() {
        let msg = "test";
        let private_key = "tprv8kMTe6rSuFZ2N49r6pahMEJSKj6F4DL3jnEmuoySkPVaxCAgD31dRwFaf2W3CBbzBL61xN2ZgNUz1y6vodzhvQRmAuq6WVFzABFjurs2GyX";
        let signature =
            sign_readable(&Secp256k1::new(), msg, private_key, SCRIPT_TYPE_INFO_BECH32).unwrap();

        assert_eq!(
            "AQAAAAhbufUXmrJ9f6lr4X+ccfrCOi0+Nj19X4YW7btbZDnLhSQ7LPVyRgq1tEx06wvcluO04nsv51Eo5kriSVl/NxJ0",
            signature
        );
    }

    #[test]
    fn test_verify_readable_address_testnet3() {
        let msg = "test";
        let signature = "AQAAAAhbufUXmrJ9f6lr4X+ccfrCOi0+Nj19X4YW7btbZDnLhSQ7LPVyRgq1tEx06wvcluO04nsv51Eo5kriSVl/NxJ0";

        let address = "tb1q9g6jnlgxu6altezjplk7eyle04qnhrvgadrr65";
        let network = "testnet";
        let result = verify_readable(&Secp256k1::new(), address, msg, signature, network);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_readable_address_mainnet() {
        let msg = "test";
        let signature = "AQAAAAhbufUXmrJ9f6lr4X+ccfrCOi0+Nj19X4YW7btbZDnLhSQ7LPVyRgq1tEx06wvcluO04nsv51Eo5kriSVl/NxJ0";

        let address = "bc1q9g6jnlgxu6altezjplk7eyle04qnhrvghtcsp8";
        let network = "bitcoin";
        let result = verify_readable(&Secp256k1::new(), address, msg, signature, network);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_readable_address_fail() {
        let msg = "test_modify";
        let signature = "AQAAAAhbufUXmrJ9f6lr4X+ccfrCOi0+Nj19X4YW7btbZDnLhSQ7LPVyRgq1tEx06wvcluO04nsv51Eo5kriSVl/NxJ0";

        let address = "tb1q9g6jnlgxu6altezjplk7eyle04qnhrvgadrr65";
        let network = "Testnet3";
        let result = verify_readable(&Secp256k1::new(), address, msg, signature, network);
        assert!(result.is_err());
    }

    #[test]
    fn test_readable_private_key_sign_and_verify_p2sh() {
        let msg = "test";
        let private_key = "tprv8kMTe6rSuFZ2N49r6pahMEJSKj6F4DL3jnEmuoySkPVaxCAgD31dRwFaf2W3CBbzBL61xN2ZgNUz1y6vodzhvQRmAuq6WVFzABFjurs2GyX";
        let signature =
            sign_readable(&Secp256k1::new(), msg, private_key, SCRIPT_TYPE_INFO_P2SH).unwrap();

        // address should start with 3
        let address = "367gqAgkjNCpMybiZbo3B9pGMJmULqqhMT";
        let network = "bitcoin";
        let result = verify_readable(&Secp256k1::new(), address, msg, &signature, network);
        assert!(result.is_ok());
    }

    #[test]
    fn test_readable_private_key_sign_and_verify_p2pkh() {
        let msg = "test";
        let private_key = "tprv8kMTe6rSuFZ2N49r6pahMEJSKj6F4DL3jnEmuoySkPVaxCAgD31dRwFaf2W3CBbzBL61xN2ZgNUz1y6vodzhvQRmAuq6WVFzABFjurs2GyX";
        let signature =
            sign_readable(&Secp256k1::new(), msg, private_key, SCRIPT_TYPE_INFO_P2PKH).unwrap();

        // address should start with 1
        let address = "14rB4xYBqBQ5JRvZQMF92jcTBR82JpJ5Yu";
        let network = "bitcoin";
        let result = verify_readable(&Secp256k1::new(), address, msg, &signature, network);
        assert!(result.is_ok());
    }

    #[test]
    fn test_address_to_script_type_info() {
        let address_str = "14rB4xYBqBQ5JRvZQMF92jcTBR82JpJ5Yu";
        assert_eq!(
            SCRIPT_TYPE_INFO_P2PKH,
            address_to_script_type_info(address_str).unwrap()
        );

        let address_str = "367gqAgkjNCpMybiZbo3B9pGMJmULqqhMT";
        assert_eq!(
            SCRIPT_TYPE_INFO_P2SH,
            address_to_script_type_info(address_str).unwrap()
        );

        let address_str = "tb1q9g6jnlgxu6altezjplk7eyle04qnhrvgadrr65";
        assert_eq!(
            SCRIPT_TYPE_INFO_BECH32,
            address_to_script_type_info(address_str).unwrap()
        );

        let address_str = "bc1q9g6jnlgxu6altezjplk7eyle04qnhrvghtcsp8";
        assert_eq!(
            SCRIPT_TYPE_INFO_BECH32,
            address_to_script_type_info(address_str).unwrap()
        );
    }
}
