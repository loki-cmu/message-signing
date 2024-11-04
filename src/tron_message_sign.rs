use crate::error::SigningError;
use base58::ToBase58;
use base64::{engine::general_purpose::STANDARD, Engine};
use bip32::{secp256k1::sha2::Sha256, XPrv};
use core::str::FromStr;
use secp256k1::{
    ecdsa::{self, RecoveryId},
    Error, Message, Secp256k1, SecretKey, Signing, Verification,
};
use sha3::{Digest, Keccak256, Sha3_256};

pub fn sign_readable<C: Signing>(
    secp: &Secp256k1<C>,
    msg: &str,
    seckey: &str,
) -> Result<String, Error> {
    let msg = message_digest(msg.as_bytes());
    let msg = Message::from_digest_slice(msg.as_ref())?;

    let xprv = XPrv::from_str(seckey).map_err(|_| Error::InvalidSecretKey)?;
    let private_key = xprv.private_key();
    let secret_key = SecretKey::from_slice(private_key.to_bytes().as_slice())?;
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let (recover_id, serialized_sig) = sig.serialize_compact();
    let joint_sig = combine_signature_bytes(recover_id.to_i32(), serialized_sig);
    Ok(STANDARD.encode(&joint_sig))
}

fn message_digest(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    let signed_message_header = b"\x19TRON Signed Message:\n";

    hasher.update(signed_message_header);
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);

    hasher.finalize().to_vec()
}

fn combine_signature_bytes(recid: i32, serialized_sig: [u8; 64]) -> Vec<u8> {
    // signature = bytes([recid]) + signature[1:]

    // Convert recid to a byte array (4 bytes for i32)
    let recid_bytes: [u8; 4] = recid.to_le_bytes(); // or to_be_bytes() depending on endianness

    // 4 bytes for recid, 1 byte for script_type_info, 64 bytes for serialized_sig
    let mut merged: Vec<u8> = Vec::with_capacity(4 + 64);

    merged.extend_from_slice(recid_bytes.as_slice());
    merged.extend_from_slice(&serialized_sig);

    merged
}

fn split_signature_bytes(merged: &[u8]) -> Result<(i32, [u8; 64]), &'static str> {
    // Check if the merged slice has the correct length
    if merged.len() != 68 {
        // 4 bytes for recid, 64 bytes for serialized_sig
        return Err("Invalid merged signature length");
    }

    // Extract recid (first 4 bytes)
    let recid_bytes = &merged[0..4];
    let recid = i32::from_le_bytes(
        recid_bytes
            .try_into()
            .map_err(|_| "Failed to convert recid bytes")?,
    );

    // Extract serialized_sig (last 64 bytes)
    let serialized_sig = merged[4..68]
        .try_into()
        .map_err(|_| "Failed to convert serialized_sig bytes")?;

    Ok((recid, serialized_sig))
}

pub fn verify_readable<C: Verification>(
    secp: &Secp256k1<C>,
    address: &str,
    msg: &str,
    sig: &str,
) -> Result<bool, SigningError> {
    // TODO: Validate the address format

    let sig_bytes_full = STANDARD
        .decode(sig)
        .map_err(SigningError::Base64DecodeError)?;

    let (recover_id, sig_bytes) = split_signature_bytes(&sig_bytes_full)
        .map_err(|err_str| SigningError::InvalidSignatureLength(err_str.to_string()))?;
    let sig_recover = ecdsa::RecoverableSignature::from_compact(
        &sig_bytes,
        RecoveryId::from_i32(recover_id).unwrap(),
    )
    .map_err(SigningError::InvalidSignature)?;

    // Hash the message
    let msg = message_digest(msg.as_bytes());
    let msg = Message::from_digest_slice(msg.as_ref())?;

    let public_key = secp.recover_ecdsa(&msg, &sig_recover)?;

    let expected_address = public_key_to_address(&public_key);
    if address != expected_address {
        return Err(SigningError::AddressDoesNotMatch);
    }

    // Verify the signature
    let sig = sig_recover.to_standard();
    Ok(secp.verify_ecdsa(&msg, &sig, &public_key).is_ok())
}

fn public_key_to_address(public_key: &secp256k1::PublicKey) -> String {
    let public_bytes = public_key.serialize();

    // Keccak-256哈希
    let mut hasher = Keccak256::default();
    hasher.update(&public_bytes.as_slice()[1..]); // 跳过第一个字节（前缀）
    let digest = hasher.finalize();

    let mut raw = [0x41; 21];
    raw[1..21].copy_from_slice(&digest[digest.len() - 20..]);

    b58encode_check(raw)
}

pub fn b58encode_check<T: AsRef<[u8]>>(raw: T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_ref());
    let digest1 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(digest1);
    let digest = hasher.finalize();

    let mut raw = raw.as_ref().to_owned();
    raw.extend(&digest[..4]);
    raw.to_base58()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_readable_private_key_sign() {
        let msg = "test";
        let private_key = "tprv8kMTe6rSuFZ2N49r6pahMEJSKj6F4DL3jnEmuoySkPVaxCAgD31dRwFaf2W3CBbzBL61xN2ZgNUz1y6vodzhvQRmAuq6WVFzABFjurs2GyX";
        let signature = sign_readable(&Secp256k1::new(), msg, private_key).unwrap();

        assert_eq!(
            "AQAAAJCMwEKSnGfCMcyMAwuituDQ5d1QPf3hgNNRNFDg/NsbOJyb63E1VhkkJZ5weuFUt61qgAIMjp4FIf+Tfigxx2U=",
            signature
        );
    }

    #[test]
    fn test_verify_readable_address() {
        let msg = "test";
        let signature = "AQAAAJCMwEKSnGfCMcyMAwuituDQ5d1QPf3hgNNRNFDg/NsbOJyb63E1VhkkJZ5weuFUt61qgAIMjp4FIf+Tfigxx2U=";
        let address = "TKdAp53XCQfqraaBQ9aZeGtG5DqEMqozoz";

        let result = verify_readable(&Secp256k1::new(), address, msg, signature);
        assert!(result.is_err());
    }
}
