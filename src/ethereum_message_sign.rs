use crate::error::SigningError;
use base64::{engine::general_purpose::STANDARD, Engine};
use bip32::XPrv;
use core::str::FromStr;
use secp256k1::{
    ecdsa::{self, RecoveryId},
    Error, Message, Secp256k1, SecretKey, Signing, Verification,
};
use sha3::{Digest, Keccak256};

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
    let mut hasher = Keccak256::new();
    let signed_message_header = b"\x19Ethereum Signed Message:\n";

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
    let result = hasher.finalize();

    // 提取最后20个字节并生成以太坊地址
    let eth_address = format!("0x{}", hex::encode(&result[12..]));

    eth_address
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
            "AQAAABJMnqfJp5MKCnW+aAPCvXVQRkX832TbUBseVX+0uvmkD9dtGUhgDY3oRKUpzTCTQ+8h+ZVNKhuisMTB4o/OQM8=",
            signature
        );
    }

    #[test]
    fn test_verify_readable_address() {
        let msg = "test";
        let signature = "AQAAAAhbufUXmrJ9f6lr4X+ccfrCOi0+Nj19X4YW7btbZDnLhSQ7LPVyRgq1tEx06wvcluO04nsv51Eo5kriSVl/NxJ0";
        let address = "tb1q9g6jnlgxu6altezjplk7eyle04qnhrvgadrr65";

        let result = verify_readable(&Secp256k1::new(), address, msg, signature);
        assert!(result.is_err());
    }
}
