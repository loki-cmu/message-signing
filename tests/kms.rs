use anyhow::Result;
use base58::ToBase58;
use bip32::{secp256k1::sha2::Sha256, ChildNumber, Prefix, XPrv, XPub};
use bip39::{Language, Mnemonic};
use core::{convert::TryFrom, fmt::Display, str::FromStr};
use sha3::{Digest, Keccak256};
#[derive(Debug, thiserror::Error)]
pub enum ChainTypeError {
    UnknownType(u32),
}

impl Display for ChainTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownType(code) => write!(f, "unknown chain type :{}", code),
        }
    }
}

pub enum ChainType {
    Bitcoin = 0,
    BitcoinTestnet = 1,
    Ethereum = 60,
    Tron = 195,
    TronTestnet = 198,
}

impl TryFrom<u32> for ChainType {
    type Error = ChainTypeError;
    fn try_from(type_code: u32) -> Result<Self, Self::Error> {
        match type_code {
            0 => Ok(Self::Bitcoin),
            1 => Ok(Self::BitcoinTestnet),
            60 => Ok(Self::Ethereum),
            195 => Ok(Self::Tron),
            198 => Ok(Self::TronTestnet),
            _ => Err(ChainTypeError::UnknownType(type_code)),
        }
    }
}

pub fn generate_seed(mnemonic: &str) -> String {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
    let seed = mnemonic.to_seed("");
    hex::encode(seed)
}

pub fn generate_xprv(mnemonic: &str, child_path: &str) -> Result<String> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
    let seed = mnemonic.to_seed("");

    let _root_xprv = XPrv::new(seed)?;

    let child_xprv = XPrv::derive_from_path(seed, &child_path.parse()?)?;
    let child_xprv_str = child_xprv.to_string(Prefix::XPRV);

    Ok(child_xprv_str.to_string())
}

pub fn generate_xpub(mnemonic: &str, child_path: &str) -> Result<String> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
    let seed = mnemonic.to_seed("");

    // let _root_xprv = XPrv::new(&seed)?;
    let child_xprv = XPrv::derive_from_path(seed, &child_path.parse()?)?;
    let child_xpub = child_xprv.public_key();

    Ok(child_xpub.to_string(Prefix::XPUB))
}

#[allow(dead_code)]
pub fn create_address_eth(xpub: &str, index: u32) -> Result<String> {
    let xpub = XPub::from_str(xpub)?;
    let public_key = xpub.derive_child(ChildNumber(index))?;
    let public_bytes = public_key.to_bytes();

    // Keccak-256哈希
    let mut hasher = Keccak256::default();
    hasher.update(&public_bytes[1..]); // 跳过第一个字节（前缀）
    let result = hasher.finalize();

    // 提取最后20个字节并生成以太坊地址
    let eth_address = format!("0x{}", hex::encode(&result[12..]));

    Ok(eth_address)
}

#[allow(dead_code)]
pub fn create_address_tron(xpub: &str, index: u32) -> Result<String> {
    let xpub = XPub::from_str(xpub)?;
    let public_key = xpub.derive_child(ChildNumber(index))?;
    let public_bytes = public_key.to_bytes();

    // Keccak-256哈希
    let mut hasher = Keccak256::default();
    hasher.update(&public_bytes[1..]); // 跳过第一个字节（前缀）
    let digest = hasher.finalize();

    let mut raw = [0x41; 21];
    raw[1..21].copy_from_slice(&digest[digest.len() - 20..]);

    let tron_address = b58encode_check(raw);
    Ok(tron_address)
}

/// Base58check encode.
#[allow(dead_code)]
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

#[test]
fn test_generate_seed() {
    let mnemonic = "list build regret beach net symptom pilot child all hazard endless powder";
    let seed = generate_seed(mnemonic);
    assert_eq!(
        "e99170aacdc369b12f2a18c8f37f74bcaec63c850ac46bcea1cc7b43d5ecf5dcdb9a040e5a71edc01db4a4904b69ea0096e9169beda55973b2c8808bb85fbe2d",
        seed
    );
}

#[test]
fn test_generate_master_xpub() {
    let mnemonic_words =
        "list build regret beach net symptom pilot child all hazard endless powder";

    let child_path = "m/44'/60'/0'/0";
    let xprv = generate_xprv(mnemonic_words, child_path).expect("Failed to generate xprv");
    let xpub = generate_xpub(mnemonic_words, child_path).expect("Failed to generate xpub");

    assert_eq!(
        xprv,
        "xprvA1ep9yKTHnR6YtC6XvW3KFwUS9Z69kRJswpvR8xBEnUC6uqFARc6suomTD6oE7RmmQZowr5iP9e6Xj2g8X7BVWvrCuATeqjYfc5bVjdGWh2"
    );
    assert_eq!(
        xpub,
        "xpub6EeAZUrM89yPmNGZdx33gPtCzBPaZD9AFAkXDXMno81AyiAPhxvMRi8FJWzjz37Qb1ia7wqXGD2n4NbrLaBS1sRAU3TfJyGN3FWfbMoU7Sa"
    );
}
