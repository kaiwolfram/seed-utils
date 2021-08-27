use std::str::FromStr;

use bip85::bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use rand::{thread_rng, Rng};

const MAX_ENTROPY_BYTES: usize = 32;
const MIN_ENTROPY_BYTES: usize = 16;

pub fn derive_child_seed<S>(seed: S, index: u32, word_count: u32) -> String
where
    S: AsRef<str>,
{
    let parsed_seed = bip85::bip39::Mnemonic::from_str(seed.as_ref()).unwrap();
    let entropy = parsed_seed.to_entropy();
    let xprv = bip85::bitcoin::util::bip32::ExtendedPrivKey::new_master(
        bip85::bitcoin::Network::Bitcoin,
        &entropy,
    )
    .unwrap();

    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();
    let derived = bip85::to_mnemonic(&secp, &xprv, word_count, index).unwrap();

    derived.to_string()
}

pub fn extend_seed<S>(seed: S) -> Vec<String>
where
    S: AsRef<str>,
{
    let parsed_seed = bip85::bip39::Mnemonic::from_str(seed.as_ref()).unwrap();
    let mut entropy = parsed_seed.to_entropy();

    if entropy.len() < MAX_ENTROPY_BYTES {
        let mut rand = thread_rng();
        let more_entropy = std::iter::repeat(())
            .map(|()| rand.gen::<u8>())
            .take(MAX_ENTROPY_BYTES - entropy.len());
        entropy.extend(more_entropy);
    }
    let extended_seed = bip85::bip39::Mnemonic::from_entropy(&entropy).unwrap();

    let mut result: Vec<String> = Vec::new();
    result.push(extended_seed.to_string());

    result
}

pub fn truncate_seed<S>(seed: S) -> Vec<String>
where
    S: AsRef<str>,
{
    let parsed_seed = bip85::bip39::Mnemonic::from_str(seed.as_ref()).unwrap();
    let mut entropy = parsed_seed.to_entropy();
    entropy.truncate(MIN_ENTROPY_BYTES);

    let truncated_seed = bip85::bip39::Mnemonic::from_entropy(&entropy).unwrap();

    let mut result: Vec<String> = Vec::new();
    result.push(truncated_seed.to_string());

    result
}

pub fn xor_seeds(seeds: &[&str]) -> String {
    seeds
        .iter()
        .map(|seed| seed_xor::Mnemonic::from_str(seed).unwrap())
        .reduce(|a, b| a ^ b)
        .unwrap()
        .to_string()
}

pub fn derive_xpubs_from_seed<S>(seed: S, index_range: (u32, u32)) -> Vec<String>
where
    S: AsRef<str>,
{
    let parsed_seed = bip85::bip39::Mnemonic::from_str(seed.as_ref()).unwrap();
    let entropy = parsed_seed.to_entropy();
    let xprv = bip85::bitcoin::util::bip32::ExtendedPrivKey::new_master(
        bip85::bitcoin::Network::Bitcoin,
        &entropy,
    )
    .unwrap();

    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();
    let path = DerivationPath::from_str("m/84'/0'")
        .unwrap()
        .child(ChildNumber::from_normal_idx(index_range.0).unwrap());
    let xpub = ExtendedPubKey::from_private(&secp, &xprv);
    let derived = xpub.derive_pub(&secp, &path).unwrap();

    let mut result: Vec<String> = Vec::new();
    result.push(derived.to_string());

    result
}
