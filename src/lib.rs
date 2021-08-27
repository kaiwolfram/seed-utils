use std::str::FromStr;

use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::Network;
use bip85::{
    bip39::Mnemonic,
    bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
};
use rand::{thread_rng, Rng};

const ENTROPY_24_WORDS_BYTES: usize = 32;
const ENTROPY_18_WORDS_BYTES: usize = 24;
const ENTROPY_12_WORDS_BYTES: usize = 16;

pub fn derive_child_seeds<S>(
    seed: S,
    (start, mut end): (u32, u32),
    word_count: u8,
) -> Result<Vec<(u32, Mnemonic)>, String>
where
    S: AsRef<str>,
{
    if end < start {
        end = start;
    }
    let parsed_seed = parse_seed(seed)?;
    let entropy = parsed_seed.to_entropy();
    let xprv =
        ExtendedPrivKey::new_master(Network::Bitcoin, &entropy).map_err(|e| e.to_string())?;
    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();

    let mut result: Vec<(u32, Mnemonic)> = Vec::with_capacity(end as usize - start as usize);

    for i in start..end {
        let mnemonic =
            bip85::to_mnemonic(&secp, &xprv, word_count as u32, i).map_err(|e| e.to_string())?;
        result.push((i, mnemonic));
    }

    Ok(result)
}

pub fn extend_seed<S>(seed: S, word_count: u8) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() >= word_count as usize {
        return Err("Seed is already longer or the same as the desired length".to_string());
    }
    let mut entropy = parsed_seed.to_entropy();
    let mut rand = thread_rng();
    let new_entropy_count = match word_count {
        18 => ENTROPY_18_WORDS_BYTES - entropy.len(),
        24 => ENTROPY_24_WORDS_BYTES - entropy.len(),
        _ => return Err(format!("{} is not a valid word count", word_count)),
    };

    let more_entropy = std::iter::repeat(())
        .map(|()| rand.gen::<u8>())
        .take(new_entropy_count);
    entropy.extend(more_entropy);

    Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())
}

pub fn truncate_seed<S>(seed: S, word_count: u8) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() <= word_count as usize {
        return Ok(parsed_seed);
    }

    let mut entropy = parsed_seed.to_entropy();
    match word_count {
        12 => entropy.truncate(ENTROPY_12_WORDS_BYTES),
        18 => entropy.truncate(ENTROPY_18_WORDS_BYTES),
        _ => {
            return Err(format!(
                "Truncation for {} word seeds is not implemented",
                parsed_seed.word_count()
            ))
        }
    }

    Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())
}

pub fn xor_seeds(seeds: &[&str]) -> Result<seed_xor::Mnemonic, String> {
    let mut mnemonics: Vec<seed_xor::Mnemonic> = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let mnemonic = seed_xor::Mnemonic::from_str(seed).map_err(|e| e.to_string())?;
        mnemonics.push(mnemonic);
    }

    mnemonics
        .into_iter()
        .reduce(|a, b| a ^ b)
        .ok_or_else(|| "No seeds to xor".to_string())
}

pub fn derive_xpubs_from_seed<S>(
    seed: S,
    (start, end): (u32, u32),
) -> Result<Vec<(u32, ExtendedPubKey)>, String>
where
    S: AsRef<str>,
{
    let xprvs = derive_xprvs_from_seed(seed, (start, end))?;
    let secp = Secp256k1::new();
    let xpubs = xprvs
        .iter()
        .map(|(i, xprv)| (*i, ExtendedPubKey::from_private(&secp, xprv)))
        .collect();

    Ok(xpubs)
}

pub fn derive_xprvs_from_seed<S>(
    seed: S,
    (start, mut end): (u32, u32),
) -> Result<Vec<(u32, ExtendedPrivKey)>, String>
where
    S: AsRef<str>,
{
    if end < start {
        end = start;
    }
    let secp = Secp256k1::new();
    let master = derive_master_xprv(seed)?;
    let path = DerivationPath::from_str("m/84'/0'").map_err(|e| e.to_string())?;
    let mut result: Vec<(u32, ExtendedPrivKey)> = Vec::with_capacity(end as usize - start as usize);

    for i in start..end {
        let child = ChildNumber::from_normal_idx(i).map_err(|e| e.to_string())?;
        let child_path = path.child(child);
        let derived = master
            .derive_priv(&secp, &child_path)
            .map_err(|e| e.to_string())?;
        result.push((i, derived));
    }

    Ok(result)
}

pub fn derive_master_xpub<S>(seed: S) -> Result<ExtendedPubKey, String>
where
    S: AsRef<str>,
{
    let xprv = derive_master_xprv(seed)?;
    let secp = Secp256k1::new();

    Ok(ExtendedPubKey::from_private(&secp, &xprv))
}

pub fn derive_master_xprv<S>(seed: S) -> Result<ExtendedPrivKey, String>
where
    S: AsRef<str>,
{
    let parsed_seed = parse_seed(seed)?;
    let entropy = parsed_seed.to_entropy();
    let xprv =
        ExtendedPrivKey::new_master(Network::Bitcoin, &entropy).map_err(|e| e.to_string())?;

    Ok(xprv)
}

fn parse_seed<S>(seed: S) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    Mnemonic::from_str(seed.as_ref()).map_err(|e| e.to_string())
}
