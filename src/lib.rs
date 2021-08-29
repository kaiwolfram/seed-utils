use std::str::FromStr;

use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::Network;
use bip85::{
    bip39::Mnemonic,
    bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
};
use rand::{thread_rng, Rng};
use seed_xor::SeedXor;

const ENTROPY_BYTES_24_WORDS: usize = 32;
const ENTROPY_BYTES_18_WORDS: usize = 24;
const ENTROPY_BYTES_12_WORDS: usize = 16;

/// Valid number of words in a mnemonic.
pub enum WordCount {
    Words12,
    Words18,
    Words24,
}

impl WordCount {
    /// Returns the number that `self` represents.
    pub fn count(&self) -> u8 {
        match self {
            WordCount::Words12 => 12,
            WordCount::Words18 => 18,
            WordCount::Words24 => 24,
        }
    }
}

impl FromStr for WordCount {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "12" => Ok(WordCount::Words12),
            "18" => Ok(WordCount::Words18),
            "24" => Ok(WordCount::Words24),
            _ => Err("Word count can either be 12, 18 or 24".to_string()),
        }
    }
}

/// Derives child seeds of `seed` within an index range of `[start, end]`. Each seed's word count will be exactly `word_count`.
/// Returned list of tuples contains the derived seeds and their indexes.
pub fn derive_child_seeds<S>(
    seed: S,
    (start, mut end): (u32, u32),
    word_count: WordCount,
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

    let mut result: Vec<(u32, Mnemonic)> = Vec::with_capacity(end as usize - start as usize + 1);

    for i in start..end {
        let mnemonic = bip85::to_mnemonic(&secp, &xprv, word_count.count() as u32, i)
            .map_err(|e| e.to_string())?;
        result.push((i, mnemonic));
    }

    Ok(result)
}

/// Extends a `seed`'s number of words to the desired length `word_count` by enxtending its entropy.
/// The returned new seed will start with the same words as `seed`.
pub fn extend_seed<S>(seed: S, word_count: WordCount) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    // Check if seed can be extended
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() >= word_count.count() as usize {
        return Err("Seed is already longer or the same as the desired length".to_string());
    }

    // Determine length of new entropy
    let mut entropy = parsed_seed.to_entropy();
    let mut rand = thread_rng();
    let new_entropy_count = match word_count {
        WordCount::Words12 => 0,
        WordCount::Words18 => ENTROPY_BYTES_18_WORDS - entropy.len(),
        WordCount::Words24 => ENTROPY_BYTES_24_WORDS - entropy.len(),
    };

    // Generate entropy
    let more_entropy = std::iter::repeat(())
        .map(|()| rand.gen::<u8>())
        .take(new_entropy_count);
    entropy.extend(more_entropy);

    Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())
}

/// Truncates a `seed`'s number of words to `word_count` by truncating its entropy.
pub fn truncate_seed<S>(seed: S, word_count: WordCount) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    // Return early if seed has already the desired length
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() <= word_count.count() as usize {
        return Ok(parsed_seed);
    }

    // Truncate entropy
    let mut entropy = parsed_seed.to_entropy();
    match word_count {
        WordCount::Words12 => entropy.truncate(ENTROPY_BYTES_12_WORDS),
        WordCount::Words18 => entropy.truncate(ENTROPY_BYTES_18_WORDS),
        WordCount::Words24 => (),
    }

    Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())
}

/// XORs multiple seeds and returns the resulting seed or `None` if seeds are empty.
/// Can fail if a seed is not a valid [bip39::Mnemonic].
pub fn xor_seeds(seeds: &[&str]) -> Result<Option<Mnemonic>, String> {
    let mut mnemonics: Vec<Mnemonic> = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let mnemonic = Mnemonic::from_str(seed).map_err(|e| e.to_string())?;
        mnemonics.push(mnemonic);
    }

    Ok(mnemonics.into_iter().reduce(|a, b| a.xor(&b)))
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

/// Derives extended private keys of a `seed` within an index range `[start, end]`.
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
    let master = derive_root_xprv(seed)?;
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

/// Derives the master public key of a `seed` at the bip32 root.
pub fn derive_root_xpub<S>(seed: S) -> Result<ExtendedPubKey, String>
where
    S: AsRef<str>,
{
    let xprv = derive_root_xprv(seed)?;
    let secp = Secp256k1::new();

    Ok(ExtendedPubKey::from_private(&secp, &xprv))
}

/// Derives the master private key of a `seed` at the bip32 root.
pub fn derive_root_xprv<S>(seed: S) -> Result<ExtendedPrivKey, String>
where
    S: AsRef<str>,
{
    let parsed_seed = parse_seed(seed)?;
    let entropy = parsed_seed.to_entropy();
    let xprv =
        ExtendedPrivKey::new_master(Network::Bitcoin, &entropy).map_err(|e| e.to_string())?;

    Ok(xprv)
}

/// Parses a `seed` string to a [bip39::Mnemonic].
fn parse_seed<S>(seed: S) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    Mnemonic::from_str(seed.as_ref()).map_err(|e| e.to_string())
}
