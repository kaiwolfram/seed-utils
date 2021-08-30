use std::str::FromStr;

use bip85::bitcoin::secp256k1::Secp256k1;
use bip85::bitcoin::Network;
use bip85::{
    bip39::Mnemonic,
    bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
};
use rand::{thread_rng, Rng};
use seed_xor::SeedXor;
use xyzpub::Version;

const ENTROPY_BYTES_24_WORDS: usize = 32;
const ENTROPY_BYTES_18_WORDS: usize = 24;
const ENTROPY_BYTES_12_WORDS: usize = 16;

/// Valid number of words in a mnemonic.
#[derive(Debug, PartialEq, Eq)]
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

/// Derives child seeds of `seed` within an index range of `[start, end)`. Each seed's word count will be exactly `word_count`.
/// Returned list of tuples contains the derived seeds and their indexes.
pub fn derive_child_seeds<S>(
    seed: S,
    (start, mut end): (u32, u32),
    word_count: &WordCount,
) -> Result<Vec<(u32, Mnemonic)>, String>
where
    S: AsRef<str>,
{
    if end < start {
        end = start;
    }
    let xprv = derive_root_xprv(seed)?;
    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();

    let mut result: Vec<(u32, Mnemonic)> = Vec::with_capacity(end as usize - start as usize);

    for i in start..end {
        let mnemonic = bip85::to_mnemonic(&secp, &xprv, word_count.count() as u32, i)
            .map_err(|e| e.to_string())?;
        result.push((i, mnemonic));
    }

    Ok(result)
}

/// Extends a `seed`'s number of words to the desired length `word_count` by enxtending its entropy.
/// The returned new seed will start with the same words as `seed`.
pub fn extend_seed<S>(seed: S, word_count: &WordCount) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    // Check if seed can be extended
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() > word_count.count() as usize {
        return Err("Seed is already longer than the desired length".to_string());
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
pub fn truncate_seed<S>(seed: S, word_count: &WordCount) -> Result<Mnemonic, String>
where
    S: AsRef<str>,
{
    // Return early if seed has already the desired length
    let parsed_seed = parse_seed(seed)?;
    if parsed_seed.word_count() < word_count.count() as usize {
        return Err("Seed is already shorter than the desired length".to_string());
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

/// Derives account extended public keys of a `seed` within an index range `[start, end)` with the derivation path of `version`.
/// Returns a tuple of the derivation path and its derived xpub.
pub fn derive_xpubs_from_seed<S>(
    seed: S,
    (start, end): (u32, u32),
    version: &Version,
) -> Result<Vec<(DerivationPath, ExtendedPubKey)>, String>
where
    S: AsRef<str>,
{
    let xprvs = derive_xprvs_from_seed(seed, (start, end), version)?;
    let secp = Secp256k1::new();
    let xpubs = xprvs
        .into_iter()
        .map(move |(i, xprv)| (i, ExtendedPubKey::from_private(&secp, &xprv)))
        .collect();

    Ok(xpubs)
}

/// Derives account extended private keys of a `seed` within an index range `[start, end)` with the derivation path of `version`.
/// Returns a tuple of the derivation path and its derived xprv.
pub fn derive_xprvs_from_seed<S>(
    seed: S,
    (start, mut end): (u32, u32),
    version: &Version,
) -> Result<Vec<(DerivationPath, ExtendedPrivKey)>, String>
where
    S: AsRef<str>,
{
    if end < start {
        end = start;
    }
    let secp = Secp256k1::new();
    let master = derive_root_xprv(seed)?;
    let path = derivation_path_from_version(version)?;
    let mut result: Vec<(DerivationPath, ExtendedPrivKey)> =
        Vec::with_capacity(end as usize - start as usize);

    for i in start..end {
        let child = ChildNumber::from_hardened_idx(i).map_err(|e| e.to_string())?;
        let child_path = path.child(child);
        let derived = master
            .derive_priv(&secp, &child_path)
            .map_err(|e| e.to_string())?;
        result.push((child_path, derived));
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
    let entropy = parsed_seed.to_seed("");
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

/// Returns the bip32 derivation path of a xpub/xprv version.
fn derivation_path_from_version(version: &Version) -> Result<DerivationPath, String> {
    match version {
        Version::Xpub | Version::Xprv => {
            DerivationPath::from_str("m/44h/0h").map_err(|e| e.to_string())
        }
        Version::Ypub | Version::Yprv => {
            DerivationPath::from_str("m/49h/0h").map_err(|e| e.to_string())
        }
        Version::Zpub | Version::Zprv => {
            DerivationPath::from_str("m/84h/0h").map_err(|e| e.to_string())
        }
        Version::Tpub | Version::Tprv => {
            DerivationPath::from_str("m/44h/1h").map_err(|e| e.to_string())
        }
        Version::Upub | Version::Uprv => {
            DerivationPath::from_str("m/49h/1h").map_err(|e| e.to_string())
        }
        Version::Vpub | Version::Vprv => {
            DerivationPath::from_str("m/84h/1h").map_err(|e| e.to_string())
        }
        _ => Err("Multisig versions have no derivation path".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bip85::bitcoin::util::bip32::DerivationPath;
    use xyzpub::Version;

    use crate::{
        derivation_path_from_version, derive_child_seeds, derive_root_xprv, derive_root_xpub,
        derive_xprvs_from_seed, derive_xpubs_from_seed, extend_seed, parse_seed, truncate_seed,
        xor_seeds, WordCount,
    };

    #[test]
    fn wordcount_count_returns_correct_number() {
        let word_count_12 = WordCount::Words12;
        let word_count_18 = WordCount::Words18;
        let word_count_24 = WordCount::Words24;

        assert_eq!(word_count_12.count(), 12);
        assert_eq!(word_count_18.count(), 18);
        assert_eq!(word_count_24.count(), 24);
    }

    #[test]
    fn wordcount_from_str_returns_correct_wordcount() {
        let word_count_12 = WordCount::from_str("12").unwrap();
        let word_count_18 = WordCount::from_str("18").unwrap();
        let word_count_24 = WordCount::from_str("24").unwrap();
        let word_count_err = WordCount::from_str("10");

        assert_eq!(word_count_12, WordCount::Words12);
        assert_eq!(word_count_18, WordCount::Words18);
        assert_eq!(word_count_24, WordCount::Words24);
        assert!(word_count_err.is_err());
    }

    #[test]
    fn derive_child_seeds_returns_correct_seeds() {
        let seed = "almost talk bulk high steel flush siege intact liberty radar journey bullet little olympic suffer neck clock glad furnace undo outdoor useful feature mobile";
        let start = 0;
        let end = 9;

        // With 12 Words
        let word_count = WordCount::Words12;
        let result = derive_child_seeds(seed, (start, end), &word_count).unwrap();
        let mut expected_index = start;
        let child_seed_0 =
            "loyal utility atom boat debris blush skull rare cool bamboo stage ritual";
        assert_eq!(result.get(0).unwrap().1.to_string(), child_seed_0);
        for (i, mnemonic) in result {
            assert_eq!(i, expected_index);
            assert_eq!(mnemonic.word_count(), word_count.count() as usize);
            expected_index += 1;
        }
        assert_eq!(expected_index, end);

        // With 18 Words
        let word_count = WordCount::Words18;
        let result = derive_child_seeds(seed, (start, end), &word_count).unwrap();
        let mut expected_index = start;
        for (i, mnemonic) in result {
            assert_eq!(i, expected_index);
            assert_eq!(mnemonic.word_count(), word_count.count() as usize);
            expected_index += 1;
        }
        assert_eq!(expected_index, end);

        // With 24 Words
        let word_count = WordCount::Words24;
        let result = derive_child_seeds(seed, (start, end), &word_count).unwrap();
        let mut expected_index = start;
        for (i, mnemonic) in result {
            assert_eq!(i, expected_index);
            assert_eq!(mnemonic.word_count(), word_count.count() as usize);
            expected_index += 1;
        }
        assert_eq!(expected_index, end);

        // With start non 0
        let start = 1;
        let word_count = WordCount::Words24;
        let result = derive_child_seeds(seed, (start, end), &word_count).unwrap();
        let mut expected_index = start;
        for (i, mnemonic) in result {
            assert_eq!(i, expected_index);
            assert_eq!(mnemonic.word_count(), word_count.count() as usize);
            expected_index += 1;
        }
        assert_eq!(expected_index, end);
    }

    #[test]
    fn derive_child_seeds_returns_err_when_seed_invalid() {
        let seed = "almost talk bulk high steel flush siege intact liberty radar";
        let start = 0;
        let end = 9;
        let word_count = WordCount::Words12;

        let result = derive_child_seeds(seed, (start, end), &word_count);

        assert!(result.is_err());
    }

    #[test]
    fn extend_seed_extends_seed_to_word_count() {
        // From 12 to 12
        let seed =
            "tourist correct mango profit mom embody move thought deputy trophy excuse torch";
        let word_count = WordCount::Words12;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);

        // From 12 to 18
        let word_count = WordCount::Words18;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 18);

        // From 12 to 24
        let word_count = WordCount::Words24;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 24);

        // From 18 to 12
        let seed = "decline wide tone omit home crime ridge student crop dog purchase actress inject eager hungry country actress shoot";
        let word_count = WordCount::Words12;
        let result = extend_seed(seed, &word_count);
        assert!(result.is_err());

        // From 18 to 18
        let word_count = WordCount::Words18;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);

        // From 18 to 24
        let word_count = WordCount::Words24;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 24);

        // From 24 to 12
        let seed = "seven snack chicken they course lawsuit century protect glimpse loan course thing nation ketchup fringe uniform kite else lawn that female impose silver citizen";
        let word_count = WordCount::Words12;
        let result = extend_seed(seed, &word_count);
        assert!(result.is_err());

        // From 24 to 18
        let word_count = WordCount::Words18;
        let result = extend_seed(seed, &word_count);
        assert!(result.is_err());

        // From 24 to 24
        let word_count = WordCount::Words24;
        let result = extend_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);
    }

    #[test]
    fn truncate_seed_truncates_seed_to_word_count() {
        // From 12 to 12
        let seed =
            "tourist correct mango profit mom embody move thought deputy trophy excuse torch";
        let word_count = WordCount::Words12;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);

        // From 12 to 18 -> err
        let word_count = WordCount::Words18;
        let result = truncate_seed(seed, &word_count);
        assert!(result.is_err());

        // From 12 to 24 -> err
        let word_count = WordCount::Words24;
        let result = truncate_seed(seed, &word_count);
        assert!(result.is_err());

        // From 18 to 12
        let seed = "decline wide tone omit home crime ridge student crop dog purchase actress inject eager hungry country actress shoot";
        let word_count = WordCount::Words12;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 12);

        // From 18 to 18
        let word_count = WordCount::Words18;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);

        // From 18 to 24 -> err
        let word_count = WordCount::Words24;
        let result = truncate_seed(seed, &word_count);
        assert!(result.is_err());

        // From 24 to 12
        let seed = "seven snack chicken they course lawsuit century protect glimpse loan course thing nation ketchup fringe uniform kite else lawn that female impose silver citizen";
        let word_count = WordCount::Words12;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 12);

        // From 24 to 18
        let word_count = WordCount::Words18;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.word_count(), 18);

        // From 24 to 24
        let word_count = WordCount::Words24;
        let result = truncate_seed(seed, &word_count).unwrap();
        assert_eq!(result.to_string(), seed);
    }

    #[test]
    fn xor_seeds_returns_err_when_seed_invalid() {
        let seeds = vec!["wagyu beef"];
        let result = xor_seeds(&seeds);

        assert!(result.is_err());
    }

    #[test]
    fn xor_seeds_xors() {
        let mut seeds: Vec<&str> = Vec::new();

        // No seeds -> None
        let result = xor_seeds(&seeds).unwrap();
        assert!(result.is_none());

        // One seed -> same seed
        let seed1 = "romance wink lottery autumn shop bring dawn tongue range crater truth ability miss spice fitness easy legal release recall obey exchange recycle dragon room";
        seeds.push(seed1);
        let result = xor_seeds(&seeds).unwrap().unwrap();
        assert_eq!(result.to_string(), seed1);

        // More seeds -> correct XOR
        let seed2 = "lion misery divide hurry latin fluid camp advance illegal lab pyramid unaware eager fringe sick camera series noodle toy crowd jeans select depth lounge";
        let seed3 = "vault nominee cradle silk own frown throw leg cactus recall talent worry gadget surface shy planet purpose coffee drip few seven term squeeze educate";
        let expected = "silent toe meat possible chair blossom wait occur this worth option bag nurse find fish scene bench asthma bike wage world quit primary indoor";
        seeds.push(seed2);
        seeds.push(seed3);
        let result = xor_seeds(&seeds).unwrap().unwrap();
        assert_eq!(result.to_string(), expected);
    }

    #[test]
    fn derive_root_xprv_derives_root_derives_root_xprv() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire borrow";
        let expected = "xprv9s21ZrQH143K3rd3KuNUKxQMNEJsXTxUSuN9RQSm92oJEduoR4wnBneKzSdBDTnv9NtN9VJ2abs66gmM1rNbTdFKHoQPPMeyciwZZqsUbVC";
        let result = derive_root_xprv(seed).unwrap();
        assert_eq!(result.to_string(), expected);
    }

    #[test]
    fn derive_root_xpub_derives_root_xpub() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire borrow";
        let expected = "xpub661MyMwAqRbcGLhWRvuUh6M5vG9MvvgKp8HkDnrNhNLH7SEwxcG2jaxoqgd5sQf8iQNLMV7F5kSczN52jPqaYRnACAZSjfGuX5sj3AdRDPM";
        let result = derive_root_xpub(seed).unwrap();
        assert_eq!(result.to_string(), expected);
    }

    #[test]
    fn derive_xprvs_from_seed_derives_xprvs() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire borrow";
        let start = 0;
        let end = 9;

        // xprv
        let version = Version::Xprv;
        let expected0 = "xprv9yG8MuRhkRHFKzBVybi9MP13e4xrMYo9hWcp9sUEfAwXcCDNz29CET74FAGwfk6yFceEHpuk5XUrmQnJSJW4dHcmJnwhJj6ee9h2kQUaDz5";
        let expected1 = "xprv9yG8MuRhkRHFPTa4tJbapc9G4QLgfZtqKJ4xsk4p3nsVYDVVERMa9xmiwRPKkpxb9WRJAWakwVja38WRH9FTHbaXcBxsqaT7sk8GzTsKneJ";
        let result = derive_xprvs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/44'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/44'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);

        // yprv
        let version = Version::Yprv;
        let expected0 = "xprv9yvxNCHWSBEQ7AtVCjf2jGK3qHULFkM55EqwcEktzUYLWMy9SiJJ2CTCK24m6sxpim2a7yYY9usaB1nLD6SvkupHCRZz7AE2U8ywMH2jbxU";
        let expected1 = "xprv9yvxNCHWSBEQAqZpE9kUdUu7wbPUSvaC5YP43SyqxRLAHE5HBwe92omAxDMhfZrmV9m2vS46n9xk6JxBwAHq6GfwRto7VnshAwa2bmF33am";
        let result = derive_xprvs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/49'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/49'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);

        // zprv
        let version = Version::Zprv;
        let expected0 = "xprv9zFNLT61T56ccvGNiPh3f1XiWSaGJTwUJYTLvGBdNGfhg2EddRjVwRAUV2LgdiVS5g8ffzUiucZzaZFGcjVjTXsTQGRgndqp5CG6wsG6cvx";
        let expected1 = "xprv9zFNLT61T56cdVw4WVXh5KZFupHAkDXCKTL8oy4WCfznHsafM3wYuCedYQN91v5WYr2LPr2HX3ZrdspypqnXnHjqvNY117FRnKJZfjM3qBF";
        let result = derive_xprvs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/84'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/84'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);
    }

    #[test]
    fn derive_xpubs_from_seed_derives_xpubs() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire borrow";
        let start = 0;
        let end = 9;

        // xpub
        let version = Version::Xpub;
        let expected0 = "xpub6CFUmQxbanqYYUFy5dF9iWwnC6oLm1X14jYQxFsrDWUWUzYXXZTSnFRY6T9e7V9R1762jkvCHAF7PVQ3rJtC5dwCCA7PkCqoxfrDBhyot63";
        let expected1 = "xpub6CFUmQxbanqYbweXzL8bBk5zcSBB52cggWzZg8URc8QUR1pdmxfphm6CngQSPYbHJopuBLZg7qnMceyfUWN7r5RXeYQKEvArPzkstv1LiBy";
        let result = derive_xpubs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/44'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/44'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);

        // ypub
        let version = Version::Ypub;
        let expected0 = "xpub6CvJmhpQGYnhKexxJmC36QFnPKJpfD4vSTmYQdAWYp5KPAJHzFcYZzmgAJQeMDK57oRiw1cpxVmzadQJDJ9L1LW6cCiWtXvF8jJmqicHeJi";
        let expected1 = "xpub6CvJmhpQGYnhPKeHLBHUzcqrVdDxrPJ3SmJeqqPTWks9A2QRjUxPac5eoV5TtfnhKAQQgKZE377ZmoJc9oe6PSTnP8ETdRTg4tmgARXSUNE";
        let result = derive_xpubs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/49'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/49'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);

        // zpub
        let version = Version::Zpub;
        let expected0 = "xpub6DEijxcuHSeuqQLqpRE429UT4UQkhvfKfmNwiebEvcCgYpZnAy3kVDUxLKqDpPCnho5hjvsoxLB88c3pPXero4YMsNnCeh6jjqhxyA6gT6Q";
        let expected1 = "xpub6DEijxcuHSeuqz1XcX4hSTVzTr7f9gF3ggFjcMU7m1XmAfuotbFoSzy7PhzSPZA9xyYuAysaSrfjuF6caLTa81bAmreaHavVQakAuPKdYQj";
        let result = derive_xpubs_from_seed(seed, (start, end), &version).unwrap();
        assert_eq!(result.len(), 9);
        assert_eq!(result.get(0).unwrap().0.to_string(), "m/84'/0'/0'");
        assert_eq!(result.get(0).unwrap().1.to_string(), expected0);
        assert_eq!(result.get(1).unwrap().0.to_string(), "m/84'/0'/1'");
        assert_eq!(result.get(1).unwrap().1.to_string(), expected1);
    }

    #[test]
    fn parse_seed_returns_mnemonic() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire borrow";
        let result = parse_seed(seed).unwrap();
        assert_eq!(result.to_string(), seed);
    }

    #[test]
    fn parse_seed_returns_err_when_seed_invalid() {
        let seed =
            "artefact enact unable pigeon bottom traffic art antenna country clip inspire antenna";
        let result = parse_seed(seed);
        assert!(result.is_err());
    }

    #[test]
    fn derivation_path_from_version_returns_path() {
        let path44 = DerivationPath::from_str("m/44h/0h").unwrap();
        let path49 = DerivationPath::from_str("m/49h/0h").unwrap();
        let path84 = DerivationPath::from_str("m/84h/0h").unwrap();
        let path44_test = DerivationPath::from_str("m/44h/1h").unwrap();
        let path49_test = DerivationPath::from_str("m/49h/1h").unwrap();
        let path84_test = DerivationPath::from_str("m/84h/1h").unwrap();

        // xpub
        let version = Version::Xpub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path44);

        // xprv
        let version = Version::Xprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path44);

        // ypub
        let version = Version::Ypub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path49);

        // yprv
        let version = Version::Yprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path49);

        // zpub
        let version = Version::Zpub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path84);

        // zprv
        let version = Version::Zprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path84);

        // tpub
        let version = Version::Tpub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path44_test);

        // tprv
        let version = Version::Tprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path44_test);

        // upub
        let version = Version::Upub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path49_test);

        // uprv
        let version = Version::Uprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path49_test);

        // vpub
        let version = Version::Vpub;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path84_test);

        // vprv
        let version = Version::Vprv;
        let path = derivation_path_from_version(&version).unwrap();
        assert_eq!(path, path84_test);

        // Multisig -> err
        let version = Version::ZpubMultisig;
        let path = derivation_path_from_version(&version);
        assert!(path.is_err());
    }
}
