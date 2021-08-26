use std::str::FromStr;

use bip85::bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use clap::{App, Arg, ArgMatches};
use rand::{thread_rng, Rng};

const CHILD_SUB: &str = "child";
const EXTEND_SUB: &str = "extend";
const TRUNCATE_SUB: &str = "truncate";
const XOR_SUB: &str = "xor";
const XPUB_SUB: &str = "xpub";
const MAX_ENTROPY_BYTES: usize = 32;
const MIN_ENTROPY_BYTES: usize = 16;

// TODO: Split into lib and bin
// TODO: Remove unwraps
// TODO: Proper error handling

fn main() -> Result<(), ()> {
    let matches = App::new("seed-utils")
        .version("0.1.0")
        .about("CLI seed utilities")
        .author("kaiwitt")
        .subcommand(
            App::new(CHILD_SUB)
                .about("Derives a child seed from a seed.")
                .arg(
                    Arg::with_name("seed")
                        .help("Seed to derive.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("index")
                        .help("Index to derive at.")
                        .index(2)
                        .required(true),
                )
                .arg(
                    Arg::with_name("word count")
                        .help("Number of words of the derived seed.")
                        .short("w")
                        .long("words")
                        .default_value("24"),
                ),
        )
        .subcommand(
            App::new(EXTEND_SUB)
                .about("Creates a new seeds by extending the entropy of a 12 or 16 word seed")
                .arg(
                    Arg::with_name("seed")
                        .help("Seed to extend.")
                        .index(1)
                        .required(true),
                )
        )
        .subcommand(
            App::new(TRUNCATE_SUB)
                .about("Creates new seeds by shortening the entropy of another seed. 
                The new seed begins with the same words as the longer seed, only the last one is different to satisfy the checksum.")
                .arg(
                    Arg::with_name("seed")
                        .help("Seed to truncate.")
                        .index(1)
                        .required(true),
                )
        )
        .subcommand(
            App::new(XOR_SUB)
            .about("XORs two seeds.")
            .arg(
                Arg::with_name("seed")
                    .help("Seeds to xor.")
                    .short("s")
                    .long("seed")
                    .multiple(true)
                    .required(true),
            ),
        )
        .subcommand(
            App::new(XPUB_SUB)
                .about("Derives account xpubs from a seed.")
                .arg(
                    Arg::with_name("seed")
                        .help("Seed to derive xpubs from.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name("index")
                        .help("Index to derive xpub at.")
                        .short("i")
                        .long("index"),
                )
        )
        .get_matches();
    process_matches(&matches)
}

/// Processes command line arguments.
fn process_matches(matches: &ArgMatches) -> Result<(), ()> {
    match matches.subcommand_name() {
        Some(CHILD_SUB) => process_child_matches(matches),
        Some(EXTEND_SUB) => process_extend_matches(matches),
        Some(TRUNCATE_SUB) => process_truncate_matches(matches),
        Some(XOR_SUB) => process_xor_matches(matches),
        Some(XPUB_SUB) => process_xpub_matches(matches),
        None => println!("No subcommand was used"),
        Some(unknown) => println!("Subcommand [{}] does not exist", unknown),
    }

    Ok(())
}

struct ChildArgs<'a> {
    seed: &'a str,
    index: u32,
    word_count: u32,
}

impl<'a> ChildArgs<'a> {
    /// Reads command line arguments of the `child` subcommand and saves them in a new struct.
    fn new(matches: &'a ArgMatches) -> Result<Self, ()> {
        let seed = matches.value_of("seed").ok_or(())?;
        let index = matches
            .value_of("index")
            .ok_or(())?
            .parse::<u32>()
            .or_else(|_| Err(()))?;
        let word_count = matches
            .value_of("word count")
            .ok_or(())?
            .parse::<u32>()
            .or_else(|_| Err(()))?;

        Ok(ChildArgs {
            seed,
            index,
            word_count,
        })
    }
}

fn process_child_matches(matches: &ArgMatches) {
    let args = ChildArgs::new(matches).unwrap();
    let seed = bip85::bip39::Mnemonic::from_str(args.seed).unwrap();
    let entropy = seed.to_entropy();
    let xprv = bip85::bitcoin::util::bip32::ExtendedPrivKey::new_master(
        bip85::bitcoin::Network::Bitcoin,
        &entropy,
    )
    .unwrap();

    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();
    let derived = bip85::to_mnemonic(&secp, &xprv, args.word_count, args.index).unwrap();

    println!("Derived seed at {}: {}", args.index, derived.to_string());
}

struct ExtendArgs<'a> {
    seed: &'a str,
}

impl<'a> ExtendArgs<'a> {
    /// Reads command line arguments of the `extend` subcommand and saves them in a new struct.
    fn new(matches: &'a ArgMatches) -> Result<Self, ()> {
        let seed = matches.value_of("seed").ok_or(())?;

        Ok(ExtendArgs { seed })
    }
}

fn process_extend_matches(matches: &ArgMatches) {
    let args = ExtendArgs::new(matches).unwrap();
    let seed = bip85::bip39::Mnemonic::from_str(args.seed).unwrap();
    let mut entropy = seed.to_entropy();

    if entropy.len() < MAX_ENTROPY_BYTES {
        let mut rand = thread_rng();
        let more_entropy = std::iter::repeat(())
            .map(|()| rand.gen::<u8>())
            .take(MAX_ENTROPY_BYTES - entropy.len());
        entropy.extend(more_entropy);
    }
    let extended_seed = bip85::bip39::Mnemonic::from_entropy(&entropy).unwrap();

    // TODO: print different word counts
    println!("Extended seed: {}", extended_seed.to_string());
}

struct TruncateArgs<'a> {
    seed: &'a str,
}

impl<'a> TruncateArgs<'a> {
    /// Reads command line arguments of the `truncate` subcommand and saves them in a new struct.
    fn new(matches: &'a ArgMatches) -> Result<Self, ()> {
        let seed = matches.value_of("seed").ok_or(())?;

        Ok(TruncateArgs { seed })
    }
}

fn process_truncate_matches(matches: &ArgMatches) {
    let args = TruncateArgs::new(matches).unwrap();
    let seed = bip85::bip39::Mnemonic::from_str(args.seed).unwrap();
    let mut entropy = seed.to_entropy();
    entropy.truncate(MIN_ENTROPY_BYTES);

    let truncated_seed = bip85::bip39::Mnemonic::from_entropy(&entropy).unwrap();

    // TODO: Print different word lengths
    println!("Truncated seed: {}", truncated_seed.to_string());
}

struct XorArgs<'a> {
    seeds: Vec<&'a str>,
}

impl<'a> XorArgs<'a> {
    /// Reads command line arguments of the `xor` subcommand and saves them in a new struct.
    fn new(matches: &'a ArgMatches) -> Result<Self, ()> {
        let seeds: Vec<&str> = matches.values_of("seed").ok_or(())?.into_iter().collect();

        Ok(XorArgs { seeds })
    }
}

fn process_xor_matches(matches: &ArgMatches) {
    let args = XorArgs::new(matches).unwrap();
    let xor_seed: seed_xor::Mnemonic = args
        .seeds
        .iter()
        .map(|seed| seed_xor::Mnemonic::from_str(seed).unwrap())
        .reduce(|a, b| a ^ b)
        .unwrap();

    println!("XORed seed: {}", xor_seed.to_string());
}

// TODO: Derive master xpub
// TODO: Derive xpubs of different types
// TODO: Derive xpubs of index ranges
struct XpubArgs<'a> {
    seed: &'a str,
    index: u32,
}

impl<'a> XpubArgs<'a> {
    /// Reads command line arguments of the `xpub` subcommand and saves them in a new struct.
    fn new(matches: &'a ArgMatches) -> Result<Self, ()> {
        let seed = matches.value_of("seed").ok_or(())?;
        let index = matches
            .value_of("index")
            .ok_or(())?
            .parse::<u32>()
            .or_else(|_| Err(()))?;

        Ok(XpubArgs { seed, index })
    }
}

fn process_xpub_matches(matches: &ArgMatches) {
    let args = XpubArgs::new(matches).unwrap();
    let seed = bip85::bip39::Mnemonic::from_str(args.seed).unwrap();
    let entropy = seed.to_entropy();
    let xprv = bip85::bitcoin::util::bip32::ExtendedPrivKey::new_master(
        bip85::bitcoin::Network::Bitcoin,
        &entropy,
    )
    .unwrap();

    let secp = bip85::bitcoin::secp256k1::Secp256k1::new();
    let path = DerivationPath::from_str("m/84'/0'")
        .unwrap()
        .child(ChildNumber::from_normal_idx(args.index).unwrap());
    let xpub = ExtendedPubKey::from_private(&secp, &xprv);
    let derived = xpub.derive_pub(&secp, &path).unwrap();

    println!("Derived xpub at {}: {}", args.index, derived.to_string());
}
