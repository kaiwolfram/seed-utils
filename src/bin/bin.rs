use std::str::FromStr;

use bip85::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
use clap::{App, Arg, ArgMatches};
use seed_utils::WordCount;
use xyzpub::Version;

const CHILD_SUB: &str = "child";
const EXTEND_SUB: &str = "extend";
const TRUNCATE_SUB: &str = "truncate";
const XOR_SUB: &str = "xor";
const XPRV_SUB: &str = "xprv";
const XPUB_SUB: &str = "xpub";

const SEED_ARG: &str = "seed";
const INDEX_ARG: &str = "index";
const NUMBER_ARG: &str = "number";
const WORDS_ARG: &str = "words";
const ROOT_ARG: &str = "root";
const TYPE_ARG: &str = "type";

fn main() -> Result<(), String> {
    let matches = App::new("seed-utils")
        .version("0.1.0")
        .about("CLI seed utilities")
        .author("kaiwitt")
        .subcommand(
            App::new(CHILD_SUB)
                .about("Derives a child seed from a seed.")
                .arg(
                    Arg::with_name(SEED_ARG)
                        .help("Seed to derive.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name(INDEX_ARG)
                        .help("Index to derive at.")
                        .short("i")
                        .long(INDEX_ARG)
                        .takes_value(true)
                        .default_value("0"),
                )
                .arg(
                    Arg::with_name(NUMBER_ARG)
                        .help("Number of seeds to derive, starting from index.")
                        .short("n")
                        .long(NUMBER_ARG)
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::with_name(WORDS_ARG)
                        .help("Number of words of the derived seed.")
                        .short("w")
                        .long(WORDS_ARG)
                        .takes_value(true)
                        .possible_values(&["12", "18", "24"])
                        .default_value("24"),
                ),
        )
        .subcommand(
            App::new(EXTEND_SUB)
                .about("Creates a new seed by extending the entropy of a 12 or 18 word seed")
                .arg(
                    Arg::with_name(SEED_ARG)
                        .help("Seed to extend.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name(WORDS_ARG)
                        .help("Number of words of the extended seed.")
                        .short("w")
                        .long(WORDS_ARG)
                        .takes_value(true)
                        .possible_values(&["18", "24"])
                        .default_value("24"),
                ),
        )
        .subcommand(
            App::new(TRUNCATE_SUB)
                .about("Creates new seeds by shortening the entropy of another. 
                The new seed begins with the same words as the longer one, only the last word is different to satisfy its checksum.")
                .arg(
                    Arg::with_name(SEED_ARG)
                        .help("Seed to truncate.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name(WORDS_ARG)
                        .help("Number of words of the truncated seed.")
                        .short("w")
                        .long(WORDS_ARG)
                        .takes_value(true)
                        .possible_values(&["12", "18"])
                        .default_value("12"),
                ),
        )
        .subcommand(
            App::new(XOR_SUB)
            .about("Does a XOR of multiple seeds.")
            .arg(
                Arg::with_name(SEED_ARG)
                    .help("Seeds to xor.")
                    .short("s")
                    .long(SEED_ARG)
                    .multiple(true)
                    .min_values(2)
                    .required(true),
            ),
        )
        .subcommand(
            App::new(XPUB_SUB)
                .about("Derives account xpubs from a seed.")
                .arg(
                    Arg::with_name(SEED_ARG)
                        .help("Seed to derive xpubs from.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name(ROOT_ARG)
                        .help("Derive the bip32 root xpub.")
                        .long(ROOT_ARG)
                        .takes_value(false)
                        .conflicts_with_all(&[INDEX_ARG, NUMBER_ARG]),
                )
                .arg(
                    Arg::with_name(INDEX_ARG)
                        .help("Index to derive xpub at.")
                        .short("i")
                        .long(INDEX_ARG)
                        .takes_value(true)
                        .default_value("0"),
                )
                .arg(
                    Arg::with_name(NUMBER_ARG)
                        .help("Number of xpubs to derive, starting from index.")
                        .short("n")
                        .long(NUMBER_ARG)
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::with_name(TYPE_ARG)
                        .help("Type of xpub to return. Either xpub, ypub or zpub.")
                        .short("t")
                        .long(TYPE_ARG)
                        .takes_value(true)
                        .possible_values(&["xpub", "ypub", "zpub"])
                        .default_value("zpub"),
                ),
        )
        .subcommand(
            App::new(XPRV_SUB)
                .about("Derives account xprvs from a seed.")
                .arg(
                    Arg::with_name(SEED_ARG)
                        .help("Seed to derive xprvs from.")
                        .index(1)
                        .required(true),
                )
                .arg(
                    Arg::with_name(ROOT_ARG)
                        .help("Derive the bip32 root xprv.")
                        .long(ROOT_ARG)
                        .takes_value(false)
                        .conflicts_with_all(&[INDEX_ARG, NUMBER_ARG]),
                )
                .arg(
                    Arg::with_name(INDEX_ARG)
                        .help("Index to derive xprv at.")
                        .short("i")
                        .long(INDEX_ARG)
                        .takes_value(true)
                        .default_value("0"),
                )
                .arg(
                    Arg::with_name(NUMBER_ARG)
                        .help("Number of xprvs to derive, starting from index.")
                        .short("n")
                        .long(NUMBER_ARG)
                        .takes_value(true)
                        .default_value("1"),
                )
                .arg(
                    Arg::with_name(TYPE_ARG)
                        .help("Type of xprv to return. Either xprv, yprv or zprv.")
                        .short("t")
                        .long(TYPE_ARG)
                        .takes_value(true)
                        .possible_values(&["xprv", "yprv", "zprv"])
                        .default_value("zprv"),
                ),
        )
        .get_matches();
    process_matches(&matches)
}

/// Processes command line arguments.
fn process_matches(matches: &ArgMatches) -> Result<(), String> {
    match matches.subcommand_name() {
        Some(CHILD_SUB) => process_child_matches(matches)?,
        Some(EXTEND_SUB) => process_extend_matches(matches)?,
        Some(TRUNCATE_SUB) => process_truncate_matches(matches)?,
        Some(XOR_SUB) => process_xor_matches(matches)?,
        Some(XPUB_SUB) => process_xpub_matches(matches)?,
        Some(XPRV_SUB) => process_xprv_matches(matches)?,
        Some(unknown) => println!("Subcommand [{}] does not exist", unknown),
        None => println!("No subcommand was used"),
    }

    Ok(())
}

/// Returns the `index` flag's value.
fn index_value(matches: &ArgMatches) -> Result<u32, String> {
    matches
        .value_of(INDEX_ARG)
        .ok_or_else(|| "index not set".to_string())?
        .parse::<u32>()
        .map_err(|_| "index can't be higher than 2^32".to_string())
}

/// Returns the `number` flag's value.
fn number_value(matches: &ArgMatches) -> Result<u8, String> {
    matches
        .value_of(NUMBER_ARG)
        .ok_or_else(|| "number not set".to_string())?
        .parse::<u8>()
        .map_err(|_| "number can't be higher than 255".to_string())
}

/// Returns the `seed` flag's value.
fn seed_value<'a>(matches: &'a ArgMatches) -> Result<&'a str, String> {
    matches
        .value_of(SEED_ARG)
        .ok_or_else(|| "seed not set".to_string())
}

/// Returns the `seed` flag's values as a list of seeds.
fn seed_values<'a>(matches: &'a ArgMatches) -> Result<Vec<&'a str>, String> {
    Ok(matches
        .values_of(SEED_ARG)
        .ok_or_else(|| "seeds not set".to_string())?
        .into_iter()
        .collect())
}

/// Returns the `words` flag's value.
fn word_count_value(matches: &ArgMatches) -> Result<WordCount, String> {
    let count = matches.value_of(WORDS_ARG).ok_or("word count not set")?;

    WordCount::from_str(count)
}

/// Returns the `type` flag's value.
fn type_value<'a>(matches: &'a ArgMatches) -> Result<Version, String> {
    let version = matches
        .value_of(TYPE_ARG)
        .ok_or("type not set".to_string())?;
    Version::from_str(version).map_err(|_| format!("Version prefix [{}] is not supported", version))
}

/// Returns the `root` flag.
fn is_root(matches: &ArgMatches) -> bool {
    matches.is_present(ROOT_ARG)
}

/// Processes the `child` subcommand.
fn process_child_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let index = index_value(matches)?;
    let number = number_value(matches)?;
    let word_count = word_count_value(matches)?;

    let derived =
        seed_utils::derive_child_seeds(seed_str, (index, index + number as u32), &word_count)?;

    for (i, mnemonic) in derived {
        println!("Derived seed at {}: {}", i, mnemonic);
    }

    Ok(())
}

/// Processes the `extend` subcommand.
fn process_extend_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let word_count = word_count_value(matches)?;

    let extended_seed = seed_utils::extend_seed(seed_str, &word_count)?;
    println!("Extended seed: {}", extended_seed);

    Ok(())
}

/// Processes the `truncate` subcommand.
fn process_truncate_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because seed is required and word count has a default
    let seed_str = seed_value(matches)?;
    let word_count = word_count_value(matches)?;

    let truncated_seed = seed_utils::truncate_seed(&seed_str, &word_count)?;
    println!("Truncated seed: {}", truncated_seed);

    Ok(())
}

/// Processes the `xor` subcommand.
fn process_xor_matches(matches: &ArgMatches) -> Result<(), String> {
    let seeds = seed_values(matches)?;

    if let Some(xor) = seed_utils::xor_seeds(&seeds)? {
        println!("XORed seed: {}", xor);
    } else {
        println!("No seeds to XOR");
    }

    Ok(())
}

/// Processes the `xpub` subcommand.
fn process_xpub_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let version = type_value(matches)?;

    // Print root key if flag is present
    if is_root(matches) {
        let master = seed_utils::derive_root_xpub(seed_str)?.versioned_string(&version)?;
        println!("Root xpub: {}", master);

        return Ok(());
    }

    // Derive extended public keys
    let index = index_value(matches)?;
    let number = number_value(matches)?;
    let derived =
        seed_utils::derive_xpubs_from_seed(seed_str, (index, index + number as u32), &version)?;
    for (i, xpub) in derived {
        println!(
            "Derived xpub at {}: {}",
            i,
            xpub.versioned_string(&version)?
        );
    }

    Ok(())
}

/// Processes the `xprv` subcommand.
fn process_xprv_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let version = type_value(matches)?;

    // Print root key if flag is present
    if is_root(matches) {
        let master = seed_utils::derive_root_xprv(seed_str)?.versioned_string(&version)?;
        println!("Root xprv: {}", master);

        return Ok(());
    }

    // Derive extended private keys
    let index = index_value(matches)?;
    let number = number_value(matches)?;
    let derived =
        seed_utils::derive_xprvs_from_seed(seed_str, (index, index + number as u32), &version)?;
    for (i, xpub) in derived {
        println!(
            "Derived xprv at {}: {}",
            i,
            xpub.versioned_string(&version)?
        );
    }

    Ok(())
}

/// Trait for returning a versioned string of a Bitcoin address.
trait VersionedString {
    /// Returns a versioned string or `Err` if conversion fails.
    /// Failure may occur when `self`'s string value is not a valid base58 check encoded Bitcoin address.
    fn versioned_string(&self, version: &Version) -> Result<String, String>;
}

impl VersionedString for ExtendedPubKey {
    fn versioned_string(&self, version: &Version) -> Result<String, String> {
        xyzpub::convert_version(self.to_string(), version)
            .map_err(|_| "Failed to convert extended public key to requested version".to_string())
    }
}

impl VersionedString for ExtendedPrivKey {
    fn versioned_string(&self, version: &Version) -> Result<String, String> {
        xyzpub::convert_version(self.to_string(), version)
            .map_err(|_| "Failed to convert extended private key to requested version".to_string())
    }
}
