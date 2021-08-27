use clap::{App, Arg, ArgMatches};

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
const MASTER_ARG: &str = "master";

// TODO: Docs
// TODO: Readme.md

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
                    Arg::with_name(MASTER_ARG)
                        .help("Derive master xpub.")
                        .long(MASTER_ARG)
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
                    Arg::with_name(MASTER_ARG)
                        .help("Derive master xprv.")
                        .long(MASTER_ARG)
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

fn index_value(matches: &ArgMatches) -> Result<u32, String> {
    matches
        .value_of(INDEX_ARG)
        .ok_or_else(|| "index not set".to_string())?
        .parse::<u32>()
        .map_err(|_| "index can't be higher than 2^32".to_string())
}

fn number_value(matches: &ArgMatches) -> Result<u8, String> {
    matches
        .value_of(NUMBER_ARG)
        .ok_or_else(|| "number not set".to_string())?
        .parse::<u8>()
        .map_err(|_| "number can't be higher than 255".to_string())
}

fn seed_value<'a>(matches: &'a ArgMatches) -> Result<&'a str, String> {
    matches
        .value_of(SEED_ARG)
        .ok_or_else(|| "seed not set".to_string())
}

fn seed_values<'a>(matches: &'a ArgMatches) -> Result<Vec<&'a str>, String> {
    Ok(matches
        .values_of(SEED_ARG)
        .ok_or_else(|| "seeds not set".to_string())?
        .into_iter()
        .collect())
}

fn word_count_value(matches: &ArgMatches) -> Result<u8, String> {
    matches
        .value_of(WORDS_ARG)
        .ok_or("word count not set")?
        .parse::<u8>()
        .map_err(|_| "word count can't be higher than 24".to_string())
}

fn is_master(matches: &ArgMatches) -> bool {
    matches.is_present(MASTER_ARG)
}

fn process_child_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let index = index_value(matches)?;
    let number = number_value(matches)?;
    let word_count = word_count_value(matches)?;

    let derived = lib::derive_child_seeds(seed_str, (index, index + number as u32), word_count)?;

    for (i, mnemonic) in derived {
        println!("Derived seed at {}: {}", i, mnemonic);
    }

    Ok(())
}

fn process_extend_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    let word_count = word_count_value(matches)?;

    let extended_seed = lib::extend_seed(seed_str, word_count)?;
    println!("Extended seed: {}", extended_seed);

    Ok(())
}

fn process_truncate_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because seed is required and word count has a default
    let seed_str = seed_value(matches)?;
    let word_count = word_count_value(matches)?;

    let truncated_seed = lib::truncate_seed(&seed_str, word_count)?;

    println!("Truncated seed: {}", truncated_seed);
    Ok(())
}

fn process_xor_matches(matches: &ArgMatches) -> Result<(), String> {
    let seeds = seed_values(matches)?;
    let xor_seed = lib::xor_seeds(&seeds)?;

    println!("XORed seed: {}", xor_seed);

    Ok(())
}

fn process_xpub_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    if is_master(matches) {
        let master = lib::derive_master_xpub(seed_str)?;
        println!("Master xpub: {}", master);

        return Ok(());
    }
    let index = index_value(matches)?;
    let number = number_value(matches)?;

    let derived = lib::derive_xpubs_from_seed(seed_str, (index, index + number as u32))?;

    for (i, xpub) in derived {
        println!("Derived xpub at {}: {}", i, xpub);
    }

    Ok(())
}

fn process_xprv_matches(matches: &ArgMatches) -> Result<(), String> {
    // Return early because every field is either required or has a default value
    let seed_str = seed_value(matches)?;
    if is_master(matches) {
        let master = lib::derive_master_xprv(seed_str)?;
        println!("Master xprv: {}", master);

        return Ok(());
    }
    let index = index_value(matches)?;
    let number = number_value(matches)?;

    let derived = lib::derive_xprvs_from_seed(seed_str, (index, index + number as u32))?;

    for (i, xpub) in derived {
        println!("Derived xprv at {}: {}", i, xpub);
    }

    Ok(())
}
