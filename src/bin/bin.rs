use clap::{App, Arg, ArgMatches};
use lib::{derive_child_seed, derive_xpubs_from_seed, extend_seed, truncate_seed, xor_seeds};

const CHILD_SUB: &str = "child";
const EXTEND_SUB: &str = "extend";
const TRUNCATE_SUB: &str = "truncate";
const XOR_SUB: &str = "xor";
const XPUB_SUB: &str = "xpub";

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
        Some(CHILD_SUB) => process_child_matches(matches)?,
        Some(EXTEND_SUB) => process_extend_matches(matches)?,
        Some(TRUNCATE_SUB) => process_truncate_matches(matches)?,
        Some(XOR_SUB) => process_xor_matches(matches)?,
        Some(XPUB_SUB) => process_xpub_matches(matches)?,
        Some(unknown) => println!("Subcommand [{}] does not exist", unknown),
        None => println!("No subcommand was used"),
    }

    Ok(())
}

fn index_value(matches: &ArgMatches) -> Result<u32, ()> {
    matches
        .value_of("index")
        .ok_or(())?
        .parse::<u32>()
        .or_else(|_| Err(()))
}

fn seed_value<'a>(matches: &'a ArgMatches) -> Result<&'a str, ()> {
    matches.value_of("seed").ok_or(())
}

fn seed_values<'a>(matches: &'a ArgMatches) -> Result<Vec<&'a str>, ()> {
    Ok(matches.values_of("seed").ok_or(())?.into_iter().collect())
}

fn word_count_value(matches: &ArgMatches) -> Result<u32, ()> {
    matches
        .value_of("word count")
        .ok_or(())?
        .parse::<u32>()
        .or_else(|_| Err(()))
}

fn process_child_matches(matches: &ArgMatches) -> Result<(), ()> {
    let seed_str = seed_value(matches)?;
    let word_count = word_count_value(matches)?;
    let index = index_value(matches)?;

    let derived = derive_child_seed(seed_str, index, word_count);

    println!("Derived seed at {}: {}", index, derived);

    Ok(())
}

fn process_extend_matches(matches: &ArgMatches) -> Result<(), ()> {
    let seed_str = seed_value(matches)?;

    let extended_seeds = extend_seed(seed_str);
    // TODO: print different word counts
    for seed in extended_seeds {
        println!("Extended seed: {}", seed);
    }

    Ok(())
}

fn process_truncate_matches(matches: &ArgMatches) -> Result<(), ()> {
    let seed_str = seed_value(matches)?;

    let truncated_seeds = truncate_seed(&seed_str);

    for seed in truncated_seeds {
        // TODO: Print different word lengths
        println!("Truncated seed: {}", seed);
    }

    Ok(())
}

fn process_xor_matches(matches: &ArgMatches) -> Result<(), ()> {
    let seeds = seed_values(matches)?;
    let xor_seed = xor_seeds(&seeds);

    println!("XORed seed: {}", xor_seed);

    Ok(())
}

// TODO: Derive master xpub
// TODO: Derive xpubs of different types
// TODO: Derive xpubs of index ranges

fn process_xpub_matches(matches: &ArgMatches) -> Result<(), ()> {
    let seed_str = seed_value(matches)?;
    let index = index_value(matches)?;

    let derived = derive_xpubs_from_seed(seed_str, (index, index));

    for xpub in derived {
        println!("Derived xpub at {}: {}", index, xpub);
    }

    Ok(())
}
