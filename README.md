# seed-utils

Extend and truncate seeds, XOR them, derive child seeds and xpubs/xprvs at account or root level.


## Usage

```
seed-utils 0.1.0
CLI seed utilities.

USAGE:
    seed-utils [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    child       Derives a child seed from a seed.
    extend      Creates a new seed by extending the entropy of a 12 or 18 word seed
    help        Prints this message or the help of the given subcommand(s)
    truncate    Creates new seeds by shortening the entropy of another.
                                The new seed begins with the same words as the longer one, only the last word is
                different to satisfy its checksum.
    xor         Does a XOR of multiple seeds.
    xprv        Derives account xprvs from a seed.
    xpub        Derives account xpubs from a seed.
```
### `child` subcommand:
```
Derives a child seed from a seed.

USAGE:
    seed-utils child [OPTIONS] <seed>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --index <index>      Index to derive at [default: 0]
    -n, --number <number>    Number of seeds to derive, starting from index [default: 1]
    -w, --words <words>      Number of words of the derived seed [default: 24]  [possible values: 12, 18, 24]

ARGS:
    <seed>    Seed to derive
```
### `extend` subcommand:
```
Creates a new seed by extending the entropy of a 12 or 18 word seed.

USAGE:
    seed-utils extend [OPTIONS] <seed>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --words <words>    Number of words of the extended seed [default: 24]  [possible values: 18, 24]

ARGS:
    <seed>    Seed to extend
```
### `truncate` subcommand:
```
Creates new seeds by shortening the entropy of another.
                The new seed begins with the same words as the longer one, only the last word is different to satisfy
its checksum.

USAGE:
    seed-utils truncate [OPTIONS] <seed>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --words <words>    Number of words of the truncated seed [default: 12]  [possible values: 12, 18]

ARGS:
    <seed>    Seed to truncate
```
### `xor` subcommand:
```
Does a XOR of multiple seeds.

USAGE:
    seed-utils xor <seed>...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <seed>...    Seeds to xor
```
### `xprv` subcommand:
```
Derives account or root xprvs from a seed.

USAGE:
    seed-utils xprv [FLAGS] [OPTIONS] <seed>

FLAGS:
    -h, --help       Prints help information
    -r, --root       Derives xprv at bip32 root instead of account level
    -V, --version    Prints version information

OPTIONS:
    -i, --index <index>      Index to derive xprv at [default: 0]
    -n, --number <number>    Number of xprvs to derive, starting from index [default: 1]
    -t, --type <type>        Type of xprv to return [default: zprv]  [possible values: xprv, yprv, zprv]

ARGS:
    <seed>    Seed to derive xprvs from
```
### `xpub` subcommand:
```
Derives account or root xpubs from a seed.

USAGE:
    seed-utils xpub [FLAGS] [OPTIONS] <seed>

FLAGS:
    -h, --help       Prints help information
    -r, --root       Derives xpub at bip32 root instead of account level
    -V, --version    Prints version information

OPTIONS:
    -i, --index <index>      Index to derive xpub at [default: 0]
    -n, --number <number>    Number of xpubs to derive, starting from index [default: 1]
    -t, --type <type>        Type of xpub to return [default: zpub]  [possible values: xpub, ypub, zpub]

ARGS:
    <seed>    Seed to derive xpubs from
```


 ## Useful resources
 - Online tool: https://iancoleman.io/bip39/
 - bip32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 - bip39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 - bip85: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki