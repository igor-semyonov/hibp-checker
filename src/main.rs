#![feature(iter_array_chunks)]
use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::io::BufRead;
use std::path::PathBuf;
// use indicatif::ParallelProgressIterator;

#[derive(Parser, Debug)]
struct Args {
    #[arg(
        long,
        short,
        default_value = "/home/igor/data/pwnedpasswords-dotnet"
    )]
    pwned_passwords_dir: Box<std::path::Path>,
    #[arg(
        short, long,
        num_args = 1..,
    )]
    bitwarden_jsons: Vec<PathBuf>,
}

#[derive(Debug)]
struct PwItem {
    name: String,
    username: String,
    password: String,
    hashed_password: String,
}


fn main() -> Result<()> {
    let args = Args::parse();

    let pws_jsons = args.bitwarden_jsons;
    let additional_logins: Vec<(
        String,
        String,
        String,
    )> = std::fs::read_to_string("./additional-logins.csv")
        .unwrap()
        .lines()
        .map(
            |line| {
                let mut line_items = line.split(",");
                let name = line_items
                    .next()
                    .unwrap()
                    .to_owned();
                let username = line_items
                    .next()
                    .unwrap()
                    .to_owned();
                let password = line_items
                    .next()
                    .unwrap()
                    .to_owned();
                (
                    name, username, password,
                )
            },
        )
        .collect();

    let pw_items: Vec<PwItem> = pws_jsons
        .into_iter()
        .flat_map(
            |pws_json| {
                let pws_str =
                    std::fs::read_to_string(&pws_json)
                        .context(
                            format!("Could not read json passwords file {pws_json:?}"),
                        )
                        .unwrap();
                serde_json::from_str::<Value>(&pws_str)
                    .unwrap()
                    .get("items")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(
                        |item| {
                            let username = item
                                .get("login")
                                .and_then(|v| {
                                    v.get("username")
                                })?
                                .as_str()?;
                            let password = item
                                .get("login")
                                .and_then(|v| {
                                    v.get("password")
                                })?
                                .as_str()?;
                            let name = item
                                .get("name")?
                                .as_str()?;
                            Some((
                                name.to_owned(),
                                username.to_owned(),
                                password.to_owned(),
                            ))
                        },
                    )
                    .collect::<Vec<_>>()
            },
        )
        .chain(additional_logins)
        .map(
            |(name, username, password)| PwItem {
                name: name,
                username: username,
                password: password.clone(),
                hashed_password: hash_password(&password),
            },
        )
        .collect();

    args
        .pwned_passwords_dir
        .read_dir()?
        .into_iter()
        .flatten()
        .map(|entry| entry.path())
        .par_bridge()
        .for_each(
            |hash_file| {
                let file =
                    std::fs::File::open(hash_file).unwrap();
                let reader = std::io::BufReader::new(file);
                reader
                    .lines()
                    .flatten()
                    .for_each(
                        |line| {
                            let (hash, times_seen) = line
                                .split_once(":")
                                .unwrap();
                            for pw_item in pw_items.iter() {
                                let (_, tail) = pw_item.hashed_password.split_at(5);
                                if tail == hash
                                {
                                    println!(
                                        "Login for {} with username {} and password {} seen {}",
                                        pw_item.name,
                                        pw_item.username,
                                        pw_item.password,
                                        times_seen
                                    );
                                }
                            }
                        },
                    );
            }
        );

    Ok(())
}

fn hash_password(pw: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(pw.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| {
            format!(
                "{:02X}",
                b
            )
        })
        .collect()
}
