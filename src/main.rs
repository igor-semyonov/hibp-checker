use anyhow::{Context, Result};
use rayon::prelude::*;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::io::BufRead;

#[derive(Debug)]
struct PwItem {
    name: String,
    hashed_pw: String,
}

fn main() -> Result<()> {
    let pws_jsons = vec![
        "/home/igor/data/bitwarden-my-vault.json",
        "/home/igor/data/bitwarden-asf.json",
        "/home/igor/data/bitwarden-nalgor.json",
    ];
    let additional_logins: Vec<(
        String,
        String,
    )> = std::fs::read_to_string("./additional-logins.csv")
        .unwrap()
        .lines()
        .into_iter()
        .map(
            |line| {
                let mut line_items = line.split(",");
                let name = line_items
                    .next()
                    .unwrap()
                    .to_owned();
                let pw = line_items
                    .next()
                    .unwrap()
                    .to_owned();
                (
                    name, pw,
                )
            },
        )
        .collect();

    let pw_items: Vec<PwItem> = pws_jsons
        .into_iter()
        .flat_map(
            |pws_json| {
                let pws_str =
                    std::fs::read_to_string(pws_json)
                    .context(format!("Could not read json passwords file {}", pws_json)).unwrap();
                serde_json::from_str::<Value>(&pws_str)
                    .unwrap()
                    .get("items")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(
                        |item| {
                            let pw = item
                                .get("login")
                                .and_then(|v| {
                                    v.get("password")
                                })?
                                .as_str()?;
                            let name = item
                                .get("name")?
                                .as_str()?;
                            Some((
                                name.to_owned(), pw.to_owned(),
                            ))
                        },
                    )
                    .collect::<Vec<_>>()
            },
        )
        .chain(additional_logins)
        .map(
            |(name, pw)| {
                PwItem {
                    name: name,
                    hashed_pw: hash_pw(&pw)
                }
            },
        )
        .collect();

    std::fs::read_dir("/home/igor/data/pwnedpasswords")?
        .into_iter()
        .flat_map(|entry| entry)
        .map(|entry| entry.path())
        .par_bridge()
        .for_each(
            |hash_file| {
                let file =
    
    std::fs::File::open(hash_file).unwrap();
                let reader =
    std::io::BufReader::new(file);             reader
                .lines()
                .flat_map(|line| line)
                .for_each(
                    |line| {
                        let (hash, times_seen) = line
                            .split_once(":")
                            .unwrap();
                        for pw_item in pw_items.iter() {
                            if pw_item.hashed_pw == hash {
                                println!(
                                    "Login for {} seen
    {}",                                 pw_item.name,
    times_seen                             );
                            }
                        }
                    },
                );
            },
        );

    Ok(())
}

fn hash_pw(pw: &str) -> String {
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
