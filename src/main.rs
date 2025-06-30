#![allow(unused_imports)]
#![feature(iter_chain)]
use base64::prelude::*;
use hex_literal::hex;
use rayon::prelude::*;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::BufRead;

#[derive(Debug)]
struct Item<'a> {
    name: &'a str,
    hashed_pw: String,
}

fn main() -> std::io::Result<()> {
    let pws_str =
        std::fs::read_to_string("./pws.json").unwrap();
    let pws_root: Value =
        serde_json::from_str(&pws_str).unwrap();
    let additional_logins: Vec<(&str, &str)> = vec![];

    let items: Vec<Item> = pws_root
        .get("items")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .flat_map(
            |item| {
                let pw = item
                    .get("login")
                    .and_then(|v| v.get("password"))?
                    .as_str()?;
                let name = item
                    .get("name")?
                    .as_str()?;
                Some((
                    name, pw,
                ))
            },
        )
        .chain(additional_logins)
        .map(
            |(name, pw)| {
                let mut hasher = Sha1::new();
                hasher.update(pw.as_bytes());
                let hashed_pw = hasher
                    .finalize()
                    .iter()
                    .map(|b| {
                        format!(
                            "{:02X}",
                            b
                        )
                    })
                    .collect::<String>();
                Item {
                    name,
                    hashed_pw,
                }
            },
        )
        .collect::<Vec<_>>();

    // let file = std::fs::File::open(
    //     "/home/kdcadet/data/pwnedpasswords.txt",
    // )?;
    let file = std::fs::File::open("./pwned.txt")?;
    let reader = std::io::BufReader::new(file);

    reader
        .lines()
        .par_bridge()
        .flat_map(|line| line)
        .for_each(
            |line| {
                let (hash, times_seen) = line
                    .split_once(":")
                    .unwrap();
                for item in items.iter() {
                    if item.hashed_pw == hash {
                        println!(
                            "Login for {} seen {}",
                            item.name, times_seen
                        );
                    }
                }
            },
        );

    Ok(())
}
