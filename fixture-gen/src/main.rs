//! `fixture-gen` — deterministic FROST fixture generator.
//!
//! Drives the Zcash Foundation `frost-secp256k1-tr` crate (and its non-TR
//! sibling) through full DKG/sign/aggregate ceremonies with a seeded RNG and
//! captures every intermediate value plus every consumed random byte. The
//! resulting JSON is the byte-equality oracle for the `frots` TypeScript port.
//!
//! See `~/projects/frots/PLAN.md` Step 1 for the design rationale.

mod ceremony;
mod fixture;
mod recording_rng;

use std::fs;
use std::path::Path;

use frost_secp256k1_tr::{Ciphersuite, Secp256K1Sha256TR};

fn main() {
    println!("fixture-gen {}", env!("CARGO_PKG_VERSION"));
    println!("ciphersuite ID: {}", Secp256K1Sha256TR::ID);

    let fixtures_dir = Path::new("fixtures");
    if !fixtures_dir.exists() {
        fs::create_dir_all(fixtures_dir).expect("create fixtures dir");
    }

    let seed: [u8; 32] = [0u8; 32];

    let runs: &[(u16, u16, &str)] = &[
        (2, 3, "2of3"),
        (3, 5, "3of5"),
    ];

    let mut idx = 1;
    for &(min_signers, max_signers, label) in runs {
        let msg_dealer = format!("frots fixture-gen {} dealer -tr", label);
        let msg_dkg = format!("frots fixture-gen {} dkg -tr", label);

        println!("\n[{}] running {}-of-{} -tr dealer ceremony…", idx, min_signers, max_signers);
        idx += 1;
        let dealer = ceremony::run_dealer_tr(min_signers, max_signers, seed, msg_dealer.as_bytes());
        write_json(
            &fixtures_dir.join(format!("secp256k1_tr_{}_dealer.json", label)),
            &dealer,
            dealer.rng_log.len(),
        );

        println!("\n[{}] running {}-of-{} -tr DKG ceremony…", idx, min_signers, max_signers);
        idx += 1;
        let dkg = ceremony::run_dkg_tr(min_signers, max_signers, seed, msg_dkg.as_bytes());
        write_json(
            &fixtures_dir.join(format!("secp256k1_tr_{}_dkg.json", label)),
            &dkg,
            dkg.rng_log.len(),
        );
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T, rng_call_count: usize) {
    let json = serde_json::to_string_pretty(value).expect("serialize fixture");
    fs::write(path, &json).expect("write fixture");
    println!(
        "    wrote {} ({} bytes, {} rng calls)",
        path.display(),
        json.len(),
        rng_call_count,
    );
}
