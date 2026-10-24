// SPDX-License-Identifier: Apache-2.0

//! Streams invocation-ABI verdicts for the cross-language differential
//! harness (`scripts/abi-differential.mjs`).
//!
//! Protocol: each stdin line carries one base64-encoded wire request; each
//! stdout line reports the Rust validator's verdict for that input, in
//! order — `accept`, or `reject<TAB><message>`. Every input line produces
//! exactly one output line, including an empty line (an empty wire is a
//! reject). Identical to `cmd/abi-verdict` on the Go side.

use std::io::{BufRead, Write};

use base64::Engine as _;
use nemo_crabedence_bridge::abi::validate_invocation_request;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin is readable");
        let wire = base64::engine::general_purpose::STANDARD
            .decode(line.trim_end())
            .expect("input line is base64");
        match validate_invocation_request(&wire) {
            Ok(()) => writeln!(out, "accept").expect("stdout is writable"),
            Err(error) => writeln!(out, "reject\t{error}").expect("stdout is writable"),
        }
    }
}
