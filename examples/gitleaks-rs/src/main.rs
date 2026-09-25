//! One JSON object in, one out, then exit (T1). Diagnostics go to stderr: a
//! stray line on stdout is indistinguishable from a response (T2).

use std::io::{self, Read, Write};

use rsp_gitleaks::gitleaks::Gitleaks;
use rsp_gitleaks::protocol::{respond, Request};
use rsp_gitleaks::Error;

fn main() {
    if let Err(error) = answer() {
        eprintln!("rsp-gitleaks-rs: {error}");
        std::process::exit(1);
    }
}

fn answer() -> Result<(), Error> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;
    let response = respond(&Gitleaks::from_env(), &request)?;

    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
