//! `xtask check-go`: the Go half of `concord-tsnet` (`crates/tsnet/go`), which cargo does not
//! build: `gofmt`, `go vet` with and without the `ctstest` tag, and its tests, which drive the
//! library through cgo. A machine without `go` skips them and says so.

use std::io;
use std::path::Path;
use std::process::Command;

const DIR: &str = "crates/tsnet/go";

pub fn check() -> Result<(), String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(DIR);
    let version = match go(&dir).arg("version").output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            println!("check-go: skipped, no `go` on PATH, so {DIR} was neither vetted nor tested");
            return Ok(());
        }
        Err(err) => return Err(format!("go version: {err}")),
    };
    println!("check-go: {version}");
    let unformatted = Command::new("gofmt")
        .args(["-l", "."])
        .current_dir(&dir)
        .output()
        .map_err(|err| format!("gofmt: {err}"))?;
    let unformatted = String::from_utf8_lossy(&unformatted.stdout);
    if !unformatted.trim().is_empty() {
        return Err(format!("gofmt would change: {}", unformatted.trim()));
    }
    run(&dir, &["vet", "."])?;
    run(&dir, &["vet", "-tags", "ctstest", "."])?;
    run(&dir, &["test", "-count=1", "-tags", "ctstest", "."])
}

/// `go` as found on PATH: go.mod's `toolchain` line would otherwise have it download that
/// release first.
fn go(dir: &Path) -> Command {
    let mut command = Command::new("go");
    command.current_dir(dir).env("GOTOOLCHAIN", "local");
    command
}

fn run(dir: &Path, args: &[&str]) -> Result<(), String> {
    let status = go(dir)
        .args(args)
        .status()
        .map_err(|err| format!("go {}: {err}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("go {} failed in {DIR}", args.join(" ")))
    }
}
