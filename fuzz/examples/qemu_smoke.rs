//! Deterministic guest gate using exactly the cargo-fuzz adapter and decoder.

use anyhow::{bail, ensure, Result};
use nilix_fuzz::qemu_executor::{
    configured_executor, parse_fuzzer_input, ExecutionResult, SMOKE_INPUTS, ZERO_COVERAGE_INPUT,
};

fn main() -> Result<()> {
    if let Some(directory) = std::env::args_os().nth(1) {
        std::fs::create_dir_all(&directory)?;
        let directory = std::path::Path::new(&directory);
        for (name, input) in SMOKE_INPUTS {
            std::fs::write(directory.join(name), input)?;
        }
        std::fs::write(
            directory.join(ZERO_COVERAGE_INPUT.0),
            ZERO_COVERAGE_INPUT.1,
        )?;
        return Ok(());
    }

    let executor = configured_executor()?;
    for (name, input) in SMOKE_INPUTS {
        let program = parse_fuzzer_input(input)?;
        match executor.execute(&program)? {
            ExecutionResult::Success(coverage) => {
                let occupied = coverage.iter().filter(|&&byte| byte != 0).count();
                ensure!(occupied > 0, "{name}: empty guest coverage");
                println!("QEMU-FUZZ-SEED PASS name={name} occupied={occupied}");
            }
            result => bail!("{name}: {result:?}"),
        }
    }

    let (name, input) = ZERO_COVERAGE_INPUT;
    let program = parse_fuzzer_input(input)?;
    match executor.execute(&program)? {
        ExecutionResult::Success(coverage) => {
            let occupied = coverage.iter().filter(|&&byte| byte != 0).count();
            ensure!(occupied == 0, "{name}: expected zero coverage, got {occupied}");
            println!("QEMU-FUZZ-ZERO-SMOKE PASS name={name} occupied=0");
        }
        result => bail!("{name}: {result:?}"),
    }

    println!("QEMU-FUZZ-SMOKE PASS seeds={}", SMOKE_INPUTS.len() + 1);
    Ok(())
}
