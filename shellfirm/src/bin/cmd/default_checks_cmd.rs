use clap::{Arg, ArgMatches, Command};
use shellfirm::{checks, error::{Error, Result}, managed_checks, CmdExit};

pub fn command() -> Command {
    Command::new("default-checks")
        .about("Inspect or validate the default-check catalog without executing commands")
        .subcommand_required(true)
        .subcommand(Command::new("source").about("Print the compiled-in catalog source"))
        .subcommand(Command::new("status").about("Load and verify the configured catalog"))
        .subcommand(Command::new("validate").about("Validate a candidate catalog")
            .arg(Arg::new("file").required(true)))
}

pub fn run(matches: &ArgMatches) -> Result<CmdExit> {
    match matches.subcommand() {
        Some(("source", _)) => println!("{}", managed_checks::source()),
        Some(("status", _)) => {
            let checks = checks::get_all()?;
            println!("source: {}\nchecks: {}", managed_checks::source(), checks.len());
        }
        Some(("validate", args)) => {
            let file = args.get_one::<String>("file")
                .ok_or_else(|| Error::Config("catalog file is required".into()))?;
            let checks = managed_checks::parse(&std::fs::read_to_string(file)?)?;
            println!("Valid default-check catalog: {} checks", checks.len());
        }
        _ => return Err(Error::Config("unknown default-check command".into())),
    }
    Ok(CmdExit { code: exitcode::OK, message: None })
}
