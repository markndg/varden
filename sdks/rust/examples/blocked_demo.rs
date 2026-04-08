fn main() -> Result<(), Box<dyn std::error::Error>> {
    sentinel::protect()?;
    println!("Sentinel Rust demo: only sentinel::protect() is required");

    match sentinel::process::Command::new("python")?
        .arg("-c")
        .arg("print('rust demo')")
        .arg("delete_database")
        .arg("prod-customer-db")
        .spawn() {
        Ok(_) => println!("Expected a block, but process ran"),
        Err(sentinel::Error::Blocked(result)) => {
            println!("Sentinel blocked the process as expected");
            println!("{:?}", result.decision);
        }
        Err(other) => return Err(Box::new(other)),
    }

    Ok(())
}
