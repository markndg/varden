fn main() -> Result<(), Box<dyn std::error::Error>> {
    varden::protect()?;
    println!("Varden Rust demo: only varden::protect() is required");

    match varden::process::Command::new("python")?
        .arg("-c")
        .arg("print('rust demo')")
        .arg("delete_database")
        .arg("prod-customer-db")
        .spawn() {
        Ok(_) => println!("Expected a block, but process ran"),
        Err(varden::Error::Blocked(result)) => {
            println!("Varden blocked the process as expected");
            println!("{:?}", result.decision);
        }
        Err(other) => return Err(Box::new(other)),
    }

    Ok(())
}
