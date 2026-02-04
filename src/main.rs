fn main() {
    println!("psbt-coordinator: 2-of-3 multisig PSBT toolkit");
    println!();
    println!("Available commands:");
    println!("  cargo run --bin keygen       Generate 3 key pairs");
    println!("  cargo run --bin coordinator  Create unsigned PSBT");
    println!("  cargo run --bin signer       Sign PSBT with a key");
    println!("  cargo run --bin finalizer    Finalize and extract TX");
}
