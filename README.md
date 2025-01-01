# eth-stealth-gas-tickets

rust library implementing blind RSA signatures for gas tickets on ethereum to enable private gas sponsorship

this is an auxiliary part of a robust and user-friendly stealth addresses scheme

let's make privacy on evm chains a reality!

NOT AUDITED - HOMEROLLED CRYPTO - USE AT YOUR OWN RISK

## Usage

Add this library to your rust project with:

```
cargo add eth-stealth-gas-tickets
```

Use it:

```rust
use eth_stealth_gas_tickets::CoordinatorPubKey;
use rand::Rng;

fn main() {
    let pk_hex = "0xCoordinatorPubKeyFetchedFromChain";
    let pk = CoordinatorPubKey::from_hex_string(pk_hex).unwrap();

    let mut rng = rand::thread_rng();
    let blind_tickets = pk.new_blind_tickets(&mut rng, 5);

    println!("blind tickets: {:?}", blind_tickets);
}
```

a simple cli is forthcoming

## Test

```
cargo test
```

to test the core functionality of library

