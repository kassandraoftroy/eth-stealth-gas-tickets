# eth-stealth-gas-tickets

rust library implementing blind RSA signatures for gas tickets on ethereum to enable private gas sponsorship.

private gas sponsorship is a tool that supports robust and user-friendly stealth addresses on ethereum. see related eth-stealth-addresses lib [here](https://github.com/kassandraoftroy/eth-stealth-addresses)

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

cli is forthcoming!

## Test

```
cargo test
```

to test the core functionality of library

