use alloy::primitives::{Bytes, FixedBytes};
use serde::{Deserialize, Serialize};

/// A ticket generated during the blinding process
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsignedTicket {
    pub msg: Bytes,
    pub blind_msg: Bytes,
    pub msg_randomizer: FixedBytes<32>,
    pub id: FixedBytes<32>,
    pub secret: Bytes,
}

/// A blind signature returned from the coordinator
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedSignature {
    pub blind_sig: Bytes,
    pub id: FixedBytes<32>,
}

/// A finalized signed ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedTicket {
    pub msg: Bytes,
    pub msg_randomizer: FixedBytes<32>,
    pub finalized_sig: Bytes,
    pub id: FixedBytes<32>,
}
