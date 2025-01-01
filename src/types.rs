use serde::{Deserialize, Serialize};

/// A ticket generated during the blinding process
#[derive(Debug, Serialize, Deserialize)]
pub struct UnsignedTicket {
    pub msg: String,
    pub blind_msg: String,
    pub msg_randomizer: String,
    pub id: String,
    pub secret: String,
}

/// A blind signature returned from the coordinator
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedSignature {
    pub blind_sig: String,
    pub id: String,
}

/// A finalized signed ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedTicket {
    pub msg: String,
    pub msg_randomizer: String,
    pub finalized_sig: String,
    pub id: String,
}
