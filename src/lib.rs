mod types;

use alloy::primitives::{Bytes, FixedBytes};
use blind_rsa_signatures::reexports::rsa::BigUint;
use blind_rsa_signatures::reexports::rsa::PublicKeyParts;
use blind_rsa_signatures::reexports::rsa::RsaPublicKey as BlindRsaPublicKey;
use blind_rsa_signatures::{
    BlindSignature, MessageRandomizer, Options, PublicKey, Secret, Signature,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::error::Error;
pub use types::{BlindedSignature, SignedTicket, UnsignedTicket};

/// Custom error for the library
#[derive(Debug)]
pub enum CoordPubKeyError {
    BlindingFailed(String),
    FinalizationFailed(String),
    VerificationFailed(String),
    LengthMismatch,
    IdMismatch,
}

impl std::fmt::Display for CoordPubKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordPubKeyError::BlindingFailed(e) => write!(f, "Blinding failed: {}", e),
            CoordPubKeyError::FinalizationFailed(e) => write!(f, "Finalization failed: {}", e),
            CoordPubKeyError::VerificationFailed(e) => write!(f, "Verification failed: {}", e),
            CoordPubKeyError::LengthMismatch => write!(f, "Mismatched lengths between inputs"),
            CoordPubKeyError::IdMismatch => {
                write!(f, "ID mismatch between ticket and blind signature")
            }
        }
    }
}

impl Error for CoordPubKeyError {}

/// Represents a Coordinator's public key for blind signature operations
pub struct CoordinatorPubKey {
    pub_key: PublicKey,
}

impl CoordinatorPubKey {
    /// Create a new CoordinatorPubKey from a raw `PublicKey`
    pub fn new(pub_key: PublicKey) -> Self {
        Self { pub_key }
    }

    /// Create a CoordinatorPubKey from a hex string
    pub fn from_hex_string(hex_key: &str) -> Result<Self, CoordPubKeyError> {
        // Remove the "0x" prefix
        let hex = hex_key.trim_start_matches("0x");

        // Extract the exponent (first 6 hex characters) and modulus (rest)
        let exponent_hex = &hex[0..6]; // e is typically 0x010001
        let modulus_hex = &hex[8..];

        // Decode hex strings into bytes
        let exponent_bytes = hex::decode(exponent_hex).expect("Invalid exponent hex");
        let modulus_bytes = hex::decode(modulus_hex).expect("Invalid modulus hex");

        // Convert bytes to BigUint
        let exponent = BigUint::from_bytes_be(&exponent_bytes);
        let modulus = BigUint::from_bytes_be(&modulus_bytes);

        // Construct the DER representation for the public key
        let blind_key = BlindRsaPublicKey::new(modulus, exponent).expect("Failed to convert key");

        let pub_key = PublicKey(blind_key);
        Ok(Self { pub_key })
    }

    pub fn to_hex_string(&self) -> String {
        // Get the modulus (n) and exponent (e)
        let modulus = self.pub_key.n().to_bytes_be();
        let exponent = self.pub_key.e().to_bytes_be();

        // Convert modulus and exponent to hex
        let modulus_hex = hex::encode(modulus);
        let exponent_hex = hex::encode(exponent);

        // Concatenate exponent and modulus with a 0x prefix
        format!("0x{}00{}", exponent_hex, modulus_hex)
    }

    /// Generate new blind tickets
    pub fn new_blind_tickets<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        count: usize,
    ) -> Result<Vec<UnsignedTicket>, CoordPubKeyError> {
        let mut tickets = Vec::new();
        let options = Options::default();

        for _ in 0..count {
            // Generate a random 32-byte message
            let mut msg = vec![0u8; 32];
            rng.fill_bytes(&mut msg);

            // Blind the message
            let blinding_result = self
                .pub_key
                .blind(rng, &msg, true, &options)
                .map_err(|e| CoordPubKeyError::BlindingFailed(format!("{:?}", e)))?;

            // Compute the ID (sha256 hash of the blind message)
            let mut hasher = Sha256::new();
            hasher.update(&blinding_result.blind_msg);
            let id = FixedBytes::from_slice(&hasher.finalize());

            let msg_randomizer = match blinding_result.msg_randomizer {
                Some(r) => FixedBytes::from_slice(r.as_ref()),
                None => FixedBytes::from_slice(&[0; 32]),
            };

            tickets.push(UnsignedTicket {
                msg: Bytes::copy_from_slice(&msg),
                blind_msg: Bytes::copy_from_slice(&blinding_result.blind_msg),
                msg_randomizer: msg_randomizer,
                id: id,
                secret: Bytes::copy_from_slice(&blinding_result.secret),
            });
        }

        Ok(tickets)
    }

    /// Finalize blind signatures into signed tickets
    pub fn finalize_tickets(
        &self,
        tickets: Vec<UnsignedTicket>,
        blind_signatures: Vec<BlindedSignature>,
    ) -> Result<Vec<SignedTicket>, CoordPubKeyError> {
        if tickets.len() != blind_signatures.len() {
            return Err(CoordPubKeyError::LengthMismatch);
        }

        let options = Options::default();
        let mut signed_tickets = Vec::new();

        for (ticket, blind_sig) in tickets.into_iter().zip(blind_signatures.into_iter()) {
            if ticket.id != blind_sig.id {
                return Err(CoordPubKeyError::IdMismatch);
            }

            let sig = BlindSignature(blind_sig.blind_sig.to_vec());
            let secret = Secret(ticket.secret.to_vec());
            let msg = ticket.msg.to_vec();
            let msg_randomizer = {
                let raw = ticket.msg_randomizer.to_vec();
                if raw.iter().all(|&b| b == 0) {
                    None
                } else {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&raw);
                    Some(MessageRandomizer(arr))
                }
            };

            let finalized_sig = self
                .pub_key
                .finalize(&sig, &secret, msg_randomizer, &msg, &options)
                .map_err(|e| CoordPubKeyError::FinalizationFailed(format!("{:?}", e)))?;

            signed_tickets.push(SignedTicket {
                msg: ticket.msg,
                msg_randomizer: ticket.msg_randomizer,
                finalized_sig: Bytes::copy_from_slice(&finalized_sig),
                id: blind_sig.id,
            });
        }

        Ok(signed_tickets)
    }

    pub fn verify_signed_ticket(
        &self,
        signed_ticket: SignedTicket,
        options: &Options,
    ) -> Result<(), CoordPubKeyError> {
        let sig = Signature(signed_ticket.finalized_sig.to_vec());
        let msg = signed_ticket.msg.to_vec();
        let msg_randomizer = {
            let raw = signed_ticket.msg_randomizer.to_vec();
            if raw.iter().all(|&b| b == 0) {
                None
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                Some(MessageRandomizer(arr))
            }
        };

        self.pub_key
            .verify(&sig, msg_randomizer, &msg, options)
            .map_err(|_| CoordPubKeyError::VerificationFailed("Invalid signature".to_string()))?;

        Ok(())
    }

    /// Verify signed tickets
    pub fn verify_signed_tickets(
        &self,
        signed_tickets: Vec<SignedTicket>,
    ) -> Result<(), CoordPubKeyError> {
        let options = Options::default();
        for ticket in signed_tickets {
            self.verify_signed_ticket(ticket, &options)?;
        }

        Ok(())
    }

    pub fn get_options() -> Options {
        Options::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::KeyPair;
    use rand::thread_rng;

    #[test]
    fn test_coordinatorpubkey_from_hex_string() {
        // Generate a keypair and extract the public key
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng, 2048).unwrap();
        let pub_key = kp.pk;

        // Convert public key to hex
        let modulus = pub_key.n().to_bytes_be();
        let exponent = pub_key.e().to_bytes_be();
        let hex_key = format!("0x{}00{}", hex::encode(exponent), hex::encode(modulus));

        // Create CoordinatorPubKey from hex
        let coordinator_pubkey = CoordinatorPubKey::from_hex_string(&hex_key)
            .expect("Failed to parse public key from hex");

        // Ensure the modulus and exponent match
        assert_eq!(coordinator_pubkey.pub_key.n(), pub_key.n());
        assert_eq!(coordinator_pubkey.pub_key.e(), pub_key.e());
    }

    #[test]
    fn test_new_blind_tickets() {
        // Setup CoordinatorPubKey
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng, 2048).unwrap();
        let coordinator = CoordinatorPubKey::new(kp.pk);

        // Generate blind tickets
        let tickets = coordinator
            .new_blind_tickets(&mut rng, 5)
            .expect("Failed to generate blind tickets");

        // Validate tickets
        assert_eq!(tickets.len(), 5);
        for ticket in tickets {
            assert!(!ticket.msg.is_empty());
            assert!(!ticket.blind_msg.is_empty());
            assert!(!ticket.msg_randomizer.is_zero());
            assert!(!ticket.id.is_zero());
            assert!(!ticket.secret.is_empty());
        }
    }

    #[test]
    fn test_finalize_tickets() {
        // Setup CoordinatorPubKey
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng, 2048).unwrap();
        let priv_key = kp.sk;
        let coordinator = CoordinatorPubKey::new(kp.pk);

        // Generate blind tickets
        let tickets = coordinator
            .new_blind_tickets(&mut rng, 3)
            .expect("Failed to generate blind tickets");

        // Sign the blind messages
        let mut blind_signatures = Vec::new();
        for ticket in &tickets {
            let blind_sig = priv_key
                .blind_sign(&mut rng, ticket.blind_msg.as_ref(), &Options::default())
                .expect("Failed to sign blind message");

            blind_signatures.push(BlindedSignature {
                blind_sig: Bytes::copy_from_slice(&blind_sig),
                id: ticket.id.clone(),
            });
        }

        // Finalize tickets
        let signed_tickets = coordinator
            .finalize_tickets(tickets, blind_signatures)
            .expect("Failed to finalize tickets");

        // Validate signed tickets
        assert_eq!(signed_tickets.len(), 3);
        for signed_ticket in &signed_tickets {
            assert!(!signed_ticket.msg.is_empty());
            assert!(!signed_ticket.msg_randomizer.is_zero());
            assert!(!signed_ticket.finalized_sig.is_empty());
            assert!(!signed_ticket.id.is_zero());
        }
    }

    #[test]
    fn test_verify_signed_tickets() {
        // Setup CoordinatorPubKey
        let mut rng = thread_rng();
        let kp = KeyPair::generate(&mut rng, 2048).unwrap();
        let priv_key = kp.sk;
        let coordinator = CoordinatorPubKey::new(kp.pk);

        // Generate blind tickets
        let tickets = coordinator
            .new_blind_tickets(&mut rng, 3)
            .expect("Failed to generate blind tickets");

        // Sign the blind messages
        let mut blind_signatures = Vec::new();
        for ticket in &tickets {
            let blind_sig = priv_key
                .blind_sign(&mut rng, ticket.blind_msg.as_ref(), &Options::default())
                .expect("Failed to sign blind message");

            blind_signatures.push(BlindedSignature {
                blind_sig: Bytes::copy_from_slice(&blind_sig),
                id: ticket.id.clone(),
            });
        }

        // Finalize tickets
        let signed_tickets = coordinator
            .finalize_tickets(tickets, blind_signatures)
            .expect("Failed to finalize tickets");

        // Verify signed tickets
        coordinator
            .verify_signed_tickets(signed_tickets)
            .expect("Verification failed");
    }
}
