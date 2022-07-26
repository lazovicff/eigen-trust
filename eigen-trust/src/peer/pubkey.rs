use super::utils::{extract_pub_key, to_wide};
use crate::EigenError;
use eigen_trust_circuit::halo2wrong::curves::{bn256::Fr as Bn256Scalar, FieldExt};
use libp2p::core::identity::Keypair as IdentityKeypair;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pubkey(Bn256Scalar);

impl Pubkey {
	pub fn from_keypair(keypair: &IdentityKeypair) -> Result<Self, EigenError> {
		let pubkey = extract_pub_key(keypair)?;
		Ok(Self(pubkey))
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		let pubkey = Bn256Scalar::from_bytes_wide(&to_wide(bytes));
		Self(pubkey)
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.0.to_bytes()
	}

	pub fn value(&self) -> Bn256Scalar {
		self.0
	}
}
