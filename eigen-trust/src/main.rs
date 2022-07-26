use eigen_trust::{extract_pub_key, extract_sk_bytes, EigenError, Keypair};

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	generate_random_keypairs();
	Ok(())
}

fn generate_random_keypairs() {
	for _ in 0..7 {
		let kp = Keypair::generate_secp256k1();
		let sk_bytes = extract_sk_bytes(&kp).unwrap();
		let pk = extract_pub_key(&kp).unwrap();
		println!("{}", bs58::encode(sk_bytes).into_string());
		println!("{}", bs58::encode(pk.to_bytes()).into_string())
	}
}
