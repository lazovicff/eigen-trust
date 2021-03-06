use clap::Parser;
use env_logger::Builder;
use std::str::FromStr;

use eigen_trust::{EigenError, Keypair, LevelFilter, Multiaddr, Node, PeerId};
use eigen_trust_circuit::utils::read_params;

const BOOTSTRAP_PEERS: [(&str, &str); 2] = [
	(
		"/ip4/127.0.0.1/tcp/58584",
		"12D3KooWLyTCx9j2FMcsHe81RMoDfhXbdyyFgNGQMdcrnhShTvQh",
	),
	(
		"/ip4/127.0.0.1/tcp/58601",
		"12D3KooWKBKXsLwbmVBySEmbKayJzfWp3tPCKrnDCsmNy9prwjvy",
	),
];

const DEFAULT_ADDRESS: &str = "/ip4/0.0.0.0/tcp/0";
const INTERVAL: u64 = 10;

#[derive(Parser, Debug)]
struct Args {
	#[clap(short, long)]
	key: Option<String>,
	#[clap(short, long)]
	address: Option<String>,
}

pub fn init_logger() {
	let mut builder = Builder::from_default_env();

	builder
		.filter(None, LevelFilter::Info)
		.format_timestamp(None)
		.init();
}

#[tokio::main]
async fn main() -> Result<(), EigenError> {
	init_logger();

	let args = Args::parse();

	// Taking the keypair from the command line or generating a new one.
	let local_key = if let Some(key) = args.key {
		let decoded_key = bs58::decode(&key)
			.into_vec()
			.map_err(|_| EigenError::InvalidKeypair)?;
		Keypair::from_protobuf_encoding(&decoded_key).map_err(|_| EigenError::InvalidKeypair)?
	} else {
		Keypair::generate_ed25519()
	};

	// Taking the address from the command line arguments or the default one.
	let local_address = if let Some(addr) = args.address {
		Multiaddr::from_str(&addr).map_err(|_| EigenError::InvalidAddress)?
	} else {
		Multiaddr::from_str(DEFAULT_ADDRESS).map_err(|_| EigenError::InvalidAddress)?
	};

	let mut bootstrap_nodes = Vec::new();
	for info in BOOTSTRAP_PEERS.iter() {
		// We can also contact the address.
		let peer_addr = Multiaddr::from_str(info.0).map_err(|_| EigenError::InvalidAddress)?;
		let peer_id = PeerId::from_str(info.1).map_err(|_| EigenError::InvalidPeerId)?;

		bootstrap_nodes.push((peer_id, peer_addr));
	}

	let params = read_params("../data/params-18.bin");
	let node = Node::new(local_key, local_address, bootstrap_nodes, INTERVAL, params)?;

	node.main_loop(None).await?;

	Ok(())
}
