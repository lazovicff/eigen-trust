/// The number of neighbors the peer can have.
/// This is also the maximum number of peers that can be connected to the
/// node.
pub const MAX_NEIGHBORS: usize = 256;
/// Minimum score a peer can have.
pub const MIN_SCORE: f64 = 0.1;
/// List of predetermened bootstrap peers.
pub const BOOTSTRAP_PEERS: [&str; NUM_BOOTSTRAP_PEERS] = [
	"2745hHPZtf8prEv4TUSkLVhZN2tPW6KiYwRfC5yixfU9",
	"C1w5WRwb2G7Whykit4XSng7JMjKvpGudjH2qBUMYFYwu",
	"3kiiXA7hgMUmFh9TcmYXqJWU3WVUnjY4rFzQhNXyqt9H",
	"2XEDBFy8gh32c4F5TVGNRVKMo9NM7eYkXH7iJzf68Vs1",
	"FCKVrmoaXpoyPv9H8EiveWhUf8Greh3mSmkU81QXhRts",
];
/// The number of bootstrap peers.
pub const NUM_BOOTSTRAP_PEERS: usize = 5;
/// The score of a bootstrap peer.
pub const BOOTSTRAP_SCORE: f64 = 0.5;
/// The genesis epoch.
pub const GENESIS_EPOCH: u64 = 1234;
