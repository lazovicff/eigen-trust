//! The module for defining the request-response protocol.

use crate::{
	epoch::Epoch,
	peer::{opinion::Opinion, pubkey::Pubkey},
	EigenError,
};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{ProtocolName, RequestResponseCodec};
use std::io::{Error, ErrorKind, Result};

/// EigenTrust protocol struct.
#[derive(Debug, Clone, Default)]
pub struct EigenTrustProtocol {
	version: EigenTrustProtocolVersion,
}

impl EigenTrustProtocol {
	/// Create a new EigenTrust protocol.
	pub fn new() -> Self {
		Self {
			version: EigenTrustProtocolVersion::V1,
		}
	}
}

/// The version of the EigenTrust protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EigenTrustProtocolVersion {
	V1,
}

impl Default for EigenTrustProtocolVersion {
	fn default() -> Self {
		Self::V1
	}
}

/// The EigenTrust protocol codec.
#[derive(Clone, Debug, Default)]
pub struct EigenTrustCodec;

/// The EigenTrust protocol request struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
	Opinion(Epoch),
	Identify(Pubkey),
}

impl Request {
	/// Get the epoch of the request.
	pub fn get_epoch(&self) -> Option<Epoch> {
		match self {
			Self::Opinion(epoch) => Some(*epoch),
			_ => None,
		}
	}
}

/// The EigenTrust protocol response struct.
#[derive(Clone, Debug, PartialEq)]
pub enum Response {
	/// Successful response with an opinion.
	Opinion(Opinion),
	/// Successful response with a public key.
	Identify(Pubkey),
	/// Failed response, because of invalid request.
	InvalidRequest,
	/// Failed response, because of the internal error.
	InternalError(EigenError),
}

impl ProtocolName for EigenTrustProtocol {
	/// The name of the protocol.
	fn protocol_name(&self) -> &[u8] {
		match self.version {
			EigenTrustProtocolVersion::V1 => b"/eigen_trust/1.0.0",
		}
	}
}

#[async_trait]
impl RequestResponseCodec for EigenTrustCodec {
	type Protocol = EigenTrustProtocol;
	type Request = Request;
	type Response = Response;

	/// Read the request from the given stream.
	async fn read_request<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
	) -> Result<Self::Request>
	where
		T: AsyncRead + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let mut buf = [0; 1];
				io.read_exact(&mut buf).await?;
				match buf[0] {
					0 => {
						let mut k_buf = [0; 8];
						io.read_exact(&mut k_buf).await?;
						let k = u64::from_be_bytes(k_buf);
						Ok(Request::Opinion(Epoch(k)))
					},
					1 => {
						let mut pk_buf = [0; 32];
						io.read_exact(&mut pk_buf).await?;
						let pubkey = Pubkey::from_bytes(pk_buf);
						Ok(Request::Identify(pubkey))
					},
					_ => Err(Error::new(ErrorKind::InvalidData, "Invalid request")),
				}
			},
		}
	}

	/// Read the response from the given stream.
	async fn read_response<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
	) -> Result<Self::Response>
	where
		T: AsyncRead + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let mut buf = [0; 1];
				io.read_exact(&mut buf).await?;
				let response = match buf[0] {
					0 => {
						// Opinion
						let mut k_bytes = [0; 8];
						let mut op_bytes = [0; 8];
						let mut proof_bytes = Vec::new();

						io.read_exact(&mut k_bytes).await?;
						io.read_exact(&mut op_bytes).await?;
						io.read_to_end(&mut proof_bytes).await?;

						let k = u64::from_be_bytes(k_bytes);
						let op = f64::from_be_bytes(op_bytes);

						let epoch = Epoch(k);
						let opinion = Opinion::new(epoch, op, proof_bytes);

						Ok(Response::Opinion(opinion))
					},
					1 => {
						// Identify
						let mut pubkey_bytes = [0; 32];
						io.read_exact(&mut pubkey_bytes).await?;
						let pubkey = Pubkey::from_bytes(pubkey_bytes);
						Ok(Response::Identify(pubkey))
					},
					2 => Ok(Response::InvalidRequest),
					3 => {
						let mut err_code = [0; 1];
						io.read_exact(&mut err_code).await?;
						let err = EigenError::from(err_code[0]);
						Ok(Response::InternalError(err))
					},
					_ => Err(Error::new(ErrorKind::InvalidData, "Invalid response")),
				};
				response
			},
		}
	}

	/// Write the request to the given stream.
	async fn write_request<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
		req: Self::Request,
	) -> Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				match req {
					Request::Opinion(k) => {
						let mut bytes = vec![0];
						bytes.extend_from_slice(&k.to_be_bytes());
						io.write_all(&bytes).await?;
					},
					Request::Identify(pub_key) => {
						let mut bytes = vec![1];
						bytes.extend_from_slice(&pub_key.to_bytes());
						io.write_all(&bytes).await?;
					},
				}
				Ok(())
			},
		}
	}

	/// Write the response to the given stream.
	async fn write_response<T>(
		&mut self,
		protocol: &Self::Protocol,
		io: &mut T,
		res: Self::Response,
	) -> Result<()>
	where
		T: AsyncWrite + Unpin + Send,
	{
		match protocol.version {
			EigenTrustProtocolVersion::V1 => {
				let mut bytes = Vec::new();
				match res {
					Response::Opinion(opinion) => {
						bytes.push(0);

						// Opinion
						bytes.extend(opinion.epoch.to_be_bytes());
						bytes.extend(opinion.op.to_be_bytes());
						bytes.extend(opinion.proof_bytes);
					},
					Response::Identify(pub_key) => {
						bytes.push(1);
						bytes.extend_from_slice(&pub_key.to_bytes());
					},
					Response::InvalidRequest => bytes.push(2),
					Response::InternalError(code) => {
						bytes.push(3);
						bytes.push(code.into());
					},
				};
				io.write_all(&bytes).await?;
				Ok(())
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	impl Response {
		pub fn success(self) -> Opinion {
			match self {
				Response::Opinion(opinion) => opinion,
				_ => panic!("Response::success called on invalid response"),
			}
		}
	}

	#[tokio::test]
	async fn should_correctly_write_read_request() {
		let mut codec = EigenTrustCodec::default();
		let mut buf = vec![];
		let epoch = Epoch(1);
		let req = Request::Opinion(epoch);
		codec
			.write_request(&EigenTrustProtocol::default(), &mut buf, req)
			.await
			.unwrap();

		let mut bytes = vec![0];
		bytes.extend(epoch.to_be_bytes());
		assert_eq!(buf, bytes);

		let req = codec
			.read_request(&EigenTrustProtocol::default(), &mut &bytes[..])
			.await
			.unwrap();
		assert_eq!(req.get_epoch().unwrap(), epoch);
	}

	#[tokio::test]
	async fn should_correctly_write_read_success_response() {
		let opinion = Opinion::empty();
		let good_res = Response::Opinion(opinion.clone());

		let mut buf = vec![];
		let mut codec = EigenTrustCodec::default();
		codec
			.write_response(&EigenTrustProtocol::default(), &mut buf, good_res)
			.await
			.unwrap();

		let mut bytes = vec![];
		bytes.push(0);
		bytes.extend(opinion.epoch.to_be_bytes());
		bytes.extend(opinion.op.to_be_bytes());

		// compare the written bytes with the expected bytes
		assert_eq!(buf, bytes);

		let read_res = codec
			.read_response(&EigenTrustProtocol::default(), &mut &bytes[..])
			.await
			.unwrap();
		assert_eq!(read_res.success(), opinion);
	}

	#[tokio::test]
	async fn should_correctly_write_read_invalid_response() {
		// Testing invalid request
		let bad_res = Response::InvalidRequest;

		let mut buf = vec![];
		let mut codec = EigenTrustCodec::default();
		codec
			.write_response(&EigenTrustProtocol::default(), &mut buf, bad_res.clone())
			.await
			.unwrap();

		let mut bytes = vec![];
		bytes.push(2);
		assert_eq!(buf, bytes);

		let read_res = codec
			.read_response(&EigenTrustProtocol::default(), &mut &bytes[..])
			.await
			.unwrap();

		assert_eq!(read_res, bad_res);
	}

	#[tokio::test]
	async fn should_correctly_write_read_internal_error_response() {
		// Testing internal error
		let bad_res = Response::InternalError(EigenError::InvalidAddress);

		let mut buf = vec![];
		let mut codec = EigenTrustCodec::default();
		codec
			.write_response(&EigenTrustProtocol::default(), &mut buf, bad_res.clone())
			.await
			.unwrap();

		let mut bytes = vec![];
		// 3 is internal error code
		bytes.push(3);
		// 1 is invalid address error code
		bytes.push(1);
		assert_eq!(buf, bytes);

		let read_res = codec
			.read_response(&EigenTrustProtocol::default(), &mut &bytes[..])
			.await
			.unwrap();

		assert_eq!(read_res, bad_res);
	}
}
