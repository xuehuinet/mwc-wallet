// Copyright 2020 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::ErrorKind;
use grin_util::secp::key::SecretKey;
use grin_wallet_libwallet::proof::message::EncryptedMessage;
use grin_wallet_libwallet::proof::proofaddress;
use grinswap::swap::message::Message;

/// SwapMessage, communicated through MQS between swap maker & taker
pub struct SwapMessage {
	/// Private key to decrypt the message
	pub key: [u8; 32],
}

impl SwapMessage {
	/// decrypt message received from MQS
	pub fn from_response(
		from: &proofaddress::ProvableAddress,
		message: String,
		_challenge: String,
		_signature: String,
		secret_key: &SecretKey,
	) -> Result<Message, ErrorKind> {
		let public_key = from.public_key().map_err(|e| {
			ErrorKind::SwapMessageGenericError(format!(
				"Unable to build public key for address {}, {}",
				from, e
			))
		})?;

		let encrypted_message: EncryptedMessage = serde_json::from_str(&message).map_err(|e| {
			ErrorKind::SwapMessageGenericError(format!(
				"Failed to convert Json to EncryptedMessage {}, {}",
				message, e
			))
		})?;

		let key = encrypted_message
			.key(&public_key, secret_key)
			.map_err(|e| {
				ErrorKind::SwapMessageGenericError(format!("Unable to build a signature, {}", e))
			})?;

		let decrypted_message = encrypted_message.decrypt_with_key(&key).map_err(|e| {
			ErrorKind::SwapMessageGenericError(format!("Unable to decrypt message, {}", e))
		})?;

		let swap: Message = serde_json::from_str(&decrypted_message).map_err(|e| {
			ErrorKind::SwapMessageGenericError(format!(
				"Unable to build Swap Message from mqs message, {}",
				e
			))
		})?;

		Ok(swap)
	}
}
