// Copyright 2019 The vault713 Developers
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

use super::error::ErrorKind;
use super::message::Message;
use super::swap::Swap;
use super::types::{Action, Context, Currency};
use super::Keychain;
use crate::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};
use crate::swap::types::SwapTransactionsConfirmations;
use crate::NodeClient;
use grin_core::global;
use grin_keychain::Identifier;

/// Swap API trait that is used by both Buyer and Seller.
/// Every currency that Swap want to support, need to implement
/// this trait. Current we have only implementaiton: api::BtcSwapApi
pub trait SwapApi<K: Keychain>: Sync + Send {
	/// Number of the keys at the create_context, keys (For BTC it is 4)
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
	) -> Result<usize, ErrorKind>;

	/// Creating buyer/seller context. Keys are used to generate this session secrets.
	/// Number of them defined by context_key_count
	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>, // inputs with amounts that sellect is agree to use.
		change_amount: u64,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind>;

	/// Seller creates a swap offer and creates the core Swap Object.
	/// It is a starting point for Seller swap workflow
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		primary_amount: u64,   // mwc amount to sell
		secondary_amount: u64, // btc amount to buy
		secondary_currency: Currency,
		secondary_redeem_address: String, // redeed address for BTC
		seller_lock_first: bool,
		required_mwc_lock_confirmations: u64, // Needed conformation numbers for mwc & btc
		required_secondary_lock_confirmations: u64,
		mwc_lock_time_seconds: u64,
		seller_redeem_time: u64,
	) -> Result<(Swap, Action), ErrorKind>;

	/// Buyer accepts a swap offer and creates the core Swap Object.
	/// It is a starting point for Buyer swap workflow.
	fn accept_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		message: Message, // Income message with offer form the Seller. Seller Status  Created->Offered
	) -> Result<(Swap, Action), ErrorKind>;

	/// Check if redeem step is completed. If yes - State will be move to 'Completed'
	fn completed(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	/// Execute refund. Refund can be executed if swap trade is cancelled. automatically or
	/// by timeout (Waiting process must be limited to some point)
	fn refunded(
		&mut self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
		fee_satoshi_per_byte: Option<f32>,
	) -> Result<(), ErrorKind>;

	/// Cancel the trade. Other party need to be notified with higher level channel.
	/// It is not mwc-wallet responsibility to say nice good buy to other party.
	/// Wallet inplemention only swap logic related activity.
	fn cancelled(&mut self, keychain: &K, swap: &mut Swap) -> Result<(), ErrorKind>;

	/// Check which action should be taken by the user
	fn required_action(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind>;

	/// Producing message for another party. Message content is vary and depend on the current state
	fn message(&mut self, keychain: &K, swap: &Swap) -> Result<Message, ErrorKind>;

	/// Message has been sent to the counter-party, update state accordingly
	fn message_sent(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind>;

	/// Apply an update Message to the Swap
	fn receive_message(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<Action, ErrorKind>;

	/// Publish MWC transaction.
	/// Seller: publishing lock_slate, Status::Accepted
	/// Buyer:  publishing redeem_slate, Status::Redeem
	fn publish_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		retry: bool,
	) -> Result<Action, ErrorKind>;

	/// Publishing Secinadary (BTC) transactions
	/// Seller: redeep BTC transaction at State RedeemSecondary
	fn publish_secondary_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		fee_satoshi_per_byte: Option<f32>,
		retry: bool,
	) -> Result<Action, ErrorKind>;
}

/// Create an appropriate instance for the Currency
/// electrumx_uri - mandatory for BTC
/// Note: Result lifetime is equal of arguments lifetime!
pub fn create_instance<'a, C, K>(
	currency: &Currency,
	node_client: C,
) -> Result<Box<dyn SwapApi<K> + 'a>, ErrorKind>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	match currency {
		Currency::Btc => {
			let electrumx_uri = crate::swap::trades::get_electrumx_uri();
			if electrumx_uri.is_none() {
				return Err(ErrorKind::UndefinedElectrumXURI);
			}

			let btc_node_client = ElectrumNodeClient::new(
				electrumx_uri.expect("BTC API requires BTC node client"),
				!global::is_mainnet(),
			);
			Ok(Box::new(BtcSwapApi::new(node_client, btc_node_client)))
		}
	}
}
