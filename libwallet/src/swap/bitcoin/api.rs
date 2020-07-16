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

use super::client::BtcNodeClient;
use super::types::{BtcBuyerContext, BtcData, BtcSellerContext};
use crate::grin_util::secp::pedersen;
use crate::swap::bitcoin::types::BtcTtansaction;
use crate::swap::message::{Message, Update};
use crate::swap::types::{
	Action, BuyerContext, Context, Currency, Network, Role, RoleContext, SecondaryBuyerContext,
	SecondarySellerContext, SellerContext, Status, SwapTransactionsConfirmations,
};
use crate::swap::{BuyApi, ErrorKind, SellApi, Swap, SwapApi};
use crate::{NodeClient, Slate};
use bitcoin::{Address, Script};
use bitcoin_hashes::sha256d;
use chrono::Utc;
use grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::aggsig::export_secnonce_single as generate_nonce;
use std::str::FromStr;

/// SwapApi trait implementaiton for BTC
pub struct BtcSwapApi<C, B>
where
	C: NodeClient,
	B: BtcNodeClient,
{
	/// Client for MWC node
	node_client: C,
	/// Client for BTC electrumx node
	btc_node_client: B,
}

impl<C, B> BtcSwapApi<C, B>
where
	C: NodeClient,
	B: BtcNodeClient,
{
	/// Create BTC Swap API instance
	pub fn new(node_client: C, btc_node_client: B) -> Self {
		Self {
			node_client,
			btc_node_client,
		}
	}

	/// Update swap.secondary_data with a roll back script.
	fn script<K: Keychain>(&self, keychain: &K, swap: &Swap) -> Result<Script, ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc()?;
		Ok(btc_data.script(
			keychain.secp(),
			swap.redeem_public
				.as_ref()
				.ok_or(ErrorKind::UnexpectedAction(
					"swap.redeem_public value is not defined. Method BtcSwapApi::script"
						.to_string(),
				))?,
			swap.get_time_btc_lock(),
		)?)
	}

	/// Check BTC amount at the chain.
	fn btc_balance<K: Keychain>(
		&mut self,
		_keychain: &K,
		swap: &mut Swap,
		input_script: &Script,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64), ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let address = btc_data.address(input_script, swap.network)?;
		let outputs = self.btc_node_client.unspent(&address)?;
		let height = self.btc_node_client.height()?;
		let mut pending_amount = 0;
		let mut confirmed_amount = 0;
		let mut least_confirmations = None;

		let mut confirmed_outputs = Vec::new();

		for output in outputs {
			if output.height == 0 {
				// Output in mempool
				least_confirmations = Some(0);
				pending_amount += output.value;
			} else {
				let confirmations = height.saturating_sub(output.height) + 1;
				if confirmations >= confirmations_needed {
					// Enough confirmations
					confirmed_amount += output.value;
					confirmed_outputs.push(output);
				} else {
					// Not yet enough confirmations
					if least_confirmations
						.map(|least| confirmations < least)
						.unwrap_or(true)
					{
						least_confirmations = Some(confirmations);
					}
					pending_amount += output.value;
				}
			}
		}

		confirmed_outputs.sort_by(|a, b| a.out_point.txid.cmp(&b.out_point.txid));

		btc_data.confirmed_outputs = confirmed_outputs;

		Ok((
			pending_amount,
			confirmed_amount,
			least_confirmations.unwrap_or(0),
		))
	}

	// Seller specific methods

	/// Seller checks MWC and Bitcoin chains for the locked funds
	/// Return Ok(None) if everything is ready. Otherwise it is action.
	fn seller_check_locks<K: Keychain>(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		input_script: &Script,
	) -> Result<Option<Action>, ErrorKind> {
		//  Check if Lock slate is ready and confirmed.
		if !swap.seller_lock_first {
			// Check first if BTC are deposited and have at least 1 confirmation is made
			// We don't want wait for long time because we don;t want to interrupt the process for a long time
			let need_conf = 1; //  std::cmp::max(1, swap.secondary_confirmations / 10);

			let (pending_amount, confirmed_amount, mut least_confirmations) =
				self.btc_balance(keychain, swap, &input_script, need_conf)?;
			if pending_amount + confirmed_amount < swap.secondary_amount {
				least_confirmations = 0;
			};

			if confirmed_amount < swap.secondary_amount {
				return Ok(Some(Action::ConfirmationsSecondary {
					currency: swap.secondary_currency,
					required: need_conf,
					actual: least_confirmations,
				}));
			}
		}

		if !swap.is_mwc_locked() {
			match swap.lock_confirmations {
				None => return Ok(Some(Action::PublishTx)),
				Some(_) => {
					swap.update_mwc_lock_confirmations(keychain.secp(), &self.node_client)?;
					if !swap.is_mwc_locked() {
						return Ok(Some(Action::Confirmations {
							required: swap.mwc_confirmations,
							actual: swap.lock_confirmations.unwrap(),
						}));
					}
				}
			};
		}

		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			// Waiting for Btc confirmations
			let (pending_amount, confirmed_amount, mut least_confirmations) =
				self.btc_balance(keychain, swap, &input_script, swap.secondary_confirmations)?;
			if pending_amount + confirmed_amount < swap.secondary_amount {
				least_confirmations = 0;
			};

			if confirmed_amount < swap.secondary_amount {
				return Ok(Some(Action::ConfirmationsSecondary {
					currency: swap.secondary_currency,
					required: swap.secondary_confirmations,
					actual: least_confirmations,
				}));
			}

			swap.secondary_data.unwrap_btc_mut()?.locked = true;
		}

		// If we got here, funds have been locked on both chains with sufficient confirmations
		swap.status = Status::Locked;

		Ok(None)
	}

	/// Seller applies an update message to the Swap
	fn seller_receive_message<K: Keychain>(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::Offered => self.seller_accepted_offer(keychain, swap, context, message),
			Status::Accepted | Status::Locked => {
				self.seller_init_redeem(keychain, swap, context, message)
			}
			_ => Err(ErrorKind::UnexpectedMessageType(format!(
				"seller_receive_message get unexpected status {:?}",
				swap.status
			))),
		}
	}

	/// Seller applies accepted offer message from buyer to the swap
	fn seller_accepted_offer<K: Keychain>(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, accept_offer, secondary_update) = message.unwrap_accept_offer()?;
		let btc_update = secondary_update.unwrap_btc()?.unwrap_accept_offer()?;

		SellApi::accepted_offer(keychain, swap, context, accept_offer)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.accepted_offer(btc_update)?;

		Ok(())
	}

	/// Seller applies accepted offer message from buyer to the swap
	fn seller_init_redeem<K: Keychain>(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, init_redeem, _) = message.unwrap_init_redeem()?;
		// Expected that mwc & btc are already locked at that moment
		SellApi::init_redeem(keychain, swap, context, init_redeem)?;

		Ok(())
	}

	/// Seller builds the transaction to redeem their Bitcoins, Status::Redeem
	/// Updating data:  swap.secondary_data.redeem_tx
	fn seller_build_redeem_tx<K: Keychain>(
		&self,
		keychain: &K,
		swap: &Swap,
		context: &Context,
		input_script: &Script,
		fee_satoshi_per_byte: Option<f32>,
	) -> Result<BtcTtansaction, ErrorKind> {
		swap.expect(Status::RedeemSecondary, false)?;
		let cosign_id = &context.unwrap_seller()?.unwrap_btc()?.cosign;

		let redeem_address_str = swap.unwrap_seller()?.0.clone();
		let redeem_address = Address::from_str(&redeem_address_str).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse BTC redeem address {}, {}",
				redeem_address_str, e
			))
		})?;

		let cosign_secret = keychain.derive_key(0, cosign_id, SwitchCommitmentType::None)?;
		let redeem_secret = SellApi::calculate_redeem_secret(keychain, swap)?;

		// This function should only be called once
		let btc_data = swap.secondary_data.unwrap_btc()?;
		if btc_data.redeem_tx.is_some() {
			return Err(ErrorKind::OneShot(
				"Fn: seller_build_redeem_tx, btc_data.redeem_tx is not empty".to_string(),
			))?;
		}

		let (btc_transaction, _, _, _) = btc_data.build_redeem_tx(
			keychain.secp(),
			&redeem_address,
			&input_script,
			fee_satoshi_per_byte.unwrap_or(self.get_default_fee_satoshi_per_byte(&swap.network)),
			&cosign_secret,
			&redeem_secret,
		)?;

		Ok(btc_transaction)
	}

	fn seller_update_redeem(&mut self, swap: &mut Swap) -> Result<Action, ErrorKind> {
		swap.expect(Status::RedeemSecondary, false)?;

		// We have generated the BTC redeem tx..
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;

		if btc_data.redeem_tx.is_none() {
			return Ok(Action::PublishTxSecondary(Currency::Btc));
		}

		debug_assert!(btc_data.redeem_confirmations.is_some());

		let txid = &btc_data
			.redeem_tx
			.ok_or(ErrorKind::Generic("Redeem transaction missing".into()))?;

		// ..we published it..
		if let Some((Some(height), _)) = self.btc_node_client.transaction(txid)? {
			let confirmations = self.btc_node_client.height()?.saturating_sub(height) + 1;
			btc_data.redeem_confirmations = Some(confirmations);
			if confirmations > 0 {
				// ..and its been included in a block!
				return Ok(Action::Complete);
			}
		}
		// ..but its not confirmed yet
		Ok(Action::ConfirmationRedeemSecondary(
			swap.secondary_currency,
			format!("{}", txid),
		))
	}

	// Buyer specific methods

	/// Buyer checks Grin and Bitcoin chains for the locked funds
	fn buyer_check_locks<K: Keychain>(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		input_script: &Script,
	) -> Result<Option<Action>, ErrorKind> {
		let mut confirmations: Option<u64> = None;
		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			if swap.seller_lock_first {
				// Check first if MWC are there. Need at least one or 10% of confirmation
				let conf =
					swap.update_mwc_lock_confirmations(keychain.secp(), &self.node_client)?;
				confirmations = Some(conf);
				// Let's wait for a single confirmation.
				let need_conf = 1; // std::cmp::max(1, swap.required_mwc_lock_confirmations / 10);
				if conf < need_conf {
					return Ok(Some(Action::Confirmations {
						required: need_conf,
						actual: conf,
					}));
				}
			}

			let (pending_amount, confirmed_amount, least_confirmations) =
				self.btc_balance(keychain, swap, &input_script, swap.secondary_confirmations)?;
			let chain_amount = pending_amount + confirmed_amount;
			if chain_amount < swap.secondary_amount {
				// At this point, user needs to deposit (more) Bitcoin
				return Ok(Some(Action::DepositSecondary {
					currency: swap.secondary_currency,
					amount: swap.secondary_amount - chain_amount,
					address: format!(
						"{}",
						swap.secondary_data
							.unwrap_btc()?
							.address(input_script, swap.network)?
					),
				}));
			}

			// Enough confirmed or in mempool
			debug!(
				"SWAP confirmed amount: {}, swap secondary amount: {}",
				confirmed_amount, swap.secondary_amount
			);

			if confirmed_amount < swap.secondary_amount {
				// Wait for enough confirmations
				return Ok(Some(Action::ConfirmationsSecondary {
					currency: swap.secondary_currency,
					required: swap.secondary_confirmations,
					actual: least_confirmations,
				}));
			}

			swap.secondary_data.unwrap_btc_mut()?.locked = true;
		}

		// Check Grin chain
		let confirmations = confirmations
			.unwrap_or(swap.update_mwc_lock_confirmations(keychain.secp(), &self.node_client)?);
		if !swap.is_mwc_locked() {
			return Ok(Some(Action::Confirmations {
				required: swap.mwc_confirmations,
				actual: confirmations,
			}));
		}

		// If we got here, funds have been locked on both chains with sufficient confirmations
		swap.status = Status::Locked;
		BuyApi::init_redeem(keychain, swap, context)?;

		Ok(None)
	}

	/// Buyer applies an update message to the Swap
	fn buyer_receive_message<K: Keychain>(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		match swap.status {
			Status::InitRedeem => self.buyer_redeem(keychain, swap, context, message),
			_ => Err(ErrorKind::UnexpectedMessageType(format!(
				"Fn buyer_receive_message, get status {:?}",
				swap.status
			))),
		}
	}

	/// Buyer applies redeem message from seller to the swap
	fn buyer_redeem<K: Keychain>(
		&self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<(), ErrorKind> {
		let (_, redeem, _) = message.unwrap_redeem()?;
		BuyApi::redeem(keychain, swap, context, redeem)?;
		Ok(())
	}

	fn buyer_refund<K: Keychain>(
		&mut self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: &Address,
		input_script: &Script,
		fee_satoshi_per_byte: Option<f32>,
	) -> Result<(), ErrorKind> {
		let (pending_amount, confirmed_amount, _) =
			self.btc_balance(keychain, swap, input_script, 0)?;

		if pending_amount + confirmed_amount == 0 {
			return Err(ErrorKind::Generic(
				"Not found outputs to refund. May be it is not on the blockchain yet?".to_string(),
			));
		}

		let refund_key = keychain.derive_key(
			0,
			&context.unwrap_buyer()?.unwrap_btc()?.refund,
			SwitchCommitmentType::None,
		)?;

		let btc_lock_time = swap.get_time_btc_lock();
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let refund_tx = btc_data.refund_tx(
			keychain.secp(),
			refund_address,
			input_script,
			fee_satoshi_per_byte.unwrap_or(self.get_default_fee_satoshi_per_byte(&swap.network)),
			btc_lock_time,
			&refund_key,
		)?;

		let tx = refund_tx.tx.clone();
		self.btc_node_client.post_tx(tx)?;
		btc_data.refund_tx = Some(refund_tx.txid);

		Ok(())
	}

	fn get_slate_confirmation_number(
		&mut self,
		mwc_tip: &u64,
		slate: &Slate,
		outputs_ok: bool,
	) -> Result<Option<u64>, ErrorKind> {
		let result: Option<u64> = if slate.tx.kernels().is_empty() {
			None
		} else {
			debug_assert!(slate.tx.kernels().len() == 1);

			let kernel = &slate.tx.kernels()[0].excess;
			if kernel.0.to_vec().iter().any(|v| *v != 0) {
				// kernel is non zero - we can check transaction by kernel
				match self
					.node_client
					.get_kernel(kernel, Some(slate.height), None)?
				{
					Some((_tx_kernel, height, _mmr_index)) => {
						Some(mwc_tip.saturating_sub(height) + 1)
					}
					None => Some(0),
				}
			} else {
				if outputs_ok {
					// kernel is not valid, still can use outputs.
					let wallet_outputs: Vec<pedersen::Commitment> = slate
						.tx
						.outputs()
						.iter()
						.map(|o| o.commit.clone())
						.collect();
					let res = self.node_client.get_outputs_from_node(&wallet_outputs)?;
					let height = res.values().map(|v| v.1).max();
					match height {
						Some(h) => Some(mwc_tip.saturating_sub(h) + 1),
						None => Some(0),
					}
				} else {
					None
				}
			}
		};
		Ok(result)
	}

	fn get_btc_confirmation_number(
		&mut self,
		btc_tip: &u64,
		tx_hash: Option<sha256d::Hash>,
	) -> Result<Option<u64>, ErrorKind> {
		let result: Option<u64> = match tx_hash {
			None => None,
			Some(tx_hash) => match self.btc_node_client.transaction(&tx_hash)? {
				None => None,
				Some((height, _tx)) => match height {
					None => Some(0),
					Some(h) => Some(btc_tip.saturating_sub(h) + 1),
				},
			},
		};
		Ok(result)
	}

	fn get_default_fee_satoshi_per_byte(&self, network: &Network) -> f32 {
		// Default values
		match network {
			Network::Floonet => 1.4 as f32,
			Network::Mainnet => 26.0 as f32,
		}
	}
}

impl<K, C, B> SwapApi<K> for BtcSwapApi<C, B>
where
	K: Keychain,
	C: NodeClient,
	B: BtcNodeClient,
{
	fn context_key_count(
		&mut self,
		_keychain: &K,
		secondary_currency: Currency,
		_is_seller: bool,
	) -> Result<usize, ErrorKind> {
		if secondary_currency != Currency::Btc {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		Ok(4)
	}

	fn create_context(
		&mut self,
		keychain: &K,
		secondary_currency: Currency,
		is_seller: bool,
		inputs: Option<Vec<(Identifier, Option<u64>, u64)>>,
		change_amount: u64,
		keys: Vec<Identifier>,
	) -> Result<Context, ErrorKind> {
		if secondary_currency != Currency::Btc {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		let secp = keychain.secp();
		let mut keys = keys.into_iter();

		let role_context = if is_seller {
			RoleContext::Seller(SellerContext {
				inputs: inputs.ok_or(ErrorKind::UnexpectedRole(
					"Fn create_context() for seller not found inputs".to_string(),
				))?,
				change_output: keys.next().unwrap(),
				change_amount,
				refund_output: keys.next().unwrap(),
				secondary_context: SecondarySellerContext::Btc(BtcSellerContext {
					cosign: keys.next().unwrap(),
				}),
			})
		} else {
			RoleContext::Buyer(BuyerContext {
				output: keys.next().unwrap(),
				redeem: keys.next().unwrap(),
				secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
					refund: keys.next().unwrap(),
				}),
			})
		};

		Ok(Context {
			multisig_key: keys.next().unwrap(),
			multisig_nonce: generate_nonce(secp)?,
			lock_nonce: generate_nonce(secp)?,
			refund_nonce: generate_nonce(secp)?,
			redeem_nonce: generate_nonce(secp)?,
			role_context,
		})
	}

	/// Seller creates a swap offer
	fn create_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		primary_amount: u64,
		secondary_amount: u64,
		secondary_currency: Currency,
		secondary_redeem_address: String,
		seller_lock_first: bool,
		mwc_confirmations: u64,
		secondary_confirmations: u64,
		message_exchange_time_sec: u64,
		redeem_time_sec: u64,
	) -> Result<(Swap, Action), ErrorKind> {
		// Checking if address is valid
		let _redeem_address = Address::from_str(&secondary_redeem_address).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse BTC redeem address {}, {}",
				secondary_redeem_address, e
			))
		})?;

		if secondary_currency != Currency::Btc {
			return Err(ErrorKind::UnexpectedCoinType);
		}

		let height = self.node_client.get_chain_tip()?.0;
		let mut swap = SellApi::create_swap_offer(
			keychain,
			context,
			primary_amount,
			secondary_amount,
			Currency::Btc,
			secondary_redeem_address,
			height,
			seller_lock_first,
			mwc_confirmations,
			secondary_confirmations,
			message_exchange_time_sec,
			redeem_time_sec,
		)?;

		let btc_data = BtcData::new(keychain, context.unwrap_seller()?.unwrap_btc()?)?;
		swap.secondary_data = btc_data.wrap();

		let action = self.required_action(keychain, &mut swap, context)?;
		Ok((swap, action))
	}

	/// Buyer accepts a swap offer
	fn accept_swap_offer(
		&mut self,
		keychain: &K,
		context: &Context,
		message: Message,
	) -> Result<(Swap, Action), ErrorKind> {
		let (id, offer, secondary_update) = message.unwrap_offer()?;

		let mut swap = BuyApi::accept_swap_offer(
			keychain,
			context,
			id,
			offer,
			secondary_update,
			&self.node_client,
		)?;

		let action = self.required_action(keychain, &mut swap, context)?;
		Ok((swap, action))
	}

	fn completed(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => {
				swap.expect(Status::RedeemSecondary, false)?;
				let btc_data = swap.secondary_data.unwrap_btc()?;
				if btc_data.redeem_confirmations.unwrap_or(0) > 0 {
					swap.status = Status::Completed;
				} else {
					return Err(ErrorKind::UnexpectedAction(format!("swapapi Fn completed() found incorrect btc_data.redeem_confirmations value: {:?}", btc_data.redeem_confirmations)));
				}
			}
			Role::Buyer => BuyApi::completed(swap)?,
		}
		let action = self.required_action(keychain, swap, context)?;

		Ok(action)
	}

	fn refunded(
		&mut self,
		keychain: &K,
		context: &Context,
		swap: &mut Swap,
		refund_address: Option<String>,
		fee_satoshi_per_byte: Option<f32>,
	) -> Result<(), ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => {
				SellApi::publish_refund(&self.node_client, swap)?;
				swap.status = Status::Refunded;
				Ok(())
			}
			Role::Buyer => {
				let refund_address_str = refund_address.ok_or(ErrorKind::Generic(
					"Please define BTC refund address".to_string(),
				))?;
				let refund_address = Address::from_str(&refund_address_str).map_err(|e| {
					ErrorKind::Generic(format!(
						"Unable to parse BTC address {}, {}",
						refund_address_str, e
					))
				})?;
				let input_script = self.script(keychain, swap)?;
				self.buyer_refund(
					keychain,
					context,
					swap,
					&refund_address,
					&input_script,
					fee_satoshi_per_byte,
				)?;
				swap.status = Status::Refunded;
				Ok(())
			}
		}
	}

	fn cancelled(&mut self, _keychain: &K, swap: &mut Swap) -> Result<(), ErrorKind> {
		// User by some reason want to cancel. It is fine.
		if swap.status == Status::Completed {
			return Err(ErrorKind::UnexpectedAction(
				"This trade is complited, you can't cancel it".to_string(),
			));
		}
		swap.status = Status::Cancelled;
		Ok(())
	}

	/// Check which action should be taken by the user
	fn required_action(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		let action = match swap.role {
			Role::Seller(_, _) => {
				if swap.status == Status::Accepted {
					let input_script = self.script(keychain, swap)?;
					if let Some(action) = self.seller_check_locks(keychain, swap, &input_script)? {
						return Ok(action);
					}
				} else if swap.status == Status::RedeemSecondary {
					return self.seller_update_redeem(swap);
				}
				let action = SellApi::required_action(&mut self.node_client, swap)?;

				match (swap.status, action) {
					(Status::Redeem, Action::Complete) => {
						swap.status = Status::RedeemSecondary;
						Action::PublishTxSecondary(Currency::Btc)
					}
					(_, action) => action,
				}
			}
			Role::Buyer => {
				if swap.status == Status::Accepted {
					let input_script = self.script(keychain, swap)?;
					if let Some(action) =
						self.buyer_check_locks(keychain, swap, context, &input_script)?
					{
						return Ok(action);
					}
				}
				if swap.status == Status::Cancelled {
					let action = match self.script(keychain, swap) {
						Ok(input_script) => {
							let (pending_amount, confirmed_amount, _) =
								self.btc_balance(keychain, swap, &input_script, 0)?;

							if pending_amount + confirmed_amount == 0 {
								Action::None
							} else {
								let requied_time = swap.get_time_btc_lock();
								let now = Utc::now().timestamp() as u64;
								if now < requied_time {
									Action::WaitingForBtcRefund {
										required: requied_time,
										current: now,
									}
								} else {
									Action::Refund
								}
							}
						}
						Err(_) => Action::None,
					};
					return Ok(action);
				}

				BuyApi::required_action(&mut self.node_client, swap)?
			}
		};

		Ok(action)
	}

	fn message(&mut self, _keychain: &K, swap: &Swap) -> Result<Message, ErrorKind> {
		let message = match swap.role {
			Role::Seller(_, _) => {
				let mut message = SellApi::message(swap)?;
				if let Update::Offer(_) = message.inner {
					// exist for Status::Created. Seller creates the offer
					message.set_inner_secondary(
						swap.secondary_data.unwrap_btc()?.offer_update().wrap(),
					);
				}
				message
			}
			Role::Buyer => {
				let mut message = BuyApi::message(swap)?;
				if let Update::AcceptOffer(_) = message.inner {
					message.set_inner_secondary(
						swap.secondary_data
							.unwrap_btc()?
							.accept_offer_update()?
							.wrap(),
					);
				}
				message
			}
		};

		Ok(message)
	}

	/// Message has been sent to the counterparty, update state accordingly
	fn message_sent(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => SellApi::message_sent(swap)?,
			Role::Buyer => BuyApi::message_sent(swap)?,
		}
		let action = self.required_action(keychain, swap, context)?;

		Ok(action)
	}

	/// Apply an update Message to the Swap
	fn receive_message(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		message: Message,
	) -> Result<Action, ErrorKind> {
		if swap.id != message.id {
			return Err(ErrorKind::MismatchedId);
		}

		if swap.is_not_active() {
			return Err(ErrorKind::NotActive);
		}

		match swap.role {
			Role::Seller(_, _) => self.seller_receive_message(keychain, swap, context, message)?,
			Role::Buyer => self.buyer_receive_message(keychain, swap, context, message)?,
		};
		let action = self.required_action(keychain, swap, context)?;

		Ok(action)
	}

	fn publish_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		retry: bool,
	) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => SellApi::publish_transaction(&self.node_client, swap, retry),
			Role::Buyer => BuyApi::publish_transaction(&self.node_client, swap, retry),
		}?;

		if !retry {
			self.required_action(keychain, swap, context)
		} else {
			Ok(Action::None)
		}
	}

	fn publish_secondary_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
		fee_satoshi_per_byte: Option<f32>,
		retry: bool,
	) -> Result<Action, ErrorKind> {
		swap.expect_seller()?;

		swap.expect(Status::RedeemSecondary, retry)?;

		let input_script = self.script(keychain, swap)?;

		let btc_tx = self.seller_build_redeem_tx(
			keychain,
			swap,
			context,
			&input_script,
			fee_satoshi_per_byte,
		)?;

		self.btc_node_client.post_tx(btc_tx.tx)?;

		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if !retry && btc_data.redeem_confirmations.is_some() {
			return Err(ErrorKind::UnexpectedAction("btc_data.redeem_confirmations is already defined at publish_secondary_transaction()".to_string()));
		}
		btc_data.redeem_confirmations = Some(0);
		btc_data.redeem_tx = Some(btc_tx.txid);

		if retry {
			return Ok(Action::None);
		}

		let action = self.required_action(keychain, swap, context)?;
		Ok(action)
	}

	/// Request confirmation numberss for all transactions that are known and in the in the swap
	fn request_tx_confirmations(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
	) -> Result<SwapTransactionsConfirmations, ErrorKind> {
		let mwc_tip = self.node_client.get_chain_tip()?.0;

		let is_seller = swap.is_seller();

		let mwc_lock_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.lock_slate, !is_seller)?;
		let mwc_redeem_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.redeem_slate, is_seller)?;
		let mwc_refund_conf =
			self.get_slate_confirmation_number(&mwc_tip, &swap.refund_slate, !is_seller)?;

		let btc_tip = self.btc_node_client.height()?;
		let btc_data = swap.secondary_data.unwrap_btc()?;
		let secondary_redeem_conf =
			self.get_btc_confirmation_number(&btc_tip, btc_data.redeem_tx.clone())?;
		let secondary_refund_conf =
			self.get_btc_confirmation_number(&btc_tip, btc_data.refund_tx.clone())?;

		// BTC lock account...
		// Checking Amount, it can be too hight as well
		let mut secondary_lock_amount = 0;
		let mut least_confirmations = None;

		if let Ok(input_script) = self.script(keychain, swap) {
			if let Ok(address) = btc_data.address(&input_script, swap.network) {
				let outputs = self.btc_node_client.unspent(&address)?;
				for output in outputs {
					secondary_lock_amount += output.value;
					if output.height == 0 {
						// Output in mempool
						least_confirmations = Some(0);
					} else {
						let confirmations = btc_tip.saturating_sub(output.height) + 1;
						if confirmations < least_confirmations.unwrap_or(std::i32::MAX as u64) {
							least_confirmations = Some(confirmations);
						}
					}
				}
			}
		}

		Ok(SwapTransactionsConfirmations {
			mwc_tip,
			mwc_lock_conf,
			mwc_redeem_conf,
			mwc_refund_conf,
			secondary_tip: btc_tip,
			secondary_lock_conf: least_confirmations,
			secondary_lock_amount,
			secondary_redeem_conf,
			secondary_refund_conf,
		})
	}
}
