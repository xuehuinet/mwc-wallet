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
use crate::swap::message::{Message, Update};
use crate::swap::types::{
	Action, BuyerContext, Context, Currency, Role, RoleContext, SecondaryBuyerContext,
	SecondarySellerContext, SellerContext, Status,
};
use crate::swap::{BuyApi, ErrorKind, SellApi, Swap, SwapApi};
use crate::NodeClient;
use bitcoin::{Address, AddressType};
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
	fn script<K: Keychain>(&self, keychain: &K, swap: &mut Swap) -> Result<(), ErrorKind> {
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		btc_data.script(
			keychain.secp(),
			swap.redeem_public
				.as_ref()
				.ok_or(ErrorKind::UnexpectedAction(
					"swap.redeem_public value is not defined. Method BtcSwapApi::script"
						.to_string(),
				))?,
		)?;
		Ok(())
	}

	/// Check BTC amount at the chain.
	fn btc_balance<K: Keychain>(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		confirmations_needed: u64,
	) -> Result<(u64, u64, u64), ErrorKind> {
		self.script(keychain, swap)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let address = btc_data.address(swap.network)?;
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

	/// Seller checks Grin and Bitcoin chains for the locked funds, Statu::Accepted
	/// Return Ok(None) if everything is ready. Otherwise it is action.
	fn seller_check_locks<K: Keychain>(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
	) -> Result<Option<Action>, ErrorKind> {
		//  Check if Lock slate is ready and confirmed.
		if !swap.is_locked(swap.required_mwc_lock_confirmations) {
			match swap.lock_confirmations {
				None => return Ok(Some(Action::PublishTx)),
				Some(_) => {
					let confirmations =
						swap.update_lock_confirmations(keychain.secp(), &self.node_client)?;
					if !swap.is_locked(swap.required_mwc_lock_confirmations) {
						return Ok(Some(Action::Confirmations {
							required: swap.required_mwc_lock_confirmations,
							actual: confirmations,
						}));
					}
				}
			};
		}

		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			// Waiting for Btc confirmations
			let (pending_amount, confirmed_amount, mut least_confirmations) =
				self.btc_balance(keychain, swap, swap.required_secondary_lock_confirmations)?;
			if pending_amount + confirmed_amount < swap.secondary_amount {
				least_confirmations = 0;
			};

			if confirmed_amount < swap.secondary_amount {
				return Ok(Some(Action::ConfirmationsSecondary {
					currency: swap.secondary_currency,
					required: swap.required_secondary_lock_confirmations,
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
		swap: &mut Swap,
		context: &Context,
	) -> Result<(), ErrorKind> {
		swap.expect(Status::Redeem)?;
		self.script(keychain, swap)?;
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
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if btc_data.redeem_tx.is_some() {
			return Err(ErrorKind::OneShot(
				"Fn: seller_build_redeem_tx, btc_data.redeem_tx is not empty".to_string(),
			))?;
		}

		btc_data.redeem_tx(
			keychain.secp(),
			&redeem_address,
			10,
			&cosign_secret,
			&redeem_secret,
		)?;
		swap.status = Status::RedeemSecondary;

		Ok(())
	}

	fn seller_update_redeem(&mut self, swap: &mut Swap) -> Result<Action, ErrorKind> {
		swap.expect(Status::RedeemSecondary)?;

		// We have generated the BTC redeem tx..
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let txid = &btc_data
			.redeem_tx
			.as_ref()
			.ok_or(ErrorKind::Generic("Redeem transaction missing".into()))?
			.txid;

		if btc_data.redeem_confirmations.is_none() {
			// ..but we haven't published it yet
			Ok(Action::PublishTxSecondary(Currency::Btc))
		} else {
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
	}

	// Buyer specific methods

	/// Buyer checks Grin and Bitcoin chains for the locked funds
	fn buyer_check_locks<K: Keychain>(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Option<Action>, ErrorKind> {
		// Check Bitcoin chain
		if !swap.secondary_data.unwrap_btc()?.locked {
			let (pending_amount, confirmed_amount, least_confirmations) =
				self.btc_balance(keychain, swap, swap.required_secondary_lock_confirmations)?;
			let chain_amount = pending_amount + confirmed_amount;
			if chain_amount < swap.secondary_amount {
				// At this point, user needs to deposit (more) Bitcoin
				self.script(keychain, swap)?;
				return Ok(Some(Action::DepositSecondary {
					currency: swap.secondary_currency,
					amount: swap.secondary_amount - chain_amount,
					address: format!(
						"{}",
						swap.secondary_data.unwrap_btc()?.address(swap.network)?
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
					required: swap.required_secondary_lock_confirmations,
					actual: least_confirmations,
				}));
			}

			swap.secondary_data.unwrap_btc_mut()?.locked = true;
		}

		// Check Grin chain
		let confirmations = swap.update_lock_confirmations(keychain.secp(), &self.node_client)?;
		if !swap.is_locked(swap.required_mwc_lock_confirmations) {
			return Ok(Some(Action::Confirmations {
				required: swap.required_mwc_lock_confirmations,
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
	) -> Result<(), ErrorKind> {
		let (pending_amount, confirmed_amount, _) = self.btc_balance(keychain, swap, 0)?;

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

		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		let refund_tx = btc_data.refund_tx(keychain.secp(), refund_address, 10, &refund_key)?;

		let tx = refund_tx.tx.clone();
		self.btc_node_client.post_tx(tx)?;
		Ok(())
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
		required_mwc_lock_confirmations: u64,
		required_secondary_lock_confirmations: u64,
		mwc_lock_time_seconds: u64,
		seller_redeem_time: u64,
	) -> Result<(Swap, Action), ErrorKind> {
		let redeem_address = Address::from_str(&secondary_redeem_address).map_err(|e| {
			ErrorKind::Generic(format!(
				"Unable to parse BTC redeem address {}, {}",
				secondary_redeem_address, e
			))
		})?;

		match redeem_address.address_type() {
			Some(AddressType::P2pkh) | Some(AddressType::P2sh) => {}
			_ => {
				return Err(ErrorKind::Generic(
					"Only P2PKH and P2SH BTC redeem addresses are supported".into(),
				))
			}
		};

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
			required_mwc_lock_confirmations,
			required_secondary_lock_confirmations,
			mwc_lock_time_seconds,
			seller_redeem_time,
		)?;

		// Lock time value will be checked nicely at Buyer side when script will be created
		let lock_time: i64 =
			swap.started.timestamp() + mwc_lock_time_seconds as i64 + seller_redeem_time as i64;
		if lock_time < 0 || lock_time >= std::u32::MAX as i64 {
			return Err(ErrorKind::Generic(
				"lock time intervals are invalid".to_string(),
			));
		}

		let btc_data = BtcData::new(
			keychain,
			context.unwrap_seller()?.unwrap_btc()?,
			lock_time as u32,
		)?;
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
		let btc_data = BtcData::from_offer(
			keychain,
			secondary_update.unwrap_btc()?.unwrap_offer()?,
			context.unwrap_buyer()?.unwrap_btc()?,
		)?;

		let height = self.node_client.get_chain_tip()?.0;
		let mut swap = BuyApi::accept_swap_offer(keychain, context, id, offer, height)?;
		swap.secondary_data = btc_data.wrap();

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
				swap.expect(Status::RedeemSecondary)?;
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
				self.buyer_refund(keychain, context, swap, &refund_address)?;
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
					if let Some(action) = self.seller_check_locks(keychain, swap)? {
						return Ok(action);
					}
				} else if swap.status == Status::RedeemSecondary {
					return self.seller_update_redeem(swap);
				}
				let action = SellApi::required_action(&mut self.node_client, swap)?;

				match (swap.status, action) {
					(Status::Redeem, Action::Complete) => {
						self.seller_build_redeem_tx(keychain, swap, context)?;
						Action::PublishTxSecondary(Currency::Btc)
					}
					(_, action) => action,
				}
			}
			Role::Buyer => {
				if swap.status == Status::Accepted {
					if let Some(action) = self.buyer_check_locks(keychain, swap, context)? {
						return Ok(action);
					}
				}
				if swap.status == Status::Cancelled {
					let (pending_amount, confirmed_amount, _) =
						self.btc_balance(keychain, swap, 0)?;

					let action = if pending_amount + confirmed_amount == 0 {
						Action::None
					} else {
						let requied_time = swap.secondary_data.unwrap_btc()?.lock_time as u64;
						let now = Utc::now().timestamp() as u64;
						if now < requied_time {
							Action::WaitingForBtcRefund {
								required: requied_time,
								current: now,
							}
						} else {
							Action::Refund
						}
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
	) -> Result<Action, ErrorKind> {
		match swap.role {
			Role::Seller(_, _) => SellApi::publish_transaction(&self.node_client, swap),
			Role::Buyer => BuyApi::publish_transaction(&self.node_client, swap),
		}?;

		self.required_action(keychain, swap, context)
	}

	fn publish_secondary_transaction(
		&mut self,
		keychain: &K,
		swap: &mut Swap,
		context: &Context,
	) -> Result<Action, ErrorKind> {
		swap.expect_seller()?;
		swap.expect(Status::RedeemSecondary)?;
		let btc_data = swap.secondary_data.unwrap_btc_mut()?;
		if btc_data.redeem_confirmations.is_some() {
			return Err(ErrorKind::UnexpectedAction("btc_data.redeem_confirmations is already defined at publish_secondary_transaction()".to_string()));
		}

		let tx = btc_data
			.redeem_tx
			.as_ref()
			.ok_or(ErrorKind::UnexpectedAction("Fn publish_secondary_transaction() called with not prepared data for BTC Redeem Tx".to_string()))?
			.tx
			.clone();
		self.btc_node_client.post_tx(tx)?;
		btc_data.redeem_confirmations = Some(0);
		let action = self.required_action(keychain, swap, context)?;

		Ok(action)
	}
}
