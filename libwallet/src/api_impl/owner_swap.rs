// Copyright 2020 The MWC Develope;
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

//! Generic implementation of owner API atomic swap functions

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::grin_keychain::{Identifier, Keychain};
use crate::internal::selection;
use crate::swap::error::ErrorKind;
use crate::swap::message::{Message, Update};
use crate::swap::swap::Swap;
use crate::swap::types::{Action, Currency, Status};
use crate::swap::{trades, Context, SwapApi};
use crate::types::NodeClient;
use crate::Error;
use crate::{
	wallet_lock, OutputData, OutputStatus, Slate, SwapStartArgs, TxLogEntry, TxLogEntryType,
	WalletBackend, WalletInst, WalletLCProvider,
};
use grin_util::to_hex;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

// TODO  - Validation for all parameters.

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
pub fn swap_start<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	params: &SwapStartArgs,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Starting a swap trade.
	// This method only initialize and store the swap process. Nothing is done

	// TODO  - validate SwapStartArgs values
	// TODO  - we probably want to do that as a generic solution because all params need to be validated

	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let keychain = w.keychain(keychain_mask)?;
	let height = node_client.get_chain_tip()?.0;

	let secondary_currency = Currency::try_from(params.secondary_currency.as_str())?;
	let mut swap_api = crate::swap::api::create_instance(&secondary_currency, node_client)?;

	let parent_key_id = w.parent_key_id(); // account is current one
	let (outputs, total, amount, fee) = crate::internal::selection::select_coins_and_fee(
		&mut **w,
		params.mwc_amount,
		height,
		params.minimum_confirmations.unwrap_or(10),
		500,
		1,
		false,
		&parent_key_id,
		&None, // outputs to include into the transaction
		1,     // Number of resulting outputs. Normally it is 1
		false,
		0,
	)?;

	let context = create_context(
		&mut **w,
		keychain_mask,
		&mut swap_api,
		&keychain,
		secondary_currency,
		true,
		Some(
			outputs
				.iter()
				.map(|out| (out.key_id.clone(), out.mmr_index.clone(), out.value))
				.collect(),
		),
		total - amount - fee,
	)?;

	let (swap, _) = (*swap_api).create_swap_offer(
		&keychain,
		&context,
		params.mwc_amount,       // mwc amount to sell
		params.secondary_amount, // btc amount to buy
		secondary_currency,
		params.secondary_redeem_address.clone(),
		params.required_mwc_lock_confirmations,
		params.required_secondary_lock_confirmations,
		params.mwc_lock_time_seconds,
		params.seller_redeem_time,
	)?;

	// Store swap result into the file.
	let swap_id = swap.id.to_string();
	if trades::get_swap_trade(swap_id.as_str()).is_ok() {
		// Should be impossible, uuid suppose to be unique. But we don't want to overwrite anything
		return Err(ErrorKind::TradeIoError(
			swap_id.clone(),
			"This trade record already exist".to_string(),
		)
		.into());
	}

	trades::store_swap_trade(&context, &swap)?;

	Ok(swap_id)
}

/// List Swap trades. Returns SwapId + Status
pub fn swap_list<'a, L, C, K>(
	_wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	_keychain_mask: Option<&SecretKey>,
) -> Result<Vec<(String, String)>, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let swap_id = trades::list_swap_trades()?;
	let mut result: Vec<(String, String)> = Vec::new();

	for sw_id in &swap_id {
		let (_, swap) = trades::get_swap_trade(sw_id.as_str())?;
		result.push((sw_id.clone(), swap.status.to_string()));
	}

	Ok(result)
}

/// Delete Swap trade.
pub fn swap_delete<'a, L, C, K>(
	_wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	_keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	trades::delete_swap_trade(swap_id)?;
	Ok(())
}

/// Get a Swap kernel object.
pub fn swap_get<'a, L, C, K>(
	_wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	_keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<Swap, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (_, swap) = trades::get_swap_trade(swap_id)?;
	Ok(swap)
}

/// Get a status and action for the swap.
pub fn get_swap_status_action<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
) -> Result<(Status, Action), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context, mut swap) = trades::get_swap_trade(swap_id)?;

	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let keychain = w.keychain(keychain_mask)?;

	let mut swap_api = crate::swap::api::create_instance(&swap.secondary_currency, node_client)?;
	let action = swap_api.required_action(&keychain, &mut swap, &context)?;

	Ok((swap.status, action))
}

/// Process the action for the swap. Action has to match the expected one
pub fn swap_process<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_id: &str,
	action: Action,
	method: Option<String>,
	destination: Option<String>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let (context, mut swap) = trades::get_swap_trade(swap_id)?;

	wallet_lock!(wallet_inst, w);
	let node_client = w.w2n_client().clone();
	let keychain = w.keychain(keychain_mask)?;
	let parent_key_id = w.parent_key_id();

	let mut swap_api =
		crate::swap::api::create_instance(&swap.secondary_currency, node_client.clone())?;
	let swap_action = swap_api.required_action(&keychain, &mut swap, &context)?;

	if action != Action::Cancel && action != swap_action {
		return Err(ErrorKind::Generic(format!(
			"Unable to process unexpected action {}, expected action is {}",
			action, swap_action
		))
		.into());
	}

	match action {
		Action::SendMessage(_i) => {
			// Destination currently if only file.
			if method.is_none() || destination.is_none() {
				return Err(ErrorKind::Generic(
					"Please specify method and destination to send a message".to_string(),
				)
				.into());
			}
			let message = swap_api.message(&keychain, &swap)?;
			let msg_str = message.to_json()?;

			// Destination is allwais a file name
			// TODO - need to support method
			let destination = destination.unwrap();

			// TODO - Note, this code need to be updated !!!!
			let mut file = File::create(destination.clone())?;
			file.write_all(msg_str.as_bytes())?;
			println!("Message is written into the file {}", destination);

			// update swap status after the send. For file it is fair enough to have the message is sent
			swap_api.message_sent(&keychain, &mut swap, &context)?;
			trades::store_swap_trade(&context, &swap)?;
			return Ok(());
		}
		Action::ReceiveMessage => {
			// TODO - need to change. Currently message will be read form the file
			//    We can keep it as one of alternatives, but also same need to be done for other protocols.
			//    Because of that message is processed with different API call.
			println!("Please use 'swap_message' command to process message from the file");
			return Ok(());
		}
		Action::PublishTxSecondary(_currency) => {
			swap_api.publish_secondary_transaction(&keychain, &mut swap, &context)?;
			println!(
				"{} redeem transaction is published",
				swap.secondary_currency
			);
			return Ok(());
		}
		Action::PublishTx => {
			// Let's lock output and create transaction first.
			// If those inputs are already spent - it is really bad because we have to cancel the swap.

			if swap.is_seller() {
				// Seller publishing Lock Transaction
				if swap.lock_confirmations.is_some() {
					return Err(ErrorKind::UnexpectedAction(
						"Seller Fn publish_transaction() lock is not initialized".to_string(),
					)
					.into());
				}

				let seller_context = context.unwrap_seller()?;
				let slate_context = crate::types::Context::from_send_slate(
					&swap.lock_slate,
					context.lock_nonce.clone(),
					seller_context.inputs.clone(),
					vec![(
						seller_context.change_output.clone(),
						None,
						seller_context.change_amount,
					)],
					parent_key_id,
					0,
				)?;
				selection::lock_tx_context(
					&mut **w,
					keychain_mask,
					&swap.lock_slate,
					&slate_context,
					Some(format!("Swap {} Lock", swap_id)),
				)?;

				swap_api.publish_transaction(&keychain, &mut swap, &context)?;
				trades::store_swap_trade(&context, &swap)?;
				println!(
					"Lock MWC slate is published at transaction {}",
					swap.lock_slate.id
				);
			} else {
				// Buyer publishing redeem transaction
				if swap.redeem_confirmations.is_some() {
					// Tx already published
					return Err(ErrorKind::UnexpectedAction(
						"Buyer Fn publish_transaction(), redeem_confirmations already defined"
							.to_string(),
					)
					.into());
				}

				swap_api.publish_transaction(&keychain, &mut swap, &context)?;
				trades::store_swap_trade(&context, &swap)?;

				// Creating receive transaction from the slate
				let buyer_context = context.unwrap_buyer()?;
				create_receive_tx_record(
					&mut **w,
					keychain_mask,
					&swap.redeem_slate,
					format!("Swap {}", swap_id),
					&buyer_context.redeem,
				)?;
				println!(
					"Redeem MWC slate is published at transaction {}",
					swap.redeem_slate.id
				);
			}
			return Ok(());
		}
		Action::DepositSecondary {
			currency,
			amount,
			address,
		} => {
			println!(
				"Please deposit {} {} to {}",
				currency.amount_to_hr_string(amount, true),
				currency,
				address
			);
			return Ok(());
		}
		Action::Cancel => {
			// We want to cancel transaction.
			swap_api.cancelled(&keychain, &mut swap)?;
			trades::store_swap_trade(&context, &swap)?;
			return Ok(());
		}
		Action::Refund => {
			// Posting refund slate
			// first let's check if we can post it
			swap_api.refunded(&keychain, &context, &mut swap, destination)?;
			trades::store_swap_trade(&context, &swap)?;

			if swap.is_seller() {
				// For MWC transaction we can create a record in the wallet.
				let seller_context = context.unwrap_seller()?;
				create_receive_tx_record(
					&mut **w,
					keychain_mask,
					&swap.refund_slate,
					format!("Swap {} Refund", swap_id),
					&seller_context.refund_output,
				)?;
			}
			return Ok(());
		}
		_ => {
			println!("Sorry, not supported action {}", swap_action);
			return Ok(());
		}
	}
}

// Creating Transaction and output for expected recieve slate
fn create_receive_tx_record<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	tx_name: String,
	output_key_id: &Identifier,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = wallet.parent_key_id();
	let mut batch = wallet.batch(keychain_mask)?;
	let log_id = batch.next_tx_log_id(&parent_key_id)?;
	let mut t = TxLogEntry::new(parent_key_id.clone(), TxLogEntryType::TxReceived, log_id);

	// Creating trnasaction
	t.tx_slate_id = Some(slate.id.clone());
	t.amount_credited = slate.amount;
	t.address = Some(tx_name);
	t.num_outputs = 1;
	t.output_commits = slate
		.tx
		.body
		.outputs
		.iter()
		.map(|o| o.commit.clone())
		.collect();
	t.messages = None;
	t.ttl_cutoff_height = None;
	// when invoicing, this will be invalid
	assert!(slate.tx.body.kernels.len() == 1);
	t.kernel_excess = Some(slate.tx.body.kernels[0].excess);
	t.kernel_lookup_min_height = Some(slate.height);
	batch.save_tx_log_entry(t, &parent_key_id)?;

	assert!(slate.tx.body.outputs.len() == 1);

	// Creating output for that
	batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output_key_id.clone(),
		mmr_index: None,
		n_child: output_key_id.to_path().last_path_index(),
		commit: Some(to_hex(slate.tx.body.outputs[0].commit.0.to_vec())),
		value: slate.amount,
		status: OutputStatus::Unconfirmed,
		height: slate.height,
		lock_height: slate.lock_height,
		is_coinbase: false,
		tx_log_entry: Some(log_id),
	})?;
	batch.commit()?;
	Ok(())
}

/// Processing swap income message. Note result of that can be a new offer of modification of the current one
/// We only notify user about that, no permission will be ask.
/// Reason: Nothing will be done with the funds until user will go forward manually
pub fn swap_income_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	swap_message: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let message = Message::from_json(swap_message)?;
	let swap_id = message.id.to_string();

	match &message.inner {
		Update::None => {
			return Err(
				ErrorKind::Generic("Get empty message, nothing to process".to_string()).into(),
			)
		}
		Update::Offer(offer_update) => {
			// We get an offer
			wallet_lock!(wallet_inst, w);
			let node_client = w.w2n_client().clone();
			let keychain = w.keychain(keychain_mask)?;

			if trades::get_swap_trade(swap_id.as_str()).is_ok() {
				return Err( ErrorKind::Generic(format!("trade with SwapID {} already exist. Probably you already processed this message", swap_id)).into());
			}

			let mut swap_api =
				crate::swap::api::create_instance(&offer_update.secondary_currency, node_client)?;
			// Creating Buyer context
			let context = create_context(
				&mut **w,
				keychain_mask,
				&mut swap_api,
				&keychain,
				offer_update.secondary_currency,
				false,
				None,
				0,
			)?;

			let (swap, _) = swap_api.accept_swap_offer(&keychain, &context, message)?;
			trades::store_swap_trade(&context, &swap)?;
			println!("You get an offer to swap BTC to MWC. SwapID is {}", swap.id);
			return Ok(());
		}
		_ => {
			let (context, mut swap) = trades::get_swap_trade(swap_id.as_str())?;

			wallet_lock!(wallet_inst, w);
			let node_client = w.w2n_client().clone();
			let keychain = w.keychain(keychain_mask)?;
			let mut swap_api =
				crate::swap::api::create_instance(&swap.secondary_currency, node_client)?;
			let swap_action = swap_api.required_action(&keychain, &mut swap, &context)?;
			// Processing the rest 3 messages.
			match &message.inner {
				Update::AcceptOffer(_accept_offer_update) => {
					if !(swap_action == Action::ReceiveMessage
						&& swap.status == Status::Offered
						&& swap.is_seller())
					{
						return Err( ErrorKind::Generic(format!("AcceptOffer message for SwapId {} is declined because this trade status doesn't meet expectations", swap_id)).into());
					}
					swap_api.receive_message(&keychain, &mut swap, &context, message)?;
					trades::store_swap_trade(&context, &swap)?;
					println!("Processed message AcceptOffer for SwapId {}", swap.id);
					return Ok(());
				}
				Update::InitRedeem(_init_redeem_update) => {
					if !(swap_action == Action::ReceiveMessage
						&& swap.status == Status::Locked
						&& swap.is_seller())
					{
						return Err( ErrorKind::Generic(format!("InitRedeem message for SwapId {} is declined because this trade status doesn't meet expectations", swap_id)).into());
					}
					swap_api.receive_message(&keychain, &mut swap, &context, message)?;
					trades::store_swap_trade(&context, &swap)?;
					println!("Processed message InitRedeem for SwapId {}", swap.id);
					return Ok(());
				}
				Update::Redeem(_redeem_update) => {
					if !(swap_action == Action::ReceiveMessage
						&& swap.status == Status::InitRedeem
						&& !swap.is_seller())
					{
						return Err( ErrorKind::Generic(format!("Redeem message for SwapId {} is declined because this trade status doesn't meet expectations", swap_id)).into());
					}
					swap_api.receive_message(&keychain, &mut swap, &context, message)?;
					trades::store_swap_trade(&context, &swap)?;
					println!("Processed message Redeem for SwapId {}", swap.id);
					return Ok(());
				}
				_ => panic!("swap_income_message internal error"), // Not expected anything else.
			};
		}
	};
}

// Local Helper method to create a context
fn create_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	swap_api: &mut Box<dyn SwapApi<K> + 'a>,
	keychain: &K,
	secondary_currency: Currency,
	is_seller: bool,
	inputs: Option<Vec<(Identifier, Option<u64>, u64)>>,
	change_amount: u64,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let secondary_key_size =
		(**swap_api).context_key_count(keychain, secondary_currency, is_seller)?;
	let mut keys: Vec<Identifier> = Vec::new();

	for _ in 0..secondary_key_size {
		keys.push(wallet.next_child(keychain_mask)?);
	}

	let context = (**swap_api).create_context(
		keychain,
		secondary_currency,
		is_seller,
		inputs,
		change_amount,
		keys,
	)?;

	Ok(context)
}
