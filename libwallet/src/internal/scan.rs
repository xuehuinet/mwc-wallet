// Copyright 2019 The Grin Developers
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
//! Functions to restore a wallet's outputs from just the master seed

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_core::consensus::{valid_header_version, WEEK_HEIGHT};
use crate::grin_core::core::HeaderVersion;
use crate::grin_core::global;
use crate::grin_core::libtx::proof;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::Mutex;
use crate::grin_util::static_secp_instance;
use crate::internal::keys;
use crate::types::*;
use crate::{wallet_lock, Error, ErrorKind};
use grin_core::core::Transaction;
use grin_wallet_util::grin_util as util;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// Utility struct for return values from below
#[derive(Debug, Clone)]
pub struct OutputResult {
	///
	pub commit: pedersen::Commitment,
	///
	pub key_id: Identifier,
	///
	pub n_child: u32,
	///
	pub mmr_index: u64,
	///
	pub value: u64,
	///
	pub height: u64,
	///
	pub lock_height: u64,
	///
	pub is_coinbase: bool,
}

#[derive(Debug, Clone)]
/// Collect stats in case we want to just output a single tx log entry
/// for restored non-coinbase outputs
pub struct RestoredTxStats {
	///
	pub log_id: u32,
	///
	pub amount_credited: u64,
	///
	pub num_outputs: usize,
	/// Height of the output. Just want to know for transaction
	pub output_height: u64,
}

fn identify_utxo_outputs<'a, K>(
	keychain: &K,
	outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	percentage_complete: u8,
) -> Result<Vec<OutputResult>, Error>
where
	K: Keychain + 'a,
{
	let mut wallet_outputs: Vec<OutputResult> = Vec::new();

	let legacy_builder = proof::LegacyProofBuilder::new(keychain);
	let builder = proof::ProofBuilder::new(keychain);
	let legacy_version = HeaderVersion(1);

	for output in outputs.iter() {
		let (commit, proof, is_coinbase, height, mmr_index) = output;
		// attempt to unwind message from the RP and get a value
		// will fail if it's not ours
		let info = {
			// Before HF+2wk, try legacy rewind first
			let info_legacy =
				if valid_header_version(height.saturating_sub(2 * WEEK_HEIGHT), legacy_version) {
					proof::rewind(keychain.secp(), &legacy_builder, *commit, None, *proof)?
				} else {
					None
				};

			// If legacy didn't work, try new rewind
			if info_legacy.is_none() {
				proof::rewind(keychain.secp(), &builder, *commit, None, *proof)?
			} else {
				info_legacy
			}
		};

		let (amount, key_id, switch) = match info {
			Some(i) => i,
			None => {
				continue;
			}
		};

		let lock_height = if *is_coinbase {
			*height + global::coinbase_maturity()
		} else {
			*height
		};

		let msg = format!(
			"Output found: {:?}, amount: {:?}, key_id: {:?}, mmr_index: {},",
			commit, amount, key_id, mmr_index,
		);

		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, percentage_complete));
		}

		if switch != SwitchCommitmentType::Regular {
			let msg = format!("Unexpected switch commitment type {:?}", switch);
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::UpdateWarning(msg));
			}
		}

		wallet_outputs.push(OutputResult {
			commit: *commit,
			key_id: key_id.clone(),
			n_child: key_id.to_path().last_path_index(),
			value: amount,
			height: *height,
			lock_height: lock_height,
			is_coinbase: *is_coinbase,
			mmr_index: *mmr_index,
		});
	}
	Ok(wallet_outputs)
}

/// Scanning chain for the outputs. Shared with mwc713
pub fn collect_chain_outputs<'a, C, K>(
	keychain: &K,
	client: C,
	start_index: u64,
	end_index: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(Vec<OutputResult>, u64), Error>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let batch_size = 1000;
	let start_index_stat = start_index;
	let mut start_index = start_index;
	let mut result_vec: Vec<OutputResult> = vec![];
	let last_retrieved_return_index;
	loop {
		let (highest_index, last_retrieved_index, outputs) =
			client.get_outputs_by_pmmr_index(start_index, end_index, batch_size)?;

		let range = highest_index as f64 - start_index_stat as f64;
		let progress = last_retrieved_index as f64 - start_index_stat as f64;
		let perc_complete = cmp::min(((progress / range) * 100.0) as u8, 99);

		let msg = format!(
			"Checking {} outputs, up to index {}. (Highest index: {})",
			outputs.len(),
			highest_index,
			last_retrieved_index,
		);
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::Scanning(msg, perc_complete));
		}

		result_vec.append(&mut identify_utxo_outputs(
			keychain,
			outputs.clone(),
			status_send_channel,
			perc_complete as u8,
		)?);

		if highest_index <= last_retrieved_index {
			last_retrieved_return_index = last_retrieved_index;
			break;
		}
		start_index = last_retrieved_index + 1;
	}
	Ok((result_vec, last_retrieved_return_index))
}

/// Respore missing outputs. Shared with mwc713
pub fn restore_missing_output<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	output: OutputResult,
	found_parents: &mut HashMap<Identifier, u32>,
	tx_stats: &mut Option<&mut HashMap<Identifier, RestoredTxStats>>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);

	let commit = w.calc_commit_for_cache(keychain_mask, output.value, &output.key_id)?;
	let mut batch = w.batch(keychain_mask)?;

	let parent_key_id = output.key_id.parent_path();
	if !found_parents.contains_key(&parent_key_id) {
		found_parents.insert(parent_key_id.clone(), 0);
		if let Some(ref mut s) = tx_stats {
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: batch.next_tx_log_id(&parent_key_id)?,
					amount_credited: 0,
					num_outputs: 0,
					output_height: 0,
				},
			);
		}
	}

	let log_id = if tx_stats.is_none() || output.is_coinbase {
		let log_id = batch.next_tx_log_id(&parent_key_id)?;
		let entry_type = match output.is_coinbase {
			true => TxLogEntryType::ConfirmedCoinbase,
			false => TxLogEntryType::TxReceived,
		};
		let mut t = TxLogEntry::new(parent_key_id.clone(), entry_type, log_id);
		t.confirmed = true;
		t.output_height = output.height;
		t.amount_credited = output.value;
		t.num_outputs = 1;
		t.update_confirmation_ts();
		batch.save_tx_log_entry(t, &parent_key_id)?;
		log_id
	} else {
		if let Some(ref mut s) = tx_stats {
			let ts = s.get(&parent_key_id).unwrap().clone();
			s.insert(
				parent_key_id.clone(),
				RestoredTxStats {
					log_id: ts.log_id,
					amount_credited: ts.amount_credited + output.value,
					num_outputs: ts.num_outputs + 1,
					output_height: output.height,
				},
			);
			ts.log_id
		} else {
			0
		}
	};

	let _ = batch.save(OutputData {
		root_key_id: parent_key_id.clone(),
		key_id: output.key_id,
		n_child: output.n_child,
		mmr_index: Some(output.mmr_index),
		commit: commit,
		value: output.value,
		status: OutputStatus::Unspent,
		height: output.height,
		lock_height: output.lock_height,
		is_coinbase: output.is_coinbase,
		tx_log_entry: Some(log_id),
	});

	let max_child_index = found_parents.get(&parent_key_id).unwrap().clone();
	if output.n_child >= max_child_index {
		found_parents.insert(parent_key_id.clone(), output.n_child);
	}

	batch.commit()?;
	Ok(())
}

#[derive(Debug)]
struct WalletOutputInfo {
	updated: bool,  // true if data was updated, we need push it into DB
	at_chain: bool, // true if this Output was founf at the Chain
	output: OutputData,
	commit: String,              // commit as a string. output.output value
	tx_input_uuid: Vec<String>,  // transactions where this commit is input
	tx_output_uuid: Vec<String>, // transactions where this commit is output
}

impl WalletOutputInfo {
	pub fn new(output: OutputData) -> WalletOutputInfo {
		let commit = output.commit.clone().unwrap_or_else(|| String::new());
		WalletOutputInfo {
			updated: false,
			at_chain: false,
			output,
			commit,
			tx_input_uuid: Vec::new(),
			tx_output_uuid: Vec::new(),
		}
	}

	pub fn add_tx_input_uuid(&mut self, uuid: &str) {
		self.tx_input_uuid.push(String::from(uuid));
	}

	pub fn add_tx_output_uuid(&mut self, uuid: &str) {
		self.tx_output_uuid.push(String::from(uuid));
	}

	// Output that is not active and not mapped to any transaction.
	pub fn is_orphan_output(&self) -> bool {
		self.tx_input_uuid.len() == 0
			&& self.tx_output_uuid.len() == 0
			&& !self.output.is_spendable()
	}
}

#[derive(Debug)]
struct WalletTxInfo {
	updated: bool,   // true if data was updated, we need push it into DB
	tx_uuid: String, // transaction uuid, full name
	tx_log: TxLogEntry,
	input_commit: Vec<String>,  // Commits from input (if found)
	output_commit: Vec<String>, // Commits from output (if found)
}

impl WalletTxInfo {
	pub fn new(tx_log: TxLogEntry) -> WalletTxInfo {
		WalletTxInfo {
			updated: false,
			tx_uuid: match tx_log.tx_slate_id {
				Some(uuid) => uuid.to_string(),
				None => String::new(),
			},
			tx_log,
			input_commit: Vec::new(),
			output_commit: Vec::new(),
		}
	}

	// read all commit from the transaction tx.
	pub fn add_transaction(&mut self, tx: Transaction) {
		for input in &tx.body.inputs {
			self.input_commit
				.push(util::to_hex(input.commit.0.to_vec()));
		}

		for output in tx.body.outputs {
			self.output_commit
				.push(util::to_hex(output.commit.0.to_vec()));
		}
	}

	// return true if output was added. false - output already exist
	pub fn add_output(&mut self, commit: &String) -> bool {
		if self.input_commit.contains(commit) || self.output_commit.contains(commit) {
			false
		} else {
			self.output_commit.push(commit.clone());
			true
		}
	}

	// Output that is not active and not mapped to any transaction.
	pub fn is_orphan_transaction(&self, outputs: &HashMap<String, WalletOutputInfo>) -> bool {
		if self.tx_log.is_cancelled() {
			false
		} else {
			let outputs = self
				.input_commit
				.iter()
				.filter(|commit| outputs.contains_key(*commit))
				.count() + self
				.output_commit
				.iter()
				.filter(|commit| outputs.contains_key(*commit))
				.count();
			outputs == 0
		}
	}
}

// Getting: - transactions from wallet,
//          - outputs from wallet
//			- outputs from the chain
// Then build the transaction map that mapped to Outputs and
//     Outputs map that mapped to the transactions
fn get_wallet_and_chain_data<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<
	(
		HashMap<String, WalletOutputInfo>, // Slate based Outputs. Key: Commit
		HashMap<u64, WalletOutputInfo>,    // Coin Based Outputs. Key: height
		Vec<OutputResult>,                 // Chain outputs
		HashMap<String, WalletTxInfo>,     // Slate based Transaction. Key: tx uuid
		HashMap<u64, WalletTxInfo>,        // Coin Based Transaction.  Key: height
		(u64, u64),                        // PMMR index range for chain
		u64,                               // last Index that was scanned
	),
	Error,
>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Building the maps for

	wallet_lock!(wallet_inst, w);

	let client = w.w2n_client().clone();
	let keychain = w.keychain(keychain_mask)?.clone();

	// Retrieve the actual PMMR index range we're looking for
	let pmmr_range = client.height_range_to_pmmr_indices(start_height, Some(end_height))?;

	// Getting outputs that are published on the chain.
	let (chain_outs, last_index) = collect_chain_outputs(
		&keychain,
		client,
		pmmr_range.0,
		Some(pmmr_range.1),
		status_send_channel,
	)?;

	// Reporting user what outputs we found
	if let Some(ref s) = status_send_channel {
		let mut msg = format!(
			"For height: {} - {} PMMRs: {} - {} Identified {} wallet_outputs as belonging to this wallet [",
			start_height, end_height, pmmr_range.0, pmmr_range.1,
			chain_outs.len(),
		);
		for ch_out in &chain_outs {
			msg.push_str(&util::to_hex(ch_out.commit.0.to_vec()));
			msg.push_str(",");
		}
		if !chain_outs.is_empty() {
			msg.pop();
		}
		msg.push_str("]");

		let _ = s.send(StatusMessage::Scanning(msg, 99));
	}

	// Resulting wallet's outputs with extended info
	// Key: commit
	let mut outputs_slates: HashMap<String, WalletOutputInfo> = HashMap::new();
	let mut outputs_coinbased: HashMap<u64, WalletOutputInfo> = HashMap::new();

	// Collecting Outputs with known commits only.
	// Really hard to say why Output can be without commit. Probably same non complete or failed data.
	// In any case we can't use it for recovering.
	for w_out in w.iter() {
		if w_out.is_coinbase {
			outputs_coinbased.insert(w_out.height, WalletOutputInfo::new(w_out.clone()));
		} else {
			outputs_slates.insert(
				w_out.commit.clone().unwrap(),
				WalletOutputInfo::new(w_out.clone()),
			);
		}
	}

	// Wallet's transactions with extended info
	// Key: transaction uuid
	let mut transactions_slate: HashMap<String, WalletTxInfo> = HashMap::new();
	let mut transactions_id2uuid: HashMap<u32, String> = HashMap::new();

	let mut transactions_coinbase: HashMap<u64, WalletTxInfo> = HashMap::new();

	// Collecting Transactions from the wallet. UUID need to be known, otherwise
	// transaction is non complete and can be ignored.
	for tx in w.tx_log_iter() {
		match tx.tx_slate_id {
			Some(tx_slate_id) => {
				// Slate base transaction
				let uuid_str = tx_slate_id.to_string();

				let mut wtx = WalletTxInfo::new(tx.clone());

				if let Ok(transaction) = w.get_stored_tx_by_uuid(&uuid_str) {
					wtx.add_transaction(transaction);
				};

				// updated output vs Transactions mapping
				for com in &wtx.input_commit {
					if let Some(w_out) = outputs_slates.get_mut(com) {
						w_out.add_tx_input_uuid(&uuid_str);
					}
				}
				for com in &wtx.output_commit {
					if let Some(w_out) = outputs_slates.get_mut(com) {
						w_out.add_tx_output_uuid(&uuid_str);
					}
				}
				transactions_slate.insert(uuid_str.clone(), wtx);
				transactions_id2uuid.insert(tx.id, uuid_str);
			}
			None => {
				// Coin based transactions
				transactions_coinbase.insert(tx.output_height, WalletTxInfo::new(tx.clone()));
			}
		}
	}

	// Apply Output to transaction mapping from Outputs
	// Normally Outputs suppose to have transaction Id.
	for w_out in outputs_slates.values_mut() {
		let commit = w_out.commit.clone();
		if let Some(tx_id) = w_out.output.tx_log_entry {
			if let Some(tx_uuid) = transactions_id2uuid.get_mut(&tx_id) {
				if transactions_slate
					.get_mut(tx_uuid)
					.unwrap()
					.add_output(&commit)
				{
					w_out.add_tx_output_uuid(tx_uuid);
				}
			}
		}
	}

	Ok((
		outputs_slates,
		outputs_coinbased,
		chain_outs,
		transactions_slate,
		transactions_coinbase,
		pmmr_range,
		last_index,
	))
}

/// Check / repair wallet contents by scanning against chain
/// assume wallet contents have been freshly updated with contents
/// of latest block
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	_delete_unconfirmed: bool,
	start_height: u64,
	end_height: u64,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ScannedBlockInfo, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// First, get a definitive list of outputs we own from the chain
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::Scanning("Starting UTXO scan".to_owned(), 0));
	}

	let (
		mut outputs_slates,
		mut outputs_coinbased,
		chain_outs,
		mut transactions_slates,
		mut transactions_coinbased,
		pmmr_range,
		last_index,
	) = get_wallet_and_chain_data(
		wallet_inst.clone(),
		keychain_mask.clone(),
		start_height,
		end_height,
		status_send_channel,
	)?;

	/*	// Printing values for debug...
	{
		println!("Chain range: Heights: {} to {}  PMMRs: {} to {}", start_height, end_height, pmmr_range.0, pmmr_range.1 );
		// Dump chain outputs...
		for ch_out in &chain_outs {
			println!("Chain output: {:?}", ch_out );
		}

		println!("outputs_slates len is {}", outputs_slates.len());
		for o in &outputs_slates {
			println!("{}  =>  {:?}", o.0, o.1 );
		}
		println!("outputs_coinbased len is {}", outputs_coinbased.len());
		for o in &outputs_coinbased {
			println!("{}  =>  {:?}", o.0, o.1 );
		}

		println!("transactions_slates len is {}", transactions_slates.len());
		for t in &transactions_slates {
			println!("{}  =>  {:?}", t.0, t.1 );
		}

		println!("transactions_coinbased len is {}", transactions_coinbased.len());
		for t in &transactions_coinbased {
			println!("{}  =>  {:?}", t.0, t.1 );
		}
	}*/

	let mut found_parents: HashMap<Identifier, u32> = HashMap::new();

	// Update wallet outputs with found at the chain outputs
	// Check how sync they are
	for ch_out in &chain_outs {
		let output_res = if ch_out.is_coinbase {
			outputs_coinbased.get_mut(&ch_out.height)
		} else {
			let commit = util::to_hex(ch_out.commit.0.to_vec());
			outputs_slates.get_mut(&commit)
		};

		match output_res {
			Some(w_out) => {
				// w_out - is wallet outputs that match chain output ch_out.
				// It is mean that w_out does exist at the chain (confirmed) and doing well
				w_out.at_chain = true;

				// Updating mmr Index for output. It can be changes because of reorg
				// It is normal routine event, no need to notify the user.
				if w_out.output.height != ch_out.height {
					w_out.output.height = ch_out.height;
					w_out.updated = true;
				}

				// Validating status of the output.
				match w_out.output.status {
					OutputStatus::Spent => {
						// Spent output not supposed to exist at the chain. Seems like send transaction is not at the chain yet.
						// Reverting state to Locked
						if let Some(ref s) = status_send_channel {
							let _ = match &w_out.output.commit {
								Some(commit) => s.send(StatusMessage::Info(format!("Warning: Changing status for output {} from Spent to Locked", commit))),
								None => s.send(StatusMessage::Info(format!("Warning: Changing status for coin base output at height {} from Spent to Locked", w_out.output.height))),
							};
						}
						w_out.updated = true;
						w_out.output.status = OutputStatus::Locked;
					}
					OutputStatus::Unconfirmed => {
						// Very expected event. Output is at the chain and we get a confirmation.
						if let Some(ref s) = status_send_channel {
							let _ = match &w_out.output.commit {
								Some(commit) => s.send(StatusMessage::Info(format!("Warning: Changing status for output {} from Unconfirmed to Unspent", commit))),
								None => s.send(StatusMessage::Info(format!("Warning: Changing status for coin base output at height {} from Unconfirmed to Unspent", w_out.output.height))),
							};
						}
						w_out.updated = true;
						w_out.output.status = OutputStatus::Unspent; // confirmed...
					}
					OutputStatus::Unspent => (), // Expected, Unspend is confirmed.
					OutputStatus::Locked => (),  // Expected, Locked is confirmed. Send still in progress
				};
			}
			None => {
				// Spotted unknow output. Probably another copy of wallet send it or it is a backup data?
				// In any case it is pretty nice output that we can spend.
				// Just create a new transaction for this output.
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Info(format!(
						"Warning: Confirmed output for {} with ID {} ({:?}, index {}) exists in UTXO set but not in wallet. Restoring.",
						ch_out.value, ch_out.key_id, ch_out.commit, ch_out.mmr_index
					)));
				}
				restore_missing_output(
					wallet_inst.clone(),
					keychain_mask,
					ch_out.clone(),
					&mut found_parents,
					&mut None,
				)?;
			}
		}
	}

	// -------------------------------------------------------
	// Processing coinbased data

	// Process Coin based not found at the chain but expected outputs.
	for w_out in outputs_coinbased.values_mut() {
		// Checking if output in this sync renge period if
		if w_out.output.height > start_height && !w_out.at_chain {
			match w_out.output.status {
				OutputStatus::Spent => (), // Spent not expected to be found at the chain
				OutputStatus::Unconfirmed => (), // Unconfirmed not expected as well
				OutputStatus::Unspent => {
					// Unspent not found - likely it is reorg and that is why the last transaction can't be confirmed now.
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Warning: Changing status for output {} from Unspent to Unconfirmed",
							w_out.commit
						)));
					}
					w_out.updated = true;
					w_out.output.status = OutputStatus::Unconfirmed;
				}
				OutputStatus::Locked => {
					// Locked is not on the chain is expected, It is mean that our send transaction was confirmed.
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Info: Changing status for output {} from Locked to Spent",
							w_out.commit
						)));
					}
					w_out.updated = true;
					w_out.output.status = OutputStatus::Spent;
				}
			};

			// Updating coinbase transaction as well.
			if let Some(w_tx) = transactions_coinbased.get_mut(&w_out.output.height) {
				if w_tx.tx_log.confirmed {
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Warning: Marked coin base transaction at height {} is not confirmed.",
							w_out.output.height
						)));
					}
					w_tx.tx_log.confirmed = false;
					w_tx.updated = true;
				}
			} else {
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::UpdateWarning(format!(
						"Found non confirmed coin base output at height {} without transaction.",
						w_out.output.height
					)));
				}
			}
		} else {
			// Sync up transaction state with Output state
			let transaction_confirmed = match w_out.output.status {
				OutputStatus::Unconfirmed => false,
				OutputStatus::Unspent | OutputStatus::Locked | OutputStatus::Spent => true,
			};

			if let Some(w_tx) = transactions_coinbased.get_mut(&w_out.output.height) {
				if w_tx.tx_log.confirmed != transaction_confirmed {
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!("Warning: Change confirmation status for coin base transaction at height {} from {} to {}.", w_out.output.height, w_tx.tx_log.confirmed, transaction_confirmed )));
					}
					w_tx.tx_log.confirmed = transaction_confirmed;
					w_tx.updated = true;
				}
			} else {
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::UpdateWarning(format!(
						"Found non confirmed coin base output at height {} without transaction.",
						w_out.output.height
					)));
				}
			}
		}
	}

	// Let's clean output based transactions that are orphans
	// Just mark them as non confirmed,
	for w_tx in transactions_coinbased.values_mut() {
		if !outputs_coinbased.contains_key(&w_tx.tx_log.output_height) {
			if w_tx.tx_log.confirmed {
				w_tx.tx_log.confirmed = false;
				w_tx.updated = true;
			}
		}
	}

	// ------------------------------------------------------------------
	// Processing Slate based data

	// Process not found at the chain but expected outputs.
	// It is a normal case when send transaction was finalized
	for w_out in outputs_slates.values_mut() {
		if w_out.output.height > start_height && !w_out.at_chain {
			match w_out.output.status {
				OutputStatus::Spent => (), // Spent not expected to be found at the chain
				OutputStatus::Unconfirmed => (), // Unconfirmed not expected as well
				OutputStatus::Unspent => {
					// Unspent not found - likely it is reorg and that is why the last transaction can't be confirmed now.
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Warning: Changing status for output {} from Unspent to Unconfirmed",
							w_out.commit
						)));
					}
					w_out.updated = true;
					w_out.output.status = OutputStatus::Unconfirmed;
				}
				OutputStatus::Locked => {
					// Locked is not on the chain is expected, It is mean that our send transaction was confirmed.
					if let Some(ref s) = status_send_channel {
						let _ = s.send(StatusMessage::Info(format!(
							"Info: Changing status for output {} from Locked to Spent",
							w_out.commit
						)));
					}
					w_out.updated = true;
					w_out.output.status = OutputStatus::Spent;
				}
			};
		}
	}

	// We are done with outputs, let's process transactions... Just need to update 'confirmed flag' and height
	// We don't want to cancel the transactions. Let's user do that.
	for tx_info in transactions_slates.values_mut() {
		let tx_type = tx_info.tx_log.tx_type.clone();

		// Skipping cancelled transactions, thay processed below
		if tx_type == TxLogEntryType::TxReceivedCancelled
			|| tx_type == TxLogEntryType::TxSentCancelled
		{
			continue; // Processing not cancelled transactions. Cancelled will be reactivated as a recovery plan.
		}

		// Collecting known (belong to this wallet) inputs and outputs
		let mut inputs_status: HashSet<OutputStatus> = HashSet::new();
		let mut output_status: HashSet<OutputStatus> = HashSet::new();
		let mut tx_height = tx_info.tx_log.output_height;

		for out in &tx_info.input_commit {
			if let Some(out) = outputs_slates.get(out) {
				inputs_status.insert(out.output.status.clone());

				if tx_height < out.output.height {
					tx_height = out.output.height;
				}
			}
		}

		for out in &tx_info.output_commit {
			if let Some(out) = outputs_slates.get(out) {
				output_status.insert(out.output.status.clone());

				if tx_height < out.output.height {
					tx_height = out.output.height;
				}
			}
		}

		// Validating transaction confirmation flag. True - flag is falid. False - need to be chaged
		let tx_confirmation = match tx_type {
			TxLogEntryType::ConfirmedCoinbase => {
				// Confirmed Coinbase expected allways exist. If it is gone, mean miner got orphan block. That need to be cancelled.
				output_status.contains(&OutputStatus::Unspent)
					|| output_status.contains(&OutputStatus::Locked)
					|| output_status.contains(&OutputStatus::Spent)
			}
			TxLogEntryType::TxSent => {
				// Confirmed send expected that Inputs are NOT VALID;  Outputs are VALID
				if inputs_status.len() == 0
					|| inputs_status.contains(&OutputStatus::Unspent)
					|| inputs_status.contains(&OutputStatus::Locked)
					|| inputs_status.contains(&OutputStatus::Unconfirmed)
				{
					false
				} else if output_status.contains(&OutputStatus::Unconfirmed) {
					false
				} else {
					true
				}
			}
			TxLogEntryType::TxReceived => {
				// Confirmed receive expect that Output are VALID or Spent
				if output_status.len() == 0 || output_status.contains(&OutputStatus::Unconfirmed) {
					false
				} else {
					true
				}
			}
			_ => {
				assert!(false);
				false
			}
		};

		// Checking if transaction 'confirmed' flag match excpected.
		if tx_info.tx_log.confirmed != tx_confirmation {
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Info(format!(
					"Info: Changing transaction {} confirmation state from {:?} to {:?}",
					tx_info.tx_uuid, tx_info.tx_log.confirmed, tx_confirmation
				)));
			}
			tx_info.tx_log.confirmed = tx_confirmation;
			tx_info.updated = true;
		}

		// Updating height if needed
		if tx_height != tx_info.tx_log.output_height {
			tx_info.tx_log.output_height = tx_height;
			tx_info.updated = true;
		}
	}

	// Checking for output to transaction mapping. We don't want to see active outputs without trsansaction or with cancelled transactions
	// we might unCancel transaction if output was found but all mapped transactions are cancelled (user just a cheater)
	for w_out in outputs_slates.values() {
		// For every output checking to how many transaction it belong as Input and Output
		let in_cancelled = w_out
			.tx_input_uuid
			.iter()
			.filter(|tx_uuid| {
				transactions_slates
					.get(*tx_uuid)
					.unwrap()
					.tx_log
					.is_cancelled()
			})
			.count();
		let in_active = w_out.tx_input_uuid.len() - in_cancelled;

		let out_cancelled = w_out
			.tx_output_uuid
			.iter()
			.filter(|tx_uuid| {
				transactions_slates
					.get(*tx_uuid)
					.unwrap()
					.tx_log
					.is_cancelled()
			})
			.count();
		let out_active = w_out.tx_output_uuid.len() - in_cancelled;

		// Commit can belong to 1 transaction only. Other wise it is a transaction issue.
		// Fortunatelly transaction issue doesn't affect the balance of send logic.
		// So we can just report to user that he can't trust the transactions Data
		if out_active > 1 {
			report_transaction_collision(
				status_send_channel,
				&w_out.tx_output_uuid,
				&mut transactions_slates,
				false,
			);
		}

		if in_active > 1 {
			report_transaction_collision(
				status_send_channel,
				&w_out.tx_input_uuid,
				&mut transactions_slates,
				true,
			);
		}

		match w_out.output.status {
			OutputStatus::Locked | OutputStatus::Spent => {
				// output have to have some valid transation. User cancel all of them?
				if out_active == 0 && out_cancelled > 0 {
					recover_first_cancelled(
						status_send_channel,
						&w_out.tx_output_uuid,
						&mut transactions_slates,
					);
				}
				if in_active == 0 && in_cancelled > 0 {
					recover_first_cancelled(
						status_send_channel,
						&w_out.tx_input_uuid,
						&mut transactions_slates,
					);
				}
			}
			OutputStatus::Unconfirmed => {
				// Unconfirmed can be anything. We can delete that output
			}
			OutputStatus::Unspent => {
				// output have to have some valid transaction that created it. User cancel all of them?
				if out_active == 0 && out_cancelled > 0 {
					recover_first_cancelled(
						status_send_channel,
						&w_out.tx_output_uuid,
						&mut transactions_slates,
					);
				}
			}
		}
	}

	// Here we are done with all state changes of Outputs and transactions. Now we need to vase them at the DB
	// Note, unknown new outputs are not here because we handle them in the beginning by 'restore'.

	// Apply last data updates and saving the data into DB.
	{
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;

		// Slate based Transacitons
		for tx in transactions_slates.values() {
			// Cancel orphan transactions (transaction without know outputs in this wallet)
			// It is edge case, normally wallet save outputs into DB.
			if tx.is_orphan_transaction(&outputs_slates) {
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Info(format!(
						"Warning: Cancelling orphan transaction {}",
						tx.tx_uuid
					)));
				}

				let mut tx_log = tx.tx_log.clone();

				// Orphan transaction need to be cancelled.
				tx_log.tx_type = match tx_log.tx_type {
					TxLogEntryType::ConfirmedCoinbase => TxLogEntryType::TxReceivedCancelled,
					TxLogEntryType::TxReceived => TxLogEntryType::TxReceivedCancelled,
					TxLogEntryType::TxSent => TxLogEntryType::TxSentCancelled,
					t => {
						assert!(false);
						t
					}
				};
				batch.save_tx_log_entry(tx_log, &tx.tx_log.parent_key_id)?;
			} else if tx.updated {
				batch.save_tx_log_entry(tx.tx_log.clone(), &tx.tx_log.parent_key_id)?;
			}
		}

		// Coin Based transaction.
		for tx in transactions_coinbased.values() {
			if tx.updated {
				batch.save_tx_log_entry(tx.tx_log.clone(), &tx.tx_log.parent_key_id)?;
			}
		}

		// Save Slate Outputs to DB
		for output in outputs_slates.values() {
			if output.updated {
				batch.save(output.output.clone())?;
			}

			// Unconfirmed without any transactions must be deleted as well
			if output.is_orphan_output() {
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Info(format!( "Warning: Deleting record about unconfirmed Output without any transaction. Commit: {}", output.output.commit.clone().unwrap() )));
				}
				batch.delete(&output.output.key_id, &output.output.mmr_index)?;
			}
		}

		// Save coin based Outputs to DB
		for output in outputs_coinbased.values() {
			if output.updated {
				batch.save(output.output.clone())?;
			}
		}


		// It is very normal that Wallet has outputs without Transactions.
		// It is a coinbase transactions. Let's create coinbase transactions if they don't exist yet
		// See what updater::apply_api_outputs does
		for w_out in outputs_coinbased.values_mut() {
			if !transactions_coinbased.contains_key(&w_out.output.height) {

				let parent_key_id = &w_out.output.root_key_id; // it is Account Key ID.

				let log_id = batch.next_tx_log_id(parent_key_id)?;
				let mut t = TxLogEntry::new(
					parent_key_id.clone(),
					TxLogEntryType::ConfirmedCoinbase,
					log_id,
				);
				t.confirmed = true;
				t.output_height = w_out.output.height;
				t.amount_credited = w_out.output.value;
				t.amount_debited = 0;
				t.num_outputs = 1;
				// calculate kernel excess for coinbase
				if w_out.output.commit.is_some()
				{
					let secp = static_secp_instance();
					let secp = secp.lock();
					let over_commit = secp.commit_value(w_out.output.value)?;
					let commit = pedersen::Commitment::from_vec(
						util::from_hex( w_out.output.commit.clone().unwrap() )
								.map_err(|e| Error::from(ErrorKind::GenericError( format!("Output commit parse error {:?}",e)) ))?
					);
					let excess =
						secp.commit_sum(vec![commit], vec![over_commit])?;
					t.kernel_excess = Some(excess);
					t.kernel_lookup_min_height = Some(w_out.output.height);
				}
				t.update_confirmation_ts();
				w_out.output.tx_log_entry = Some(log_id);

				batch.save_tx_log_entry(t, parent_key_id)?;
				batch.save(w_out.output.clone())?;
			}
		}

		batch.commit()?;
	}

	{
		// restore labels, account paths and child derivation indices
		wallet_lock!(wallet_inst, w);
		let label_base = "account";
		let accounts: Vec<Identifier> = w.acct_path_iter().map(|m| m.path).collect();
		let mut acct_index = accounts.len();
		for (path, max_child_index) in found_parents.iter() {
			// Only restore paths that don't exist
			if !accounts.contains(path) {
				let label = format!("{}_{}", label_base, acct_index);
				if let Some(ref s) = status_send_channel {
					let _ = s.send(StatusMessage::Info(format!(
						"Info: Setting account {} at path {}",
						label, path
					)));
				}
				keys::set_acct_path(&mut **w, keychain_mask, &label, path)?;
				acct_index += 1;
			}
			let current_child_index = w.current_child_index(&path)?;
			if *max_child_index >= current_child_index {
				let mut batch = w.batch(keychain_mask)?;
				debug!("Next child for account {} is {}", path, max_child_index + 1);
				batch.save_child_index(path, max_child_index + 1)?;
				batch.commit()?;
			}
		}
	}

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::ScanningComplete(
			"Scanning Complete".to_owned(),
		));
	}

	Ok(ScannedBlockInfo {
		height: end_height,
		hash: "".to_owned(),
		start_pmmr_index: pmmr_range.0,
		last_pmmr_index: last_index,
	})
}

// Report to user about transactions that point to the same output.
fn report_transaction_collision(
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_uuid: &Vec<String>,
	transactions: &mut HashMap<String, WalletTxInfo>,
	inputs: bool,
) {
	if let Some(ref s) = status_send_channel {
		let mut cancelled_tx_idx = String::new();
		tx_uuid
			.iter()
			.map(|tx_uuid| transactions.get(tx_uuid).unwrap())
			.filter(|wtx| !wtx.tx_log.is_cancelled())
			.for_each(|wtx| {
				if cancelled_tx_idx.len() > 0 {
					cancelled_tx_idx.push_str(", ");
				}
				cancelled_tx_idx.push_str(&format!("{}", wtx.tx_log.id));
			});

		let inputs = if inputs { "inputs" } else { "outputs" };

		let _ = s.send(StatusMessage::UpdateWarning(format!(
			"Warning: We detected transaction collision on {} for transactions with Id {}",
			inputs, cancelled_tx_idx
		)));
	}
}

// By some reasons output exist but all related transactions are cancelled. Let's activate one of them
// Note! There is no analisys what transaction to activate. As a result that can trigger the transaction collision.
// We don't want to implement complicated algorithm to handle that. User suppose to be sane and not cancell transactions without reason.
fn recover_first_cancelled(
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_uuid: &Vec<String>,
	transactions: &mut HashMap<String, WalletTxInfo>,
) {
	// let's revert first non cancelled
	for uuid in tx_uuid {
		let wtx = transactions.get_mut(uuid).unwrap();
		if wtx.tx_log.is_cancelled() {
			let prev_tx_state = wtx.tx_log.tx_type.clone();
			wtx.tx_log.tx_type = match wtx.tx_log.tx_type {
				TxLogEntryType::TxReceivedCancelled => TxLogEntryType::TxReceived,
				TxLogEntryType::TxSentCancelled => TxLogEntryType::TxSent,
				_ => panic!(
					"Internal error. Expected cancelled transaction, but get different value"
				),
			};
			wtx.updated = true;
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::Info(format!(
					"Changing transaction {} state from {:?} to {:?}",
					wtx.tx_uuid, prev_tx_state, wtx.tx_log.tx_type
				)));
			}

			break;
		}
	}
}
