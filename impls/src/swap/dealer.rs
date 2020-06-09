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

use blake2_rfc::blake2b::blake2b;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::{fs, path};
use std::{thread, time};

use super::message::SwapConfig;
use crate::error::{Error, ErrorKind};
use crate::libwallet::internal::keys;
use crate::libwallet::{NodeClient, OutputStatus, WalletBackend, WalletInst, WalletLCProvider};
use crate::node_clients::http::HTTPNodeClient;
use crate::util::Mutex;
use crate::{Address, MWCMQPublisher, Publisher};

use grin_keychain::{ExtKeychain, Identifier, Keychain};

use bitcoin::Address as BtcAddress;
use grin_wallet_libwallet::internal::updater::retrieve_outputs;
use grinswap::swap::bitcoin::{BtcSwapApi, ElectrumNodeClient};
use grinswap::swap::message::{Message, Update};
use grinswap::{Action, Context, Currency, Status, Swap, SwapApi};
use std::str::FromStr;

pub const SWAP_DEAL_SAVE_DIR: &'static str = "saved_swap_deal";

/// Helper for taking a lock on the wallet instance
#[macro_export]
macro_rules! wallet_lock {
	($wallet_inst: expr, $wallet: ident) => {
		let inst = $wallet_inst.clone();
		let mut w_lock = inst.lock();
		let w_provider = w_lock.lc_provider()?;
		let $wallet = w_provider.wallet_inst()?;
	};
}

fn _keychain(idx: u8) -> ExtKeychain {
	let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
	let seed_sell = blake2b(32, &[], seed_sell.as_bytes());
	ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
}

// Init for file storage for saving swap deals
fn init_swap_backend(data_file_dir: &str) -> Result<(), Error> {
	let stored_swap_deal_path = path::Path::new(data_file_dir).join(SWAP_DEAL_SAVE_DIR);
	fs::create_dir_all(&stored_swap_deal_path)
		.expect("Could not create swap deal storage directory!");
	Ok(())
}

// Get swap deal from the storage
fn get_swap_deal(data_file_dir: &str, swap_id: &str) -> Result<Swap, Error> {
	let filename = format!("{}.swap", swap_id);
	let path = path::Path::new(data_file_dir)
		.join(SWAP_DEAL_SAVE_DIR)
		.join(filename);
	let swap_deal_file = Path::new(&path).to_path_buf();
	if !swap_deal_file.exists() {
		return Err(ErrorKind::SwapDealGenericError(
			swap_deal_file.to_str().unwrap_or(&"UNKNOWN").to_string(),
		)
		.into());
	}
	let mut swap_deal_f = File::open(swap_deal_file).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!("Unable to get saved swap from Json, {}", e))
	})?;
	let mut content = String::new();
	swap_deal_f.read_to_string(&mut content).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!(
			"Unable to read the content of the swap file, {}",
			e
		))
	})?;

	Ok((serde_json::from_str(&content).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!("Unable to get saved swap from Json, {}", e))
	}))?)
}

// Store swap deal to a file
fn store_swap_deal(swap: &Swap, data_file_dir: &str, swap_id: &str) -> Result<(), Error> {
	let filename = format!("{}.swap", swap_id);
	let path = path::Path::new(data_file_dir)
		.join(SWAP_DEAL_SAVE_DIR)
		.join(filename);
	let path_buf = Path::new(&path).to_path_buf();
	let mut stored_swap = File::create(path_buf).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!(
			"Unable to create the file to store swap deal, {}",
			e
		))
	})?;
	let swap_ser = serde_json::to_string(swap).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!("Unable to convert swap to Json, {}", e))
	})?;
	stored_swap.write_all(&swap_ser.as_bytes()).map_err(|e| {
		ErrorKind::SwapDealGenericError(format!("Unable to write swap deal to file, {}", e))
	})?;
	stored_swap.sync_all().map_err(|e| {
		ErrorKind::SwapDealGenericError(format!(
			"Unable to sync all after writing swap deal, {}",
			e
		))
	})?;
	Ok(())
}

pub struct SwapDealer {}

impl SwapDealer {
	pub fn new() -> SwapDealer {
		Self {}
	}

	fn context_sell<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		api_sell: &mut BtcSwapApi<HTTPNodeClient, ElectrumNodeClient>,
	) -> Context
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		let parent_key_id = wallet.parent_key_id();
		let inputs =
			retrieve_outputs(wallet, None, false, None, &parent_key_id, None, None).unwrap();
		let mut input_vec: Vec<(Identifier, u64)> = vec![];
		for input in inputs {
			if input.output.status == OutputStatus::Unspent {
				input_vec.push((input.output.key_id, input.output.value));
			}
		}

		let kc = wallet.keychain(None).unwrap();

		// Generate the appropriate amount of derivation paths
		let key_count = api_sell
			.context_key_count(&kc, Currency::Btc, true)
			.unwrap();
		let mut keys = Vec::with_capacity(key_count);
		for _ in 0..key_count {
			let id = keys::next_available_key(wallet, None).unwrap();
			keys.push(id);
		}

		api_sell
			.create_context(&kc, Currency::Btc, true, Some(input_vec), keys)
			.unwrap()
	}

	fn context_buy<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		api_buy: &mut BtcSwapApi<HTTPNodeClient, ElectrumNodeClient>,
	) -> Context
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		let kc = wallet.keychain(None).unwrap();

		// Generate the appropriate amount of derivation paths/
		let key_count = api_buy.context_key_count(&kc, Currency::Btc, true).unwrap();
		let mut keys = Vec::with_capacity(key_count);
		for _ in 0..key_count {
			let id = keys::next_available_key(wallet, None).unwrap();
			keys.push(id);
		}

		api_buy
			.create_context(&kc, Currency::Btc, false, None, keys)
			.unwrap()
	}

	pub fn make_buy_mwc<'a, T: ?Sized, C, K>(
		&self,
		_wallet: &mut T,
		_rate: u64,
		_qty: u64,
		_mwc_node_uri: &str,
		_node_api_secret: Option<String>,
		_electrum_node_uri: &str,
		_publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		Ok(())
	}

	pub fn take_sell_mwc<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		rate: u64,
		qty: u64,
		btc_redeem: &str,
		address: &str,
		mwc_node_uri: &str,
		node_api_secret: Option<String>,
		electrum_node_uri: &str,
		publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(mwc_node_uri, node_api_secret).unwrap();
		let btc_node_client = ElectrumNodeClient::new(electrum_node_uri.to_string(), true);

		let kc_sell = wallet.keychain(None).unwrap();
		let mut api_sell = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_sell = self.context_sell(wallet, &mut api_sell);

		let btc_amount_sats = ((qty as f64 / 1_000_000_000 as f64) * (rate as f64)) as u64;
		println!("_qty = {}", qty);
		println!("_rate = {}", rate);
		println!("btc amount is {}", btc_amount_sats);

		let (mut swap_sell, _action) = api_sell
			.create_swap_offer(
				&kc_sell,
				&ctx_sell,
				None,
				qty,
				btc_amount_sats,
				Currency::Btc,
				btc_redeem.to_owned(),
			)
			.unwrap();

		let message = api_sell.message(&kc_sell, &swap_sell).unwrap();
		let _res = publisher.post_take(&message, address);

		let action = api_sell
			.message_sent(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(swap_sell.status, Status::Offered);
		assert_eq!(action, Action::ReceiveMessage);
		println!("In swap, I am done creating the offer. ");
		store_swap_deal(
			&swap_sell,
			wallet.get_data_file_dir(),
			&swap_sell.id.to_string(),
		)
		.map_err(|e| {
			ErrorKind::SwapDealGenericError(format!(
				"Unable to save the swap deal from take sell, {}",
				e
			))
		})?;

		Ok(())
	}

	pub fn make_sell_mwc<'a, T: ?Sized, C, K>(
		&self,
		_wallet: &mut T,
		_rate: u64,
		_qty: u64,
		_btc_redeem: &str,
		_mwc_node_uri: &str,
		_node_api_secret: Option<String>,
		_electrum_node_uri: &str,
		_publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		Ok(())
	}

	pub fn take_buy_mwc<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		rate: u64,
		qty: u64,
		btc_redeem: &str,
		address: &str,
		mwc_node_uri: &str,
		node_api_secret: Option<String>,
		electrum_node_uri: &str,
		publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(mwc_node_uri, node_api_secret).unwrap();
		let btc_node_client = ElectrumNodeClient::new(electrum_node_uri.to_string(), true);

		let kc_buy = wallet.keychain(None).unwrap();
		let mut api_buy = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_buy = self.context_buy(wallet, &mut api_buy);

		let (mut swap_buy, _action) = api_buy
			.create_swap_offer(
				&kc_buy,
				&ctx_buy,
				Some(address.to_string()),
				qty,
				rate * qty,
				Currency::Btc,
				btc_redeem.to_owned(),
			)
			.unwrap();

		let message = api_buy.message(&kc_buy, &swap_buy).unwrap();
		publisher
			.post_take(&message, address)
			.map_err(|e| ErrorKind::MqsGenericError(format!("Error in post_take, {}", e)))?;

		api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();
		assert_eq!(swap_buy.status, Status::Offered);

		Ok(())
	}

	pub fn swap<'a, L, C, K>(
		&self,
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		_pair: &str,
		is_make: bool,
		is_buy: bool,
		rate: u64,
		qty: u64,
		address: Option<&str>,
		publisher: &mut MWCMQPublisher,
		btc_redeem: Option<&str>,
		mwc_node_uri: &str,
		node_api_secret: Option<String>,
		electrum_node_uri: &str,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'a, C, K>,
		C: NodeClient + 'a,
		K: Keychain + 'a,
	{
		println!("Starting the swap!");
		wallet_lock!(wallet_inst, w);
		init_swap_backend((&mut **w).get_data_file_dir()).unwrap_or_else(|e| {
			error!("Unable to init swap_backend_storage {}", e);
		});

		let _res = if is_make && is_buy {
			self.make_buy_mwc(
				&mut **w,
				rate,
				qty,
				mwc_node_uri,
				node_api_secret,
				electrum_node_uri,
				publisher,
			)
		} else if is_make {
			match btc_redeem {
				Some(redeem) => self.make_sell_mwc(
					&mut **w,
					rate,
					qty,
					redeem,
					mwc_node_uri,
					node_api_secret,
					electrum_node_uri,
					publisher,
				),
				None => Ok(()),
			}
		} else if is_buy {
			match btc_redeem {
				Some(redeem) => self.take_buy_mwc(
					&mut **w,
					rate,
					qty,
					redeem,
					address.unwrap(),
					mwc_node_uri,
					node_api_secret,
					electrum_node_uri,
					publisher,
				),
				None => Ok(()),
			}
		} else {
			match btc_redeem {
				Some(redeem) => self.take_sell_mwc(
					&mut **w,
					rate,
					qty,
					redeem,
					address.unwrap(),
					mwc_node_uri,
					node_api_secret,
					electrum_node_uri,
					publisher,
				),
				None => Ok(()),
			}
		};

		return _res;
	}

	pub fn process_redeem<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		_from: &dyn Address,
		message: Message,
		_publisher: &Box<dyn Publisher + Send>,
		swap_config: SwapConfig,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(
			&swap_config.mwc_node_uri,
			swap_config.mwc_api_secret,
		)
		.map_err(|e| {
			ErrorKind::SwapNodesObtainError(format!("Failed to obtain the swap http node, {}", e))
		})?;
		let btc_node_client = ElectrumNodeClient::new(swap_config.electrum_node_uri.clone(), true);

		let kc_buy = wallet.keychain(None).unwrap();
		let mut api_buy = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_buy = self.context_buy(wallet, &mut api_buy);
		let mut swap_buy =
			get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

		loop {
			let action = api_buy
				.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
				.unwrap();
			println!("action={:?}", action);
			if action == Action::ReceiveMessage {
				break;
			}

			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);
		}

		let action = api_buy
			.receive_message(&kc_buy, &mut swap_buy, &ctx_buy, message)
			.unwrap();

		assert_eq!(action, Action::PublishTx);
		assert_eq!(swap_buy.status, Status::Redeem);
		api_buy
			.publish_transaction(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		loop {
			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);

			let action = api_buy
				.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
				.unwrap();
			println!("action={:?}", action);

			if action == Action::Complete {
				break;
			}
		}

		println!("Buyer complete!");

		/*
						// Buyer: redeem
						let action = api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap();
						assert_eq!(action, Action::ReceiveMessage);
						assert_eq!(swap_buy.status, Status::InitRedeem);
						let action = api_buy
								.receive_message(&mut swap_buy, &ctx_buy, message_4)
								.unwrap();
						assert_eq!(action, Action::PublishTx);
						assert_eq!(swap_buy.status, Status::Redeem);
						let action = api_buy
								.publish_transaction(&mut swap_buy, &ctx_buy)
								.unwrap();
						assert_eq!(action, Action::ConfirmationRedeem);
						// Buyer: complete!
						nc.mine_block();
						let action = api_buy.required_action(&mut swap_buy, &ctx_buy).unwrap();
						assert_eq!(action, Action::Complete);
						// At this point, buyer would add Grin to their outputs
						let action = api_buy.completed(&mut swap_buy, &ctx_buy).unwrap();
						assert_eq!(action, Action::None);
						assert_eq!(swap_buy.status, Status::Completed);
		*/

		Ok(())
	}

	pub fn process_init_redeem<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		from: &dyn Address,
		message: Message,
		publisher: &Box<dyn Publisher + Send>,
		swap_config: SwapConfig,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(
			&swap_config.mwc_node_uri,
			swap_config.mwc_api_secret,
		)
		.map_err(|e| {
			ErrorKind::SwapNodesObtainError(format!("Failed to obtain the swap http node, {}", e))
		})?;
		let btc_node_client = ElectrumNodeClient::new(swap_config.electrum_node_uri.clone(), true);

		let kc_sell = wallet.keychain(None).unwrap();
		let mut api_sell = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_sell = self.context_sell(wallet, &mut api_sell);

		let mut swap_sell =
			get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

		loop {
			let action = api_sell
				.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
				.unwrap();
			println!("action={:?}", action);
			if action == Action::ReceiveMessage {
				break;
			}

			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);
		}

		let _action = api_sell
			.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message)
			.unwrap();

		let signed_redeem_message = api_sell.message(&kc_sell, &swap_sell).unwrap();

		println!("signed redeem sending it back");

		let res = publisher.post_take(&signed_redeem_message, &from.get_stripped());

		if res.is_err() {
			println!("Error: {:?}", res);
		} else {
			let _action = api_sell
				.message_sent(&kc_sell, &mut swap_sell, &ctx_sell)
				.unwrap();
		}

		// Seller: publish BTC tx
		loop {
			let action = api_sell
				.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
				.unwrap();
			println!("action={:?}", action);
			if action == Action::PublishTxSecondary(Currency::Btc) {
				break;
			}

			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);
		}

		// Seller: wait for BTC confirmations
		let action = api_sell
			.publish_secondary_transaction(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();

		match action {
			Action::ConfirmationRedeemSecondary(_, _) => {}
			_ => panic!("Invalid action"),
		};

		// Seller: complete!
		let action = api_sell
			.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::Complete);
		let action = api_sell
			.completed(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();
		assert_eq!(action, Action::None);
		assert_eq!(swap_sell.status, Status::Completed);

		Ok(())
	}

	pub fn process_accept_offer<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		_from: &dyn Address,
		message: Message,
		_publisher: &Box<dyn Publisher + Send>,
		swap_config: SwapConfig,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(
			&swap_config.mwc_node_uri,
			swap_config.mwc_api_secret,
		)
		.map_err(|e| {
			ErrorKind::SwapNodesObtainError(format!("Failed to obtain the swap http node, {}", e))
		})?;
		let btc_node_client = ElectrumNodeClient::new(swap_config.electrum_node_uri.clone(), true);

		let kc_sell = wallet.keychain(None).unwrap();
		let mut api_sell = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_sell = self.context_sell(wallet, &mut api_sell);

		let mut swap_sell =
			get_swap_deal(wallet.get_data_file_dir(), &message.id.to_string()).unwrap();

		let action = api_sell
			.receive_message(&kc_sell, &mut swap_sell, &ctx_sell, message)
			.unwrap();
		assert_eq!(action, Action::PublishTx);
		assert_eq!(swap_sell.status, Status::Accepted);
		println!("Received message for publishing txs!");

		api_sell
			.publish_transaction(&kc_sell, &mut swap_sell, &ctx_sell)
			.unwrap();

		loop {
			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);
			let action = api_sell
				.required_action(&kc_sell, &mut swap_sell, &ctx_sell)
				.unwrap();
			println!("action={:?}", action);

			if action == Action::SendMessage(2) {
				break;
			}
		}

		println!("Successfully submitted!");
		Ok(())
	}

	pub fn process_offer<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		from: &dyn Address,
		message: Message,
		publisher: &Box<dyn Publisher + Send>,
		swap_config: SwapConfig,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client = HTTPNodeClient::new(
			&swap_config.mwc_node_uri,
			swap_config.mwc_api_secret,
		)
		.map_err(|e| {
			ErrorKind::SwapNodesObtainError(format!("Failed to obtain swap http node info, {}", e))
		})?;
		let btc_node_client = ElectrumNodeClient::new(swap_config.electrum_node_uri.clone(), true);

		let kc_buy = wallet.keychain(None).unwrap();
		let mut api_buy = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);
		let ctx_buy = self.context_buy(wallet, &mut api_buy);

		let (mut swap_buy, action) = api_buy
			.accept_swap_offer(&kc_buy, &ctx_buy, None, message)
			.unwrap();

		assert_eq!(swap_buy.status, Status::Offered);
		assert_eq!(action, Action::SendMessage(1));

		let accepted_message = api_buy.message(&kc_buy, &swap_buy).unwrap();
		let action = api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		let (address, btc_amount) = match action {
			Action::DepositSecondary {
				currency: _,
				amount,
				address,
			} => (address, amount),
			action_invalid => panic!("Invalid action: {:?}", action_invalid),
		};
		assert_eq!(swap_buy.status, Status::Accepted);
		let address = BtcAddress::from_str(&address).unwrap();

		let res = publisher.post_take(&accepted_message, from.get_stripped().as_str());
		if res.is_err() {
			println!("Error in post_take: {:?}", res);
		}
		println!(
			"Offer accepted! Send {} satoshis to {}",
			btc_amount, address
		);

		loop {
			let ten_seconds = time::Duration::from_millis(10000);
			thread::sleep(ten_seconds);
			let action = api_buy
				.required_action(&kc_buy, &mut swap_buy, &ctx_buy)
				.unwrap();
			println!("action={:?}", action);

			if action == Action::SendMessage(2) {
				break;
			}
		}
		println!("Successfully confirmed, now starting redeem process");

		let redeem_message = api_buy.message(&kc_buy, &swap_buy).unwrap();
		api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		publisher
			.post_take(&redeem_message, &from.get_stripped())
			.map_err(|e| ErrorKind::MqsGenericError(format!("Error in post_take, {}", e)))?;

		store_swap_deal(
			&swap_buy,
			wallet.get_data_file_dir(),
			&swap_buy.id.to_string(),
		)
		.map_err(|e| {
			ErrorKind::SwapDealGenericError(format!(
				"Unable to save the swap deal from take sell, {}",
				e
			))
		})?;
		Ok(())
	}

	pub fn process_swap_message<'a, L, C, K>(
		&self,
		wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		from: &dyn Address,
		message: Message,
		publisher: &Box<dyn Publisher + Send>,
		swap_config: SwapConfig, //publisher: Arc<Mutex<Option<Box<dyn Publisher + Send>>>>,
	) -> Result<(), Error>
	where
		L: WalletLCProvider<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		println!("Processing swap message!!!");
		wallet_lock!(wallet, w);

		let _res = match &message.inner {
			Update::Offer(_u) => {
				self.process_offer(&mut **w, from, message, publisher, swap_config)
			}
			Update::AcceptOffer(_u) => {
				self.process_accept_offer(&mut **w, from, message, publisher, swap_config)
			}
			Update::InitRedeem(_u) => {
				self.process_init_redeem(&mut **w, from, message, publisher, swap_config)
			}
			Update::Redeem(_u) => {
				self.process_redeem(&mut **w, from, message, publisher, swap_config)
			}
			_ => Err(ErrorKind::SwapMessageGenericError(format!(
				"Ran into error in swap message."
			)))?,
		}?;

		Ok(())
	}
}
