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
use std::{thread, time};

use crate::config::WalletConfig;
use crate::error::{Error, ErrorKind};
use crate::libwallet::{NodeClient, WalletBackend};
use crate::node_clients::http::HTTPNodeClient;
use crate::{Address, Publisher};

use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::key::SecretKey;

use grinswap::swap::bitcoin::{
	BtcBuyerContext, BtcNodeClient, BtcSellerContext, BtcSwapApi, ElectrumNodeClient,
	TestBtcNodeClient,
};
use grinswap::swap::message::{Message, Update};
use grinswap::swap::types::{
	BuyerContext, RoleContext, SecondaryBuyerContext, SecondarySellerContext, SellerContext,
};
use grinswap::{Action, BuyApi, Context, Currency, SellApi, Status, Swap, SwapApi};

fn _keychain(idx: u8) -> ExtKeychain {
	let seed_sell: String = format!("fixed0rng0for0testing0purposes0{}", idx % 10);
	let seed_sell = blake2b(32, &[], seed_sell.as_bytes());
	ExtKeychain::from_seed(seed_sell.as_bytes(), false).unwrap()
}

fn key_id(d1: u32, d2: u32) -> Identifier {
	ExtKeychain::derive_key_id(2, d1, d2, 0, 0)
}

fn key(kc: &ExtKeychain, d1: u32, d2: u32) -> SecretKey {
	kc.derive_key(0, &key_id(d1, d2), SwitchCommitmentType::None)
		.unwrap()
}

fn context_buy(kc: &ExtKeychain) -> Context {
	Context {
		multisig_key: key_id(0, 0),
		multisig_nonce: key(kc, 1, 0),
		lock_nonce: key(kc, 1, 1),
		refund_nonce: key(kc, 1, 2),
		redeem_nonce: key(kc, 1, 3),
		role_context: RoleContext::Buyer(BuyerContext {
			output: key_id(0, 1),
			redeem: key_id(0, 2),
			secondary_context: SecondaryBuyerContext::Btc(BtcBuyerContext {
				refund: key_id(0, 3),
			}),
		}),
	}
}

pub struct SwapDealer {}

impl SwapDealer {
	pub fn new() -> SwapDealer {
		Self {}
	}

	pub fn process_offer<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		from: &dyn Address,
		message: &Message,
		config: &WalletConfig,
		publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		let node_client =
			HTTPNodeClient::new(&config.check_node_api_http_addr, config.api_secret_path).unwrap();

		let btc_node_client = ElectrumNodeClient::new(config.electrum_node_addr.unwrap(), true);
		let mut api_buy = BtcSwapApi::<_, _>::new(node_client.clone(), btc_node_client);

		let kc_buy = _keychain(2);
		let ctx_buy = context_buy(&kc_buy);
		let (mut swap_buy, action) = api_buy
			.accept_swap_offer(&kc_buy, &ctx_buy, None, message)
			.unwrap();

		assert_eq!(swap_buy.status, Status::Offered);
		assert_eq!(action, Action::SendMessage(1));

		let accepted_message = api_buy.message(&kc_buy, &swap_buy).unwrap();

		let res = publisher.post_take(&accepted_message, from);
		if res.is_err() {
			println!("Error in post_take: {:?}", res);
		}
		let action = api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		let (address, btc_amount) = match action {
			Action::DepositSecondary {
				currency: _,
				amount,
				address,
			} => (address, amount),
			_ => panic!("Invalid action"),
		};
		assert_eq!(swap_buy.status, Status::Accepted);

		let address = Address::from_str(&address).unwrap();
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
			if action == Action::SendMessage(2) {
				break;
			}
			println!(
				"Still waiting! please send {} satoshis to {}",
				btc_amount, address
			);
		}
		println!("Successfully confirmed, now starting redeem process");

		let redeem_message = api_buy.message(&kc_buy, &swap_buy).unwrap();
		api_buy
			.message_sent(&kc_buy, &mut swap_buy, &ctx_buy)
			.unwrap();

		let res = publisher.post_take(&redeem_message, from);
		if res.is_err() {
			println!("Error in post_take (redeem): {:?}", res);
		}

		Ok(())
	}

	pub fn process_swap_message<'a, T: ?Sized, C, K>(
		&self,
		wallet: &mut T,
		from: &dyn Address,
		message: &Message,
		config: &WalletConfig,
		publisher: &dyn Publisher,
	) -> Result<(), Error>
	where
		T: WalletBackend<'a, C, K>,
		C: NodeClient + 'a,
		K: grinswap::Keychain + 'a,
	{
		println!("Processing swap message!!!");

		let _res = match &message.inner {
			Update::Offer(_u) => self.process_offer(wallet, from, message, config, publisher),
			//Update::AcceptOffer(_u) => process_accept_offer(wallet, from, message, publisher),
			// Update::InitRedeem(_u) => process_init_redeem(wallet, from, message, publisher),
			//Update::Redeem(_u) => process_redeem(wallet, from, message, publisher),
			_ => Err(ErrorKind::SwapMessageGenericError(format!(
				"Ran into error in swap message."
			))),
		}?;

		Ok(())
	}
}
