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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, Slate, VersionInfo,
	VersionedSlate, WalletBackend,
};
use crate::Foreign;
use easy_jsonrpc;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `grin-wallet listen` with defaults, the V2 api is available at
/// `localhost:3415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"foreign_api_version": 2,
				"supported_slate_versions": [
					"V0",
					"V1",
					"V2"
				]
			}
		}
	}
	# "#
	# , 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		]
	}
	# "#
	# ,
	# r#"
	{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "Ok": {
      "kernel": {
        "excess": "095987fa1274901ab624386e9f76b39c6c27a6f5d11782bb06e3a55361d925e418",
        "excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b49e2040e02da3d79a3bd694d522754f118a064d62f076e87a161059222141c2c",
        "features": "Coinbase",
        "fee": "0",
        "lock_height": "0"
      },
      "key_id": "0300000000000000000000000400000000",
      "output": {
        "commit": "08f9451ff0b17a7d3b905efacc1b51ded6a77dc17aedd4959d46f6509c3298b8c7",
        "features": "Coinbase",
        "proof": "31ccbaa4c59281a8fc30ac8dda167c898ab0817fa985e29fce6a3a03c16431dd28cd931aea6b45ddb045064d687edbb5ce3b69336c7d281668c8c9a5ff7309f804c2074ebe3c0da64bd0df21563ba983c877de49c2389e549d70068c180e467bb036ac9d34e771295f143df49b01b5af3ed0e71220ec25ee6dfd2d9fdcd0acaa07edf168e66f1331ff5f3e55b50458e2a5087c43888026c50b5cc6e91abf04c8d117a5d04d1c0ec4f61ba41505baec3413d9048ee822b8d3b2832c18625a3b7779411cf3585ce3ec0e54ddc76ccd2ba92568a987a1838d578c17b2649f3524ecf690dfc5374f9a13822f1113d823c882a46ba6baf0a53032646939bf45b22d83854e383ed555c7345886f5cd53040814b219c2156035a8d3673392c806d0d89f52e13e0f3359a68a3d838b5d2752486f3841406ba49c17b705de0d3bb1c786924cc86b4c2386475498b52dfe70cc0564360cd94c0d7a78a10bebc747041fe817e514034e885109f8ca21898b61fd9b956fa90fb3a3eeaa8b183331edc8d0505d8e8b26ee93b2aea6ba4a58cdb02ca8cca3d3ee1b23bc2c42fe630c4ac2bc2a5d100f12127f0266f8d5f1bd98ef0a1d0e0b985618e6dd8eccd32bd7c9a9932687fe8a39aacb0710975271dd5003236668f87415fddfc5b7da2e3ca784f24f84b8d9a192179aab5718b96f72cc9f8bff59794c794e235258f42e757d532b15df9d2d8159ae3991a9ddbd1bff871df12aab6073a673a5e4dde408f4973bcb8f83da7e436051e25ee6b11de1aa8f8caad74272bbc864c8082f96fde8fecd65b6cf1d74163063592f5355c65f8ffb424d4ad3ad81045dbab6474859fd2ac804b7d25481b9be9f34fa4abe2968a15149ce136641ded952a01f5268378b0d611e1683aa15ae5c810f1f2cc858b023674253552f0d2635f9d33016e21460e6403a211ed623c2be"
      }
    }
  }
	}
	# "#
	# , 4, false, false);
	```
	*/
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": [ {
				"amount": "2380952380",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 1
				}
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,1 ,false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
		Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	*/
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	*/
	fn finalize_invoice_tx(&self, slate: &Slate) -> Result<Slate, ErrorKind>;
}

impl<W: ?Sized, C, K> ForeignRpc for Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = slate.version();
		let slate: Slate = slate.into();
		let slate = Foreign::receive_tx(
			self,
			&slate,
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;

		Ok(VersionedSlate::into_version(slate, version))
	}

	fn finalize_invoice_tx(&self, slate: &Slate) -> Result<Slate, ErrorKind> {
		Foreign::finalize_invoice_tx(self, slate).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc::Handler;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_libwallet::api_impl;
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_wallet_util::grin_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 = test_framework::create_wallet(
		&format!("{}/wallet1", test_dir),
		client1.clone(),
		Some(rec_phrase_1),
	);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let rec_phrase_2 =
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile";
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 = test_framework::create_wallet(
		&format!("{}/wallet2", test_dir),
		client2.clone(),
		Some(rec_phrase_2),
	);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 1 as usize, false);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut *w, true, 1).unwrap();
		assert!(wallet_refreshed);
		w.close().unwrap();
	}

	if init_invoice_tx {
		let amount = 2_380_952_380;
		let mut slate = {
			let mut w = wallet2.lock();
			w.open_with_credentials().unwrap();
			let args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};
			api_impl::owner::issue_invoice_tx(&mut *w, args, true).unwrap()
		};
		slate = {
			let mut w = wallet1.lock();
			w.open_with_credentials().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			api_impl::owner::process_invoice_tx(&mut *w, &slate, args, true).unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	if init_tx {
		let amount = 2_380_952_380;
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api_impl::owner::init_send_tx(&mut *w, args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1.clone()),
		true => Foreign::new(wallet2.clone()),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	Ok(foreign_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest_foreign;
		use serde_json;
		use serde_json::Value;
		use tempfile::tempdir;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();

		let request_val: Value = serde_json::from_str($request).unwrap();
		let expected_response: Value = serde_json::from_str($expected_response).unwrap();

		let response = run_doctest_foreign(
			request_val,
			dir,
			$blocks_to_mine,
			$init_tx,
			$init_invoice_tx,
			)
		.unwrap()
		.unwrap();

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}
