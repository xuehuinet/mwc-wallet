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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, Slate, TxLogEntry, WalletBackend, WalletInfo,
};
use crate::Owner;
use easy_jsonrpc;

/// Public definition used to generate Owner jsonrpc api.
/// * When running `grin-wallet owner_api` with defaults, the V2 api is available at
/// `localhost:3420/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false);
	```
	*/
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,4, false, false, false);
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).
        */

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).
        */

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": [true, 1],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "2380952380",
					"amount_immature": "7142857140",
					"amount_locked": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "9523809520"
				}
			]
		}
	}
	# "#
	# ,4, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;


        /**
               Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).
        */
	fn init_send_tx(&self, args: InitTxArgs) -> Result<Slate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"args": {
					"amount": "6000000000",
					"message": "Please give me your grins",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amount": "6000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"num_participants": 2,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your grins",
							"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd9bccdcf5d3a402bccc77d36346d3a899259a884f643e90266984289b39a59d2",
							"part_sig": null,
							"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
							"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
									"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
									"features": "Plain",
									"proof": "8f511614315626b5f39224482351d766f5a8ef136262befc050d839be8479b0a13470cd88f4436346d213d83847a4055c6e0ac63681556470349a1aab47034a3015eb64d8163955998e2dd4165dd24386b1e279974b05deb5d46ba2bc321f7000c0784f8f10690605ffe717119d045e02b141ed12d8fc6d20930483a8af889ef533495eb442fcff36d98ebc104f13fc645c28431b3296e4a11f7c991ff97f9abbc2f8886762d7f29fdacb31d52c6850e6ccf5386117d89e8ea4ca3071c56c218dd5d3bcd65f6c06ed9f51f848507ca1d594f41796d1cf99f68a5c3f0c5dd9873602284cff31269b102fcc6c68607565faaf0adb04ed4ff3ea5d41f3b5235ac6cb90e4046c808c9c48c27172c891b20085c56a99913ef47fd8b3dc4920cef50534b9319a7cefe0df10a0206a634ac837e11da92df83ff58b1a14de81313400988aa48b946fcbe1b81f0e79e13f7c6c639b1c10983b424bda08d0ce593a20f1f47e0aa01473e7144f116b76d9ebc60599053d8f1542d60747793d99064e51fce8f8866390325d48d6e8e3bbdbc1822c864303451525c6cb4c6902f105a70134186fb32110d8192fc2528a9483fc8a4001f4bdeab1dd7b3d1ccb9ae2e746a78013ef74043f0b2436f0ca49627af1768b7c791c669bd331fd18c16ef88ad0a29861db70f2f76f3e74fde5accb91b73573e31333333223693d6fbc786e740c085e4fc6e7bde0a3f54e9703f816c54f012d3b1f41ec4d253d9337af61e7f1f1383bd929421ac346e3d2771dfee0b60503b33938e7c83eb37af3b6bf66041a3519a2b4cb557b34e3b9afcf95524f9a011425a34d32e7b6e9f255291094930acae26e8f7a1e4e6bc405d0f88e919f354f3ba85356a34f1aba5f7da1fad88e2692f4129cc1fb80a2122b2d996c6ccf7f08d8248e511d92af9ce49039de728848a2dc74101f4e94a"
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
			}
		}
		# "#
		# ,4, false, false, false);
	```
	*/

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<Slate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	*/

	fn process_invoice_tx(&self, slate: &Slate, args: InitTxArgs) -> Result<Slate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).
	 */
	fn tx_lock_outputs(&self, slate: Slate, participant_id: usize) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": [
		{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"block_header_version": 1
			},
			"num_participants": 2,
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"tx": {
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"body": {
					"inputs": [
						{
							"features": "Coinbase",
							"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045"
						},
						{
							"features": "Coinbase",
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7"
						}
					],
					"outputs": [
						{
							"features": "Plain",
							"commit": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
							"proof": "7ebcd2ed9bf5fb29854033ba3d0e720613bdf7dfacc586d2f6084c1cde0a2b72e955d4ce625916701dc7c347132f40d0f102a34e801d745ee54b49b765d08aae0bb801c60403e57cafade3b4b174e795b633ab9e402b5b1b6e1243fd10bbcf9368a75cb6a6c375c7bdf02da9e03b7f210df45d942e6fba2729cd512a372e6ed91a1b5c9c22831febea843e3f85adcf198f39ac9f7b73b70c60bfb474aa69878ea8d1d32fef30166b59caacaec3fd024de29a90f1587e08d2c36b3d5c560cabf658e212e0a40a4129b3e5c35557058def5551f4eb395759597ba808b3c34eac3bfb9716e4480d7931c5789c538463ec75be0eb807c894047fda6cbcd22682d3c6d3823cb330f090a2099e3510a3706b57d46c95224394d7f1c0a20d99cc314b8f1d9d02668e2e435f62e1194de0be6a1f50f72ed777ed51c8819f527a94918d1aa8df6461e98ed4c2b18210de50fbcf8c3df210bfe326d41f1dc0ad748cb0320ae28401c85ab4f7dcb99d88a052e95dc85b76d22b36cabd60e06ab84bb7e4ddfdab9c9730c8a986583237ed1ecbb323ee8e79b8cadca4b438b7c09531670b471dda6a2eb3e747916c88ce7d9d8e1b7f61660eeb9e5a13c60e4dfe89d1177d81d6f6570fda85158e646a15f1e8b9e977494dc19a339aab2e0e478670d80092d6ba37646e60714ef64eb4a3d37fe15f8f38b59114af34b235489eed3f69b7781c5fe496eb43ffe245c14bd740f745844a38cf0d904347aaa2b64f51add18822dac009d8b63fa3e4c9b1fa72187f9a4acba1ab315daa1b04c9a41f3be846ac420b37990e6c947a16cc9d5c0671b292bf77d7d8b8974d2ad3afae95ba7772c37432840f53a007f31e0195f3abdf100c4477723cc6c6d5da14894a73dfac342833731036487488fdade7b9d556c06f26173b6b67598d3769447ce2828d71dd45ac5af436c6b0"
						},
						{
							"features": "Plain",
							"commit": "0812276cc788e6870612296d926cba9f0e7b9810670710b5a6e6f1ba006d395774",
							"proof": "dcff6175390c602bfa92c2ffd1a9b2d84dcc9ea941f6f317bdd0f875244ef23e696fd17c71df79760ce5ce1a96aab1d15dd057358dc835e972febeb86d50ccec0dad7cfe0246d742eb753cf7b88c045d15bc7123f8cf7155647ccf663fca92a83c9a65d0ed756ea7ebffd2cac90c380a102ed9caaa355d175ed0bf58d3ac2f5e909d6c447dfc6b605e04925c2b17c33ebd1908c965a5541ea5d2ed45a0958e6402f89d7a56df1992e036d836e74017e73ccad5cb3a82b8e139e309792a31b15f3ffd72ed033253428c156c2b9799458a25c1da65b719780a22de7fe7f437ae2fccd22cf7ea357ab5aa66a5ef7d71fb0dc64aa0b5761f68278062bb39bb296c787e4cabc5e2a2933a416ce1c9a9696160386449c437e9120f7bb26e5b0e74d1f2e7d5bcd7aafb2a92b87d1548f1f911fb06af7bd6cc13cee29f7c9cb79021aed18186272af0e9d189ec107c81a8a3aeb4782b0d950e4881aa51b776bb6844b25bce97035b48a9bdb2aea3608687bcdd479d4fa998b5a839ff88558e4a29dff0ed13b55900abb5d439b70793d902ae9ad34587b18c919f6b875c91d14deeb1c373f5e76570d59a6549758f655f1128a54f162dfe8868e1587028e26ad91e528c5ae7ee9335fa58fb59022b5de29d80f0764a9917390d46db899acc6a5b416e25ecc9dccb7153646addcc81cadb5f0078febc7e05d7735aba494f39ef05697bbcc9b47b2ccc79595d75fc13c80678b5e237edce58d731f34c05b1ddcaa649acf2d865bbbc3ceda10508bcdd29d0496744644bf1c3516f6687dfeef5649c7dff90627d642739a59d91a8d1d0c4dc55d74a949e1074427664b467992c9e0f7d3af9d6ea79513e8946ddc0d356bac49878e64e6a95b0a30214214faf2ce317fa622ff3266b32a816e10a18e6d789a5da1f23e67b4f970a68a7bcd9e18825ee274b0483896a40"
						}
					],
					"kernels": [
						{
							"features": "Plain",
							"fee": "7000000",
							"lock_height": "0",
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						}
					]
				}
			},
			"amount": "60000000000",
			"fee": "7000000",
			"height": "5",
			"lock_height": "0",
			"participant_data": [
				{
					"id": "0",
					"public_blind_excess": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part_sig": null,
					"message": null,
					"message_sig": null
				},
				{
					"id": "1",
					"public_blind_excess": "024f9bc78c984c78d6e916d3a00746aa30fa1172124c8dbc0cbddcb7b486719bc7",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba9c6dd6185c2b819799700fa1a69201f96cc6dfb9ca205a0ef7c35fb81d57dac",
					"message": null,
					"message_sig": null
				}
			]
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
		"Ok": {
				"amount": "60000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
					{
						"id": "0",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b38641aefa907a2fc1c051b1f73202794fffb6d422e328516a5c6b2ef41e935f8",
						"public_blind_excess": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "1",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba9c6dd6185c2b819799700fa1a69201f96cc6dfb9ca205a0ef7c35fb81d57dac",
						"public_blind_excess": "024f9bc78c984c78d6e916d3a00746aa30fa1172124c8dbc0cbddcb7b486719bc7",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
							{
								"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
								"features": "Coinbase"
							},
							{
								"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
								"features": "Coinbase"
							}
						],
						"kernels": [
							{
								"excess": "09bac6083b05a32a9d9b37710c70dd0a1ef9329fde0848558976b6f1b81d80ceed",
								"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da0e9c180a26b88565afcd269a7ac98f896c8db3dcbd48ab69443e8eac3beb3a4",
								"features": "Plain",
								"fee": "7000000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
								"commit": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
								"features": "Plain",
								"proof": "7ebcd2ed9bf5fb29854033ba3d0e720613bdf7dfacc586d2f6084c1cde0a2b72e955d4ce625916701dc7c347132f40d0f102a34e801d745ee54b49b765d08aae0bb801c60403e57cafade3b4b174e795b633ab9e402b5b1b6e1243fd10bbcf9368a75cb6a6c375c7bdf02da9e03b7f210df45d942e6fba2729cd512a372e6ed91a1b5c9c22831febea843e3f85adcf198f39ac9f7b73b70c60bfb474aa69878ea8d1d32fef30166b59caacaec3fd024de29a90f1587e08d2c36b3d5c560cabf658e212e0a40a4129b3e5c35557058def5551f4eb395759597ba808b3c34eac3bfb9716e4480d7931c5789c538463ec75be0eb807c894047fda6cbcd22682d3c6d3823cb330f090a2099e3510a3706b57d46c95224394d7f1c0a20d99cc314b8f1d9d02668e2e435f62e1194de0be6a1f50f72ed777ed51c8819f527a94918d1aa8df6461e98ed4c2b18210de50fbcf8c3df210bfe326d41f1dc0ad748cb0320ae28401c85ab4f7dcb99d88a052e95dc85b76d22b36cabd60e06ab84bb7e4ddfdab9c9730c8a986583237ed1ecbb323ee8e79b8cadca4b438b7c09531670b471dda6a2eb3e747916c88ce7d9d8e1b7f61660eeb9e5a13c60e4dfe89d1177d81d6f6570fda85158e646a15f1e8b9e977494dc19a339aab2e0e478670d80092d6ba37646e60714ef64eb4a3d37fe15f8f38b59114af34b235489eed3f69b7781c5fe496eb43ffe245c14bd740f745844a38cf0d904347aaa2b64f51add18822dac009d8b63fa3e4c9b1fa72187f9a4acba1ab315daa1b04c9a41f3be846ac420b37990e6c947a16cc9d5c0671b292bf77d7d8b8974d2ad3afae95ba7772c37432840f53a007f31e0195f3abdf100c4477723cc6c6d5da14894a73dfac342833731036487488fdade7b9d556c06f26173b6b67598d3769447ce2828d71dd45ac5af436c6b0"
							},
							{
								"commit": "0812276cc788e6870612296d926cba9f0e7b9810670710b5a6e6f1ba006d395774",
								"features": "Plain",
								"proof": "dcff6175390c602bfa92c2ffd1a9b2d84dcc9ea941f6f317bdd0f875244ef23e696fd17c71df79760ce5ce1a96aab1d15dd057358dc835e972febeb86d50ccec0dad7cfe0246d742eb753cf7b88c045d15bc7123f8cf7155647ccf663fca92a83c9a65d0ed756ea7ebffd2cac90c380a102ed9caaa355d175ed0bf58d3ac2f5e909d6c447dfc6b605e04925c2b17c33ebd1908c965a5541ea5d2ed45a0958e6402f89d7a56df1992e036d836e74017e73ccad5cb3a82b8e139e309792a31b15f3ffd72ed033253428c156c2b9799458a25c1da65b719780a22de7fe7f437ae2fccd22cf7ea357ab5aa66a5ef7d71fb0dc64aa0b5761f68278062bb39bb296c787e4cabc5e2a2933a416ce1c9a9696160386449c437e9120f7bb26e5b0e74d1f2e7d5bcd7aafb2a92b87d1548f1f911fb06af7bd6cc13cee29f7c9cb79021aed18186272af0e9d189ec107c81a8a3aeb4782b0d950e4881aa51b776bb6844b25bce97035b48a9bdb2aea3608687bcdd479d4fa998b5a839ff88558e4a29dff0ed13b55900abb5d439b70793d902ae9ad34587b18c919f6b875c91d14deeb1c373f5e76570d59a6549758f655f1128a54f162dfe8868e1587028e26ad91e528c5ae7ee9335fa58fb59022b5de29d80f0764a9917390d46db899acc6a5b416e25ecc9dccb7153646addcc81cadb5f0078febc7e05d7735aba494f39ef05697bbcc9b47b2ccc79595d75fc13c80678b5e237edce58d731f34c05b1ddcaa649acf2d865bbbc3ceda10508bcdd29d0496744644bf1c3516f6687dfeef5649c7dff90627d642739a59d91a8d1d0c4dc55d74a949e1074427664b467992c9e0f7d3af9d6ea79513e8946ddc0d356bac49878e64e6a95b0a30214214faf2ce317fa622ff3266b32a816e10a18e6d789a5da1f23e67b4f970a68a7bcd9e18825ee274b0483896a40"
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
		}
	}
	# "#
	# , 5, true, true, false);
	```
	*/
	fn finalize_tx(&self, slate: Slate) -> Result<Slate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": [
		{
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"body": {
				"inputs": [
					{
						"features": "Coinbase",
						"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045"
					},
					{
						"features": "Coinbase",
						"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7"
					}
				],
				"outputs": [
					{
						"features": "Plain",
						"commit": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"proof": "7ebcd2ed9bf5fb29854033ba3d0e720613bdf7dfacc586d2f6084c1cde0a2b72e955d4ce625916701dc7c347132f40d0f102a34e801d745ee54b49b765d08aae0bb801c60403e57cafade3b4b174e795b633ab9e402b5b1b6e1243fd10bbcf9368a75cb6a6c375c7bdf02da9e03b7f210df45d942e6fba2729cd512a372e6ed91a1b5c9c22831febea843e3f85adcf198f39ac9f7b73b70c60bfb474aa69878ea8d1d32fef30166b59caacaec3fd024de29a90f1587e08d2c36b3d5c560cabf658e212e0a40a4129b3e5c35557058def5551f4eb395759597ba808b3c34eac3bfb9716e4480d7931c5789c538463ec75be0eb807c894047fda6cbcd22682d3c6d3823cb330f090a2099e3510a3706b57d46c95224394d7f1c0a20d99cc314b8f1d9d02668e2e435f62e1194de0be6a1f50f72ed777ed51c8819f527a94918d1aa8df6461e98ed4c2b18210de50fbcf8c3df210bfe326d41f1dc0ad748cb0320ae28401c85ab4f7dcb99d88a052e95dc85b76d22b36cabd60e06ab84bb7e4ddfdab9c9730c8a986583237ed1ecbb323ee8e79b8cadca4b438b7c09531670b471dda6a2eb3e747916c88ce7d9d8e1b7f61660eeb9e5a13c60e4dfe89d1177d81d6f6570fda85158e646a15f1e8b9e977494dc19a339aab2e0e478670d80092d6ba37646e60714ef64eb4a3d37fe15f8f38b59114af34b235489eed3f69b7781c5fe496eb43ffe245c14bd740f745844a38cf0d904347aaa2b64f51add18822dac009d8b63fa3e4c9b1fa72187f9a4acba1ab315daa1b04c9a41f3be846ac420b37990e6c947a16cc9d5c0671b292bf77d7d8b8974d2ad3afae95ba7772c37432840f53a007f31e0195f3abdf100c4477723cc6c6d5da14894a73dfac342833731036487488fdade7b9d556c06f26173b6b67598d3769447ce2828d71dd45ac5af436c6b0"
					},
					{
						"features": "Plain",
						"commit": "0812276cc788e6870612296d926cba9f0e7b9810670710b5a6e6f1ba006d395774",
						"proof": "dcff6175390c602bfa92c2ffd1a9b2d84dcc9ea941f6f317bdd0f875244ef23e696fd17c71df79760ce5ce1a96aab1d15dd057358dc835e972febeb86d50ccec0dad7cfe0246d742eb753cf7b88c045d15bc7123f8cf7155647ccf663fca92a83c9a65d0ed756ea7ebffd2cac90c380a102ed9caaa355d175ed0bf58d3ac2f5e909d6c447dfc6b605e04925c2b17c33ebd1908c965a5541ea5d2ed45a0958e6402f89d7a56df1992e036d836e74017e73ccad5cb3a82b8e139e309792a31b15f3ffd72ed033253428c156c2b9799458a25c1da65b719780a22de7fe7f437ae2fccd22cf7ea357ab5aa66a5ef7d71fb0dc64aa0b5761f68278062bb39bb296c787e4cabc5e2a2933a416ce1c9a9696160386449c437e9120f7bb26e5b0e74d1f2e7d5bcd7aafb2a92b87d1548f1f911fb06af7bd6cc13cee29f7c9cb79021aed18186272af0e9d189ec107c81a8a3aeb4782b0d950e4881aa51b776bb6844b25bce97035b48a9bdb2aea3608687bcdd479d4fa998b5a839ff88558e4a29dff0ed13b55900abb5d439b70793d902ae9ad34587b18c919f6b875c91d14deeb1c373f5e76570d59a6549758f655f1128a54f162dfe8868e1587028e26ad91e528c5ae7ee9335fa58fb59022b5de29d80f0764a9917390d46db899acc6a5b416e25ecc9dccb7153646addcc81cadb5f0078febc7e05d7735aba494f39ef05697bbcc9b47b2ccc79595d75fc13c80678b5e237edce58d731f34c05b1ddcaa649acf2d865bbbc3ceda10508bcdd29d0496744644bf1c3516f6687dfeef5649c7dff90627d642739a59d91a8d1d0c4dc55d74a949e1074427664b467992c9e0f7d3af9d6ea79513e8946ddc0d356bac49878e64e6a95b0a30214214faf2ce317fa622ff3266b32a816e10a18e6d789a5da1f23e67b4f970a68a7bcd9e18825ee274b0483896a40"
					}
				],
				"kernels": [
					{
						"features": "Plain",
						"fee": "7000000",
						"lock_height": "0",
						"excess": "09bac6083b05a32a9d9b37710c70dd0a1ef9329fde0848558976b6f1b81d80ceed",
						"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da0e9c180a26b88565afcd269a7ac98f896c8db3dcbd48ab69443e8eac3beb3a4"
					}
				]
			}
		},
		false
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, true);
	```
	 */

	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

        /**
         */
	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	*/
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::restore](struct.Owner.html#method.restore).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "restore",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false);
	```
	 */
	fn restore(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::check_repair](struct.Owner.html#method.check_repair).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_repair",
		"params": [false],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false);
	```
	 */
	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , 5, false, false, false);
	```
	 */
	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind>;
}

impl<W: ?Sized, C, K> OwnerRpc for Owner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(self, include_spent, refresh_from_node, tx_id).map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(self, refresh_from_node, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(self, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, args: InitTxArgs) -> Result<Slate, ErrorKind> {
		Owner::init_send_tx(self, args).map_err(|e| e.kind())
	}

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<Slate, ErrorKind> {
		Owner::issue_invoice_tx(self, args).map_err(|e| e.kind())
	}

	fn process_invoice_tx(&self, slate: &Slate, args: InitTxArgs) -> Result<Slate, ErrorKind> {
		Owner::process_invoice_tx(self, slate, args).map_err(|e| e.kind())
	}

	fn finalize_tx(&self, mut slate: Slate) -> Result<Slate, ErrorKind> {
		Owner::finalize_tx(self, &mut slate).map_err(|e| e.kind())
	}

	fn tx_lock_outputs(&self, mut slate: Slate, participant_id: usize) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(self, &mut slate, participant_id).map_err(|e| e.kind())
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind> {
		Owner::get_stored_tx(self, tx).map_err(|e| e.kind())
	}

	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(self, tx, fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn restore(&self) -> Result<(), ErrorKind> {
		Owner::restore(self).map_err(|e| e.kind())
	}

	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		Owner::check_repair(self, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
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

	if perform_tx {
		let amount = 60_000_000_000;
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
		let mut slate = api_impl::owner::init_send_tx(&mut *w, args, true).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w2 = wallet2.lock();
			w2.open_with_credentials().unwrap();
			slate = api_impl::foreign::receive_tx(&mut *w2, &slate, None, None, true).unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			api_impl::owner::tx_lock_outputs(&mut *w, &slate, 0).unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut *w, &slate).unwrap();
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
		w.close().unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3 as usize, false);
	}

	let mut api_owner = Owner::new(wallet1.clone());
	api_owner.doctest_mode = true;
	let owner_api = &api_owner as &dyn OwnerRpc;
	Ok(owner_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest_owner;
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

		let response = run_doctest_owner(
			request_val,
			dir,
			$blocks_to_mine,
			$perform_tx,
			$lock_tx,
			$finalize_tx,
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
