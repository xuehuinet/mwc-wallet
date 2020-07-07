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

use super::ErrorKind;
use crate::swap::types::Context;
use crate::swap::Swap;
use grin_util::RwLock;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;

/// Lacation of the swaps states
pub const SWAP_DEAL_SAVE_DIR: &'static str = "saved_swap_deal";

lazy_static! {
	static ref TRADE_DEALS_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);
	static ref ELECTRUM_X_URI: RwLock<Option<String>> = RwLock::new(None);
}

/// Init for file storage for saving swap deals
pub fn init_swap_trade_backend(data_file_dir: &str, electrumx_uri: Option<String>) {
	let stored_swap_deal_path = Path::new(data_file_dir).join(SWAP_DEAL_SAVE_DIR);
	fs::create_dir_all(&stored_swap_deal_path)
		.expect("Could not create swap deal storage directory!");

	TRADE_DEALS_PATH.write().replace(stored_swap_deal_path);

	if let Some(uri) = electrumx_uri {
		ELECTRUM_X_URI.write().replace(uri);
	}
}

/// Get ElextrumX URL.
pub fn get_electrumx_uri() -> Option<String> {
	ELECTRUM_X_URI.read().clone()
}

/// List available swap trades.
pub fn list_swap_trades() -> Result<Vec<String>, ErrorKind> {
	let mut result: Vec<String> = Vec::new();

	for entry in fs::read_dir(TRADE_DEALS_PATH.read().clone().unwrap())? {
		let entry = entry?;
		if let Some(name) = entry.file_name().to_str() {
			if name.ends_with(".swap") {
				let name = String::from(name.split(".swap").next().unwrap_or("?"));
				result.push(name);
			}
		}
	}
	Ok(result)
}

/// Remove swap trade record.
/// Note! You don't want to remove the non compelete deal. You can loose funds because of that.
pub fn delete_swap_trade(swap_id: &str) -> Result<(), ErrorKind> {
	let target_path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap_id));
	let deleted_path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap.del", swap_id));

	fs::rename(target_path, deleted_path).map_err(|e| {
		ErrorKind::TradeIoError(swap_id.to_string(), format!("Unable to delete, {}", e))
	})?;
	Ok(())
}

// TODO -  Swap data contain bunch of secrets
/// Get swap trade from the storage.
pub fn get_swap_trade(swap_id: &str) -> Result<(Context, Swap), ErrorKind> {
	let path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap_id));
	if !path.exists() {
		return Err(ErrorKind::TradeNotFound(swap_id.to_string()));
	}
	let mut swap_deal_f = File::open(path.clone()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to open file {}, {}", path.to_str().unwrap(), e),
		)
	})?;
	let mut content = String::new();
	swap_deal_f.read_to_string(&mut content).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to read data from {}, {}", path.to_str().unwrap(), e),
		)
	})?;

	let mut split = content.split("<#>");

	let context_str = split.next();
	let swap_str = split.next();

	if context_str.is_none() || context_str.is_none() {
		return Err(ErrorKind::TradeIoError(
			swap_id.to_string(),
			"Not found all packages".to_string(),
		));
	}

	let context: Context = serde_json::from_str(context_str.unwrap()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to parce Swap data from Json, {}", e),
		)
	})?;
	let swap: Swap = serde_json::from_str(swap_str.unwrap()).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.to_string(),
			format!("Unable to parce Swap data from Json, {}", e),
		)
	})?;

	Ok((context, swap))
}

// TODO - move swap storage to separate file. It is bigger problem, the data need to be encrypted because
// Swap data contain bunch of secrets
/// Store swap deal to a file
pub fn store_swap_trade(context: &Context, swap: &Swap) -> Result<(), ErrorKind> {
	// Writing to bak file. We don't want to loose the data in case of failure. It least the prev step will be left
	let swap_id = swap.id.to_string();
	let path = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap.bak", swap_id));
	{
		let mut stored_swap = File::create(path.clone()).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to create the file {} to store swap trade, {}",
					path.to_str().unwrap(),
					e
				),
			)
		})?;

		let context_ser = serde_json::to_string(context).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!("Unable to convert context to Json, {}", e),
			)
		})?;
		let swap_ser = serde_json::to_string(swap).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!("Unable to convert swap to Json, {}", e),
			)
		})?;
		let res_str = context_ser + "<#>" + swap_ser.as_str();

		stored_swap.write_all(&res_str.as_bytes()).map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to write swap deal to file {}, {}",
					path.to_str().unwrap(),
					e
				),
			)
		})?;
		stored_swap.sync_all().map_err(|e| {
			ErrorKind::TradeIoError(
				swap_id.clone(),
				format!(
					"Unable to sync file {} all after writing swap deal, {}",
					path.to_str().unwrap(),
					e
				),
			)
		})?;
	}

	let path_target = TRADE_DEALS_PATH
		.read()
		.clone()
		.unwrap()
		.join(format!("{}.swap", swap.id.to_string()));
	fs::rename(path, path_target).map_err(|e| {
		ErrorKind::TradeIoError(
			swap_id.clone(),
			format!("Unable to finalize writing, rename failed with error {}", e),
		)
	})?;

	Ok(())
}
