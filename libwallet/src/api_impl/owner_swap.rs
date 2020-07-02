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
use crate::types::{NodeClient};
use crate::{wallet_lock, WalletInst, WalletLCProvider, SwapStartArgs};
use crate::{Error};
use std::sync::Arc;
use crate::swap::types::Currency;
use std::convert::TryFrom;
use crate::swap::trades;
use crate::swap::error::ErrorKind;
use crate::swap::swap::Swap;

// TODO  - Validation for all parameters.

/// Start swap trade process. Return SwapID that can be used to check the status or perform further action.
pub fn swap_start<'a, L, C, K>(
    wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    keychain_mask: Option<&SecretKey>,
    params: &SwapStartArgs
) -> Result<String, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    // Starting a swap trade.
    // This method only initialize and store the swap process. Nothing is done

    // TODO  - validate SwapStartArgs values
    // TODO  - validate if params.secondary_redeem_address is valid.
    // TODO  - we probably want to do that as a generic solution because all params need to be validated

    wallet_lock!(wallet_inst, w);
    let node_client = w.w2n_client().clone();
    let keychain = w.keychain(keychain_mask)?;

    let height = node_client.get_chain_tip()?.0;

    let secondary_currency = Currency::try_from(params.secondary_currency.as_str())?;
    let mut swap_api = crate::swap::api::create_instance( &secondary_currency, node_client)?;

    let secondary_key_size = (*swap_api).context_key_count(&keychain, secondary_currency, true)?;
    let mut keys: Vec<Identifier> = Vec::new();

    for _ in 0..secondary_key_size {
        keys.push( w.next_child(keychain_mask)? );
    }

    let parent_key_id = w.parent_key_id(); // account is current one
    let (outputs, _, _ , _) = crate::internal::selection::select_coins_and_fee(
        &mut **w,
        params.mwc_amount,
        height,
        params.minimum_confirmations.unwrap_or(10),
        500,
        1,
        false,
        &parent_key_id,
        &None, // outputs to include into the transaction
        1,             // Number of resulting outputs. Normally it is 1
        false,
        0)?;

    let context = (*swap_api).create_context(
        &keychain,
        secondary_currency,
        true,
        Some(outputs.iter().map(|out| (out.key_id.clone(), out.value) ).collect()),
        keys)?;

    let (swap, _) = (*swap_api).create_swap_offer(
        &keychain,
        &context,
        params.mwc_amount,     // mwc amount to sell
        params.secondary_amount,   // btc amount to buy
        secondary_currency,
        params.secondary_redeem_address.clone())?; // redeed address for BTC

    // Store swap result into the file.
    let swap_id = swap.id.to_string();
    if trades::get_swap_trade( swap_id.as_str() ).is_ok() {
        // Should be impossible, uuid suppose to be unique. But we don't want to overwrite anything
        return Err( ErrorKind::TradeIoError(swap_id.clone(), "This trade record already exist".to_string()).into() );
    }

    trades::store_swap_trade(&context, &swap)?;

    Ok(swap_id)
}

/// List Swap trades. Returns SwapId + Status
pub fn swap_list<'a, L, C, K>(
    _wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    _keychain_mask: Option<&SecretKey>
) -> Result< Vec<(String,String)>, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let swap_id = trades::list_swap_trades()?;
    let mut result : Vec<(String,String)> = Vec::new();

    for sw_id in &swap_id {
        let (_,swap) = trades::get_swap_trade(sw_id.as_str())?;
        result.push((sw_id.clone(), swap.status.to_string()) );
    }

    Ok(result)
}


/// Delete Swap trade.
pub fn swap_delete<'a, L, C, K>(
    _wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
    _keychain_mask: Option<&SecretKey>,
    swap_id: &str,
) -> Result< (), Error>
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
) -> Result< Swap, Error>
    where
        L: WalletLCProvider<'a, C, K>,
        C: NodeClient + 'a,
        K: Keychain + 'a,
{
    let (_, swap) = trades::get_swap_trade(swap_id)?;
    Ok(swap)
}
