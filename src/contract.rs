#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;
use cw20::Cw20ReceiveMsg;

use crate::error::ContractError;
use crate::msg::{Cw20HookMsg, ExecuteMsg, GetAmountResponse, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:payable-example";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let owner = deps.api.addr_validate(info.sender.as_str())?;
    let cw20 = deps.api.addr_validate(&msg.staking_token)?;

    let state = State {
        owner: owner.clone(),
        cw20: cw20.clone(),
        staked: Coin {
            ..Default::default()
        },
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", owner)
        .add_attribute("cw20", cw20)
        .add_attribute("staked_amount", state.staked.amount)
        .add_attribute("staked_denom", state.staked.denom))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Receive(cw20_msg) => receive_cw20(deps, _env, info, cw20_msg),
    }
}

/// handler function invoked when the governance contract receives
/// a transaction. This is asking to a payable function in Solidity
pub fn receive_cw20(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    // only asset contract can execute this message
    let config: State = STATE.load(deps.storage)?;
    let addr = deps.api.addr_validate(info.sender.as_str())?;
    if addr != config.cw20 {
        return Err(ContractError::Unauthorized {});
    }

    match from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::StakeVotingTokens {}) => {
            // Homework??
            let coin = &info.funds[0];

            let state = State {
                owner: config.owner,
                cw20: config.cw20,
                staked: Coin {
                    amount: coin.amount,
                    denom: coin.denom.to_string(),
                },
            };
            STATE.save(deps.storage, &state)?;

            Ok(Response::new()
                .add_attribute("method", "receive_cw20")
                .add_attribute("owner", state.owner)
                .add_attribute("cw20", state.cw20)
                .add_attribute("staked_amount", state.staked.amount)
                .add_attribute("staked_denom", state.staked.denom))
        }
        _ => Err(ContractError::CustomError {
            val: "Non applicable payable".to_string(),
        }),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetAmount {} => to_binary(&query_count(deps)?),
    }
}

fn query_count(deps: Deps) -> StdResult<GetAmountResponse> {
    let state = STATE.load(deps.storage)?;
    Ok(GetAmountResponse {
        amount: state.staked.amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            staking_token: "".to_string(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }
}
