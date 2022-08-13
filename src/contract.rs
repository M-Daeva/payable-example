#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_binary, to_binary, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    Uint128,
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
        owner: owner.clone(), // smart contract instantiator
        cw20: cw20.clone(),   // cw20 token contract address
        staked: Coin {
            amount: Uint128::new(0),
            denom: String::from("ustake"),
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
    let sender = deps.api.addr_validate(info.sender.as_str())?;
    if sender != config.owner {
        return Err(ContractError::Unauthorized {});
    }

    match from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::StakeVotingTokens {}) => {
            let state = State {
                owner: config.owner,
                cw20: config.cw20,
                staked: Coin {
                    amount: cw20_msg.amount,
                    denom: config.staked.denom,
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
    use crate::contract::{execute, instantiate, query};
    use crate::msg::{Cw20HookMsg, ExecuteMsg, GetAmountResponse, InstantiateMsg, QueryMsg};
    use crate::ContractError;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        attr, coins, from_binary, Empty, Env, MessageInfo, OwnedDeps, Response, Uint128,
    };

    pub const OWNER_ADDR: &str = "addr1";
    pub const TOKEN_ADDR: &str = "addr2";
    pub const ADDR3: &str = "addr3";

    type Instance = (
        OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        Env,
        MessageInfo,
        Result<Response, ContractError>,
    );

    fn get_instance(staking_token: String, addr: &str) -> Instance {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(addr, &[]);
        let msg = InstantiateMsg { staking_token };

        let res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg);
        (deps, env, info, res)
    }

    #[test]
    fn test_init() {
        let (_, _, _, res) = get_instance(TOKEN_ADDR.to_string(), OWNER_ADDR);

        assert_eq!(
            res.unwrap().attributes,
            vec![
                attr("method", "instantiate"),
                attr("owner", OWNER_ADDR),
                attr("cw20", TOKEN_ADDR),
                attr("staked_amount", "0"),
                attr("staked_denom", "ustake")
            ]
        );
    }

    #[test]
    fn test_execute() {
        let (mut deps, env, info, res) = get_instance(TOKEN_ADDR.to_string(), OWNER_ADDR);

        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            amount: Uint128::new(420),
            sender: String::from(OWNER_ADDR),
            msg: to_binary(&Cw20HookMsg::StakeVotingTokens {}).unwrap(),
        });

        let res2 = execute(deps.as_mut(), env, info, msg);

        assert_eq!(
            res2.unwrap().attributes,
            vec![
                attr("method", "receive_cw20"),
                attr("owner", OWNER_ADDR),
                attr("cw20", TOKEN_ADDR),
                attr("staked_amount", "420"),
                attr("staked_denom", "ustake")
            ]
        );
    }

    #[test]
    fn test_query() {
        let (mut deps, env, info, res) = get_instance(TOKEN_ADDR.to_string(), OWNER_ADDR);

        let msg = ExecuteMsg::Receive(Cw20ReceiveMsg {
            amount: Uint128::new(420),
            sender: String::from(OWNER_ADDR),
            msg: to_binary(&Cw20HookMsg::StakeVotingTokens {}).unwrap(),
        });

        execute(deps.as_mut(), env.clone(), info, msg);

        let msg = QueryMsg::GetAmount {};

        let bin = query(deps.as_ref(), env, msg).unwrap();

        let res = from_binary::<GetAmountResponse>(&bin).unwrap();

        assert_eq!(
            res,
            GetAmountResponse {
                amount: Uint128::new(420),
            }
        );
    }
}
