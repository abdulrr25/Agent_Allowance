//! Integration tests against a real NEAR sandbox node.
//!
//! Unit tests cannot schedule a cross-contract transfer or run a callback, so
//! everything about the *settlement* path — did value actually move, is the
//! refund correct when a transfer fails, does the 1 yoctoNEAR gate really stop
//! a call — is unverifiable there. These tests cover exactly that gap.
//!
//!     cd integration-tests && cargo test
//!
//! Requires network access on first run to fetch the sandbox node binary.

use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract};
use serde_json::json;

const WASM: &str =
    "../contract/target/wasm32-unknown-unknown/release/agent_allowance.wasm";

fn one_yocto() -> NearToken {
    NearToken::from_yoctonear(1)
}

/// Build the contract if it has not been built yet, then load the wasm.
fn wasm_bytes() -> anyhow::Result<Vec<u8>> {
    if !std::path::Path::new(WASM).exists() {
        let status = std::process::Command::new("cargo")
            .args(["build", "--target", "wasm32-unknown-unknown", "--release"])
            .current_dir("../contract")
            .status()?;
        anyhow::ensure!(status.success(), "contract build failed");
    }
    Ok(std::fs::read(WASM)?)
}

struct Fixture {
    vault: Contract,
    owner: Account,
    agent: Account,
    payee: Account,
}

/// Vault funded with 10 NEAR; one agent capped at 1 NEAR/tx and 3 NEAR/day,
/// allowed to pay `payee` and a non-existent account used to force a failure.
async fn setup() -> anyhow::Result<Fixture> {
    let worker = near_workspaces::sandbox().await?;
    let vault = worker.dev_deploy(&wasm_bytes()?).await?;

    let owner = worker.dev_create_account().await?;
    let agent = worker.dev_create_account().await?;
    let payee = worker.dev_create_account().await?;

    vault
        .call("new")
        .args_json(json!({ "owner_id": owner.id() }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    owner.transfer_near(vault.id(), NearToken::from_near(10)).await?.into_result()?;

    owner
        .call(vault.id(), "add_agent")
        .args_json(json!({
            "agent_id": agent.id(),
            "per_tx_cap": NearToken::from_near(1).as_yoctonear().to_string(),
            "daily_cap": NearToken::from_near(3).as_yoctonear().to_string(),
            "allowlist": [payee.id(), "ghost.nonexistent"],
        }))
        .deposit(one_yocto())
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(Fixture { vault, owner, agent, payee })
}

/// Call `request_spend` and normalise the two shapes it can return.
///
/// `request_spend` returns `PromiseOrValue`. On a denial it returns the
/// `SpendResult` object directly. On an allow it returns a Promise, so the
/// transaction's final return value is whatever the *callback* returned — a
/// bool reporting whether settlement succeeded. Both are flattened here into
/// `{allowed, reason, settled}`.
async fn spend(f: &Fixture, to: &str, amount: NearToken) -> anyhow::Result<serde_json::Value> {
    let out = f
        .agent
        .call(f.vault.id(), "request_spend")
        .args_json(json!({
            "recipient": to,
            "amount": amount.as_yoctonear().to_string(),
            "memo": "integration test",
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let raw: serde_json::Value = out.json()?;
    Ok(match raw.as_bool() {
        // Allowed: the callback reported whether the transfer settled.
        Some(settled) => json!({ "allowed": true, "reason": null, "settled": settled }),
        // Denied: the policy decision came back as a value.
        None => json!({
            "allowed": raw["allowed"],
            "reason": raw["reason"],
            "settled": false,
        }),
    })
}

async fn policy(f: &Fixture) -> anyhow::Result<serde_json::Value> {
    Ok(f.vault
        .view("get_policy")
        .args_json(json!({ "agent_id": f.agent.id() }))
        .await?
        .json()?)
}

fn yocto(v: &serde_json::Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

/// An allowed spend must actually move value, not merely return `allowed`.
#[tokio::test]
async fn allowed_spend_actually_transfers_value() -> anyhow::Result<()> {
    let f = setup().await?;
    let before = f.payee.view_account().await?.balance;

    let res = spend(&f, &f.payee.id().to_string(), NearToken::from_millinear(500)).await?;
    assert_eq!(res["allowed"], json!(true));

    let after = f.payee.view_account().await?.balance;
    let delta = after.as_yoctonear().saturating_sub(before.as_yoctonear());
    assert!(
        delta >= NearToken::from_millinear(490).as_yoctonear(),
        "payee should have received ~0.5 NEAR, got {delta} yocto"
    );

    let p = policy(&f).await?;
    assert_eq!(p["allowed_count"], json!(1));
    assert_eq!(yocto(&p["lifetime_spent"]), NearToken::from_millinear(500).as_yoctonear());
    Ok(())
}

/// The headline claim: a compromised agent aiming at an unlisted address moves
/// nothing, and the attempt is recorded rather than erased.
#[tokio::test]
async fn denied_spend_moves_no_value_and_is_recorded() -> anyhow::Result<()> {
    let f = setup().await?;
    let attacker = f.vault.as_account().view_account().await?.balance;

    let res = spend(&f, "attacker.nonexistent", NearToken::from_millinear(500)).await?;
    assert_eq!(res["allowed"], json!(false));
    assert_eq!(res["reason"], json!("RecipientNotAllowlisted"));

    let after = f.vault.as_account().view_account().await?.balance;
    assert!(
        after.as_yoctonear() + NearToken::from_millinear(50).as_yoctonear()
            >= attacker.as_yoctonear(),
        "vault balance must not drop by the requested amount on a denial"
    );

    let p = policy(&f).await?;
    assert_eq!(p["denied_count"], json!(1), "denial must be recorded");
    assert_eq!(yocto(&p["lifetime_spent"]), 0, "no value may move on a denial");
    Ok(())
}

/// The accounting guarantee behind the reentrancy defense: we debit before
/// scheduling the transfer, so a transfer that fails must give the headroom
/// back in the callback. Unit tests can only simulate this; here the promise
/// genuinely fails.
#[tokio::test]
async fn failed_transfer_refunds_headroom() -> anyhow::Result<()> {
    let f = setup().await?;

    // Allowlisted, but the account does not exist, so the transfer fails.
    let res = spend(&f, "ghost.nonexistent", NearToken::from_millinear(900)).await?;
    assert_eq!(res["allowed"], json!(true), "policy permits it");
    assert_eq!(
        res["settled"], json!(false),
        "the transfer itself must fail, so the callback reports failure"
    );

    let p = policy(&f).await?;
    assert_eq!(
        yocto(&p["spent_in_window"]), 0,
        "a failed transfer must restore the daily headroom"
    );
    assert_eq!(yocto(&p["lifetime_spent"]), 0, "lifetime spend must be restored too");

    // And the agent can still spend its full allowance afterwards.
    let again = spend(&f, &f.payee.id().to_string(), NearToken::from_near(1)).await?;
    assert_eq!(again["allowed"], json!(true), "headroom must be usable again");
    Ok(())
}

/// The daily cap must hold across real, settled transfers.
#[tokio::test]
async fn daily_cap_holds_across_settled_transfers() -> anyhow::Result<()> {
    let f = setup().await?;
    let to = f.payee.id().to_string();

    for i in 0..3 {
        let r = spend(&f, &to, NearToken::from_near(1)).await?;
        assert_eq!(r["allowed"], json!(true), "spend {i} should be allowed");
    }
    let r = spend(&f, &to, NearToken::from_millinear(100)).await?;
    assert_eq!(r["allowed"], json!(false));
    assert_eq!(r["reason"], json!("ExceedsDailyCap"));
    Ok(())
}

/// Owner methods demand 1 yoctoNEAR. A function-call key cannot attach a
/// deposit, so this is what stops a leaked agent key widening its own policy.
#[tokio::test]
async fn owner_method_without_one_yocto_is_rejected() -> anyhow::Result<()> {
    let f = setup().await?;
    let out = f
        .owner
        .call(f.vault.id(), "set_paused")
        .args_json(json!({ "paused": true }))
        .max_gas()
        .transact()
        .await?;
    assert!(out.is_failure(), "owner method must reject a zero-deposit call");
    assert_eq!(f.vault.view("is_paused").await?.json::<bool>()?, false);
    Ok(())
}

/// The agent must not be able to reach owner methods at all.
#[tokio::test]
async fn agent_cannot_pause_or_widen_policy() -> anyhow::Result<()> {
    let f = setup().await?;

    let pause = f
        .agent
        .call(f.vault.id(), "set_paused")
        .args_json(json!({ "paused": false }))
        .deposit(one_yocto())
        .max_gas()
        .transact()
        .await?;
    assert!(pause.is_failure(), "agent must not pause the vault");

    let widen = f
        .agent
        .call(f.vault.id(), "update_policy")
        .args_json(json!({
            "agent_id": f.agent.id(),
            "per_tx_cap": NearToken::from_near(999).as_yoctonear().to_string(),
            "daily_cap": NearToken::from_near(999).as_yoctonear().to_string(),
            "allowlist": ["attacker.nonexistent"],
        }))
        .deposit(one_yocto())
        .max_gas()
        .transact()
        .await?;
    assert!(widen.is_failure(), "agent must not widen its own policy");

    let p = policy(&f).await?;
    assert_eq!(
        yocto(&p["per_tx_cap"]),
        NearToken::from_near(1).as_yoctonear(),
        "policy must be unchanged after the attempt"
    );
    Ok(())
}

/// The kill switch must stop a registered, otherwise-valid agent immediately.
#[tokio::test]
async fn kill_switch_stops_settled_spending() -> anyhow::Result<()> {
    let f = setup().await?;
    let to = f.payee.id().to_string();

    assert_eq!(spend(&f, &to, NearToken::from_millinear(100)).await?["allowed"], json!(true));

    f.owner
        .call(f.vault.id(), "set_paused")
        .args_json(json!({ "paused": true }))
        .deposit(one_yocto())
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let r = spend(&f, &to, NearToken::from_millinear(100)).await?;
    assert_eq!(r["allowed"], json!(false));
    assert_eq!(r["reason"], json!("VaultPaused"));
    Ok(())
}
