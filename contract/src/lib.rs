//! # Agent Allowance
//!
//! Protocol-enforced spending guardrails for AI agents on NEAR.
//!
//! ## Threat model
//!
//! An AI agent cannot reliably distinguish instructions from data, so prompt
//! injection must be assumed to succeed. This contract therefore assumes the
//! agent is fully compromised and asks a different question: how much damage
//! can a compromised agent actually do?
//!
//! Containment is layered:
//!
//! 1. **Protocol layer (NEAR).** The agent holds a FunctionCall access key
//!    restricted to this contract and to `request_spend` only. Per the NEAR
//!    protocol, such a key cannot attach a token deposit and cannot call any
//!    other contract. A fully leaked agent key therefore cannot move tokens
//!    directly, cannot reach a DEX, and cannot touch any other account.
//! 2. **Contract layer (this code).** Amount policy: per-transaction cap,
//!    rolling 24h cap, recipient allowlist, per-agent and global kill switch.
//!
//! ## Deliberate design decisions
//!
//! * **Denials are recorded, not reverted.** A denied request returns a value
//!   instead of panicking, so the denial is durably counted and the event is
//!   emitted. Reverting would erase the evidence of an attack.
//! * **Unknown callers panic.** Recording a denial for an unregistered account
//!   would allocate new state at the vault's expense, which is a storage
//!   exhaustion attack. Unregistered callers are reverted and write nothing.
//! * **Owner mutations require 1 yoctoNEAR.** A FunctionCall key cannot attach
//!   a deposit, so this guarantees policy changes come from a full-access key.
//!   A leaked agent key can never widen its own limits.
//! * **Audit trail is events, not state.** NEP-297 events live in receipts, not
//!   in contract storage, so an attacker spamming denials cannot inflate our
//!   storage cost.
//! * **Debit before transfer.** Counters are updated before the transfer is
//!   scheduled and restored in the callback on failure, so a second request
//!   during the pending callback cannot double-spend.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::{IterableMap, IterableSet};
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};

/// Gas forwarded to a NEP-141 `ft_transfer`.
const FT_TRANSFER_GAS: Gas = Gas::from_tgas(10);
/// Gas reserved for the fungible-token spend callback.
const FT_CALLBACK_GAS: Gas = Gas::from_tgas(10);

/// Length of the rolling spend window: 24 hours in nanoseconds.
const DAY_NS: u64 = 86_400_000_000_000;
/// Maximum recipients per agent. Bounds storage and gas on policy writes.
const MAX_ALLOWLIST: usize = 20;
/// Maximum registered agents. Bounds `list_agents` gas.
const MAX_AGENTS: u32 = 50;
/// Maximum memo length in bytes.
const MAX_MEMO: usize = 256;
/// Maximum opted-in fungible tokens.
const MAX_TOKENS: u32 = 20;
/// Maximum agent/token policy pairs.
const MAX_FT_POLICIES: u32 = 100;
/// Gas reserved for the spend callback.
const CALLBACK_GAS: Gas = Gas::from_tgas(5);
/// Liquid NEAR always retained above storage staking, so the vault can never
/// transfer itself into a state where it cannot pay for its own storage.
const SAFETY_BUFFER: NearToken = NearToken::from_millinear(50);

/// The slice of NEP-141 this contract calls. The trait itself is only a
/// declaration; `ext_contract` generates the `ext_ft` builder we actually use.
#[allow(dead_code)]
#[near_sdk::ext_contract(ext_ft)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[derive(BorshStorageKey)]
#[near(serializers = [borsh])]
enum StorageKey {
    Agents,
    FtPolicies,
    FtBalances,
    AcceptedTokens,
}

/// Why a spend request was refused. Returned to the caller and emitted as an
/// event so the owner has a durable record of every attempt.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub enum DenyReason {
    VaultPaused,
    AgentDisabled,
    AmountZero,
    ExceedsPerTxCap,
    ExceedsDailyCap,
    RecipientNotAllowlisted,
    InsufficientVaultBalance,
    TokenNotAccepted,
}

impl DenyReason {
    fn as_str(&self) -> &'static str {
        match self {
            DenyReason::VaultPaused => "vault_paused",
            DenyReason::AgentDisabled => "agent_disabled",
            DenyReason::AmountZero => "amount_zero",
            DenyReason::ExceedsPerTxCap => "exceeds_per_tx_cap",
            DenyReason::ExceedsDailyCap => "exceeds_daily_cap",
            DenyReason::RecipientNotAllowlisted => "recipient_not_allowlisted",
            DenyReason::InsufficientVaultBalance => "insufficient_vault_balance",
            DenyReason::TokenNotAccepted => "token_not_accepted",
        }
    }
}

/// Outcome of a spend request.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SpendResult {
    pub allowed: bool,
    pub reason: Option<DenyReason>,
}

/// Spending policy and running counters for one agent.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct AgentPolicy {
    pub enabled: bool,
    pub per_tx_cap: U128,
    pub daily_cap: U128,
    pub window_start_ns: U64,
    pub spent_in_window: U128,
    pub lifetime_spent: U128,
    pub allowed_count: u64,
    pub denied_count: u64,
    pub allowlist: Vec<AccountId>,
}

/// One agent's policy for one fungible token, with remaining headroom.
#[near(serializers = [json])]
pub struct FtStatus {
    pub token_id: AccountId,
    pub policy: AgentPolicy,
    pub remaining_today: U128,
}

/// Live view of an agent, including remaining headroom, across native NEAR
/// and every token it has a policy for.
#[near(serializers = [json])]
pub struct AgentStatus {
    pub agent_id: AccountId,
    pub policy: AgentPolicy,
    pub remaining_today: U128,
    pub window_resets_in_ns: U64,
    pub tokens: Vec<FtStatus>,
}

/// A fungible token balance held by the vault.
#[near(serializers = [json])]
pub struct TokenHolding {
    pub token_id: AccountId,
    pub balance: U128,
}

/// Everything the dashboard needs, in a single view call. Front ends that
/// issue one request per field get throttled by public RPC endpoints, so the
/// whole page state is served here at once.
#[near(serializers = [json])]
pub struct Dashboard {
    pub owner_id: AccountId,
    pub paused: bool,
    pub vault_balance: U128,
    pub available_balance: U128,
    pub total_spent: U128,
    pub total_denied: u64,
    pub agents: Vec<AgentStatus>,
    pub tokens: Vec<TokenHolding>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    paused: bool,
    agents: IterableMap<AccountId, AgentPolicy>,
    total_spent: U128,
    total_denied: u64,
    /// Fungible-token policies, keyed by `agent_id|token_id`. The same policy
    /// shape as native NEAR, so the rules behave identically per token.
    ft_policies: IterableMap<String, AgentPolicy>,
    /// Token balances the vault currently holds.
    ft_balances: IterableMap<AccountId, U128>,
    /// Tokens the owner has opted into. Deposits of anything else are rejected,
    /// so nobody can create state in this contract at our expense.
    accepted_tokens: IterableSet<AccountId>,
}

/// State as it existed before fungible-token support, used only by `migrate`.
#[near(serializers = [borsh])]
struct LegacyContract {
    owner_id: AccountId,
    paused: bool,
    agents: IterableMap<AccountId, AgentPolicy>,
    total_spent: U128,
    total_denied: u64,
}

fn ft_key(agent_id: &AccountId, token_id: &AccountId) -> String {
    format!("{}|{}", agent_id, token_id)
}

/// Apply the spending policy and update counters.
///
/// Shared by the native-NEAR and fungible-token paths so a token spend cannot
/// drift from the rules that govern NEAR. Debits before the caller schedules a
/// transfer; the caller restores on failure.
fn evaluate(
    policy: &mut AgentPolicy,
    paused: bool,
    now: u64,
    requested: u128,
    recipient: &AccountId,
    available: u128,
) -> Result<U64, DenyReason> {
    if now.saturating_sub(policy.window_start_ns.0) >= DAY_NS {
        policy.window_start_ns = U64(now);
        policy.spent_in_window = U128(0);
    }
    let deny = if paused {
        Some(DenyReason::VaultPaused)
    } else if !policy.enabled {
        Some(DenyReason::AgentDisabled)
    } else if requested == 0 {
        Some(DenyReason::AmountZero)
    } else if requested > policy.per_tx_cap.0 {
        Some(DenyReason::ExceedsPerTxCap)
    } else if policy.spent_in_window.0.saturating_add(requested) > policy.daily_cap.0 {
        Some(DenyReason::ExceedsDailyCap)
    } else if !policy.allowlist.contains(recipient) {
        Some(DenyReason::RecipientNotAllowlisted)
    } else if requested > available {
        Some(DenyReason::InsufficientVaultBalance)
    } else {
        None
    };
    match deny {
        Some(reason) => {
            policy.denied_count = policy.denied_count.saturating_add(1);
            Err(reason)
        }
        None => {
            policy.spent_in_window = U128(policy.spent_in_window.0.saturating_add(requested));
            policy.lifetime_spent = U128(policy.lifetime_spent.0.saturating_add(requested));
            policy.allowed_count = policy.allowed_count.saturating_add(1);
            Ok(policy.window_start_ns)
        }
    }
}

fn emit_event(event: &str, data: near_sdk::serde_json::Value) {
    let payload = near_sdk::serde_json::json!({
        "standard": "agent_allowance",
        "version": "1.0.0",
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{}", payload));
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId) -> Self {
        Self {
            owner_id,
            paused: false,
            agents: IterableMap::new(StorageKey::Agents),
            total_spent: U128(0),
            total_denied: 0,
            ft_policies: IterableMap::new(StorageKey::FtPolicies),
            ft_balances: IterableMap::new(StorageKey::FtBalances),
            accepted_tokens: IterableSet::new(StorageKey::AcceptedTokens),
        }
    }

    /// Carry existing state across the upgrade that added fungible-token
    /// support. Agents, counters and the kill switch are preserved exactly;
    /// only the new collections are introduced.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: LegacyContract = env::state_read().unwrap_or_else(|| {
            env::panic_str("no existing state to migrate");
        });
        Self {
            owner_id: old.owner_id,
            paused: old.paused,
            agents: old.agents,
            total_spent: old.total_spent,
            total_denied: old.total_denied,
            ft_policies: IterableMap::new(StorageKey::FtPolicies),
            ft_balances: IterableMap::new(StorageKey::FtBalances),
            accepted_tokens: IterableSet::new(StorageKey::AcceptedTokens),
        }
    }

    // ---------------------------------------------------------------- owner

    /// Register an agent with a spending policy. Owner only.
    #[payable]
    pub fn add_agent(
        &mut self,
        agent_id: AccountId,
        per_tx_cap: U128,
        daily_cap: U128,
        allowlist: Vec<AccountId>,
    ) {
        self.assert_owner();
        require!(self.agents.len() < MAX_AGENTS, "agent limit reached");
        require!(
            !self.agents.contains_key(&agent_id),
            "agent already registered"
        );
        Self::validate_policy(per_tx_cap, daily_cap, &allowlist);

        self.agents.insert(
            agent_id.clone(),
            AgentPolicy {
                enabled: true,
                per_tx_cap,
                daily_cap,
                window_start_ns: U64(env::block_timestamp()),
                spent_in_window: U128(0),
                lifetime_spent: U128(0),
                allowed_count: 0,
                denied_count: 0,
                allowlist: allowlist.clone(),
            },
        );

        emit_event(
            "agent_added",
            near_sdk::serde_json::json!({
                "agent_id": agent_id,
                "per_tx_cap": per_tx_cap,
                "daily_cap": daily_cap,
                "allowlist": allowlist,
            }),
        );
    }

    /// Replace an existing agent's policy. Counters are preserved. Owner only.
    #[payable]
    pub fn update_policy(
        &mut self,
        agent_id: AccountId,
        per_tx_cap: U128,
        daily_cap: U128,
        allowlist: Vec<AccountId>,
    ) {
        self.assert_owner();
        Self::validate_policy(per_tx_cap, daily_cap, &allowlist);
        let policy = self
            .agents
            .get_mut(&agent_id)
            .unwrap_or_else(|| env::panic_str("unknown agent"));
        policy.per_tx_cap = per_tx_cap;
        policy.daily_cap = daily_cap;
        policy.allowlist = allowlist.clone();

        emit_event(
            "policy_updated",
            near_sdk::serde_json::json!({
                "agent_id": agent_id,
                "per_tx_cap": per_tx_cap,
                "daily_cap": daily_cap,
                "allowlist": allowlist,
            }),
        );
    }

    /// Enable or disable one agent. Owner only.
    #[payable]
    pub fn set_agent_enabled(&mut self, agent_id: AccountId, enabled: bool) {
        self.assert_owner();
        let policy = self
            .agents
            .get_mut(&agent_id)
            .unwrap_or_else(|| env::panic_str("unknown agent"));
        policy.enabled = enabled;
        emit_event(
            "agent_enabled_changed",
            near_sdk::serde_json::json!({ "agent_id": agent_id, "enabled": enabled }),
        );
    }

    /// Remove an agent entirely. Owner only.
    #[payable]
    pub fn revoke_agent(&mut self, agent_id: AccountId) {
        self.assert_owner();
        require!(self.agents.remove(&agent_id).is_some(), "unknown agent");
        emit_event(
            "agent_revoked",
            near_sdk::serde_json::json!({ "agent_id": agent_id }),
        );
    }

    /// Global kill switch. Halts every agent at once. Owner only.
    #[payable]
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;
        emit_event(
            "paused_changed",
            near_sdk::serde_json::json!({ "paused": paused }),
        );
    }

    /// Withdraw funds from the vault. Owner only.
    #[payable]
    pub fn withdraw(&mut self, amount: U128, to: AccountId) -> Promise {
        self.assert_owner();
        let available = Self::available_balance_internal().as_yoctonear();
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= available, "amount exceeds available balance");
        emit_event(
            "owner_withdrawal",
            near_sdk::serde_json::json!({ "to": to, "amount": amount }),
        );
        Promise::new(to).transfer(NearToken::from_yoctonear(amount.0))
    }

    /// Fund the vault. Open to anyone.
    #[payable]
    pub fn deposit(&mut self) {
        let amount = env::attached_deposit();
        require!(amount.as_yoctonear() > 0, "attach a deposit");
        emit_event(
            "deposit",
            near_sdk::serde_json::json!({
                "from": env::predecessor_account_id(),
                "amount": U128(amount.as_yoctonear()),
            }),
        );
    }

    // ------------------------------------------------------ fungible tokens

    /// Opt into a NEP-141 token. Deposits of anything else are refused, so no
    /// stranger can create state in this contract at the vault's expense.
    #[payable]
    pub fn add_token(&mut self, token_id: AccountId) {
        self.assert_owner();
        require!(
            self.accepted_tokens.len() < MAX_TOKENS,
            "token limit reached"
        );
        if self.accepted_tokens.insert(token_id.clone()) {
            self.ft_balances.insert(token_id.clone(), U128(0));
        }
        emit_event(
            "token_accepted",
            near_sdk::serde_json::json!({ "token_id": token_id }),
        );
    }

    /// Stop accepting a token. Any balance already held remains in the vault
    /// and can still be withdrawn by the owner with `withdraw_ft`.
    #[payable]
    pub fn remove_token(&mut self, token_id: AccountId) {
        self.assert_owner();
        require!(self.accepted_tokens.remove(&token_id), "token not accepted");
        emit_event(
            "token_removed",
            near_sdk::serde_json::json!({ "token_id": token_id }),
        );
    }

    /// Withdraw fungible tokens from the vault. Owner only.
    ///
    /// The vault accepts NEP-141 deposits, so the owner must have a way out
    /// that does not depend on an agent policy. Works for tokens that have
    /// since been removed, so stopping acceptance never strands a balance.
    /// Debits before the transfer is scheduled and credits back in the
    /// callback on failure, the same discipline as every outbound path here.
    #[payable]
    pub fn withdraw_ft(&mut self, token_id: AccountId, amount: U128, to: AccountId) -> Promise {
        self.assert_owner();
        let held = self.ft_balances.get(&token_id).map(|b| b.0).unwrap_or(0);
        require!(amount.0 > 0, "amount must be positive");
        require!(amount.0 <= held, "amount exceeds held balance");
        self.ft_balances
            .insert(token_id.clone(), U128(held.saturating_sub(amount.0)));
        emit_event(
            "owner_ft_withdrawal",
            near_sdk::serde_json::json!({
                "token_id": token_id, "to": to, "amount": amount,
            }),
        );
        ext_ft::ext(token_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(FT_TRANSFER_GAS)
            .ft_transfer(to, amount, None)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(FT_CALLBACK_GAS)
                    .on_ft_withdraw_complete(token_id, amount),
            )
    }

    /// Credits the held balance back if an owner withdrawal failed.
    #[private]
    pub fn on_ft_withdraw_complete(
        &mut self,
        token_id: AccountId,
        amount: U128,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> bool {
        if result.is_ok() {
            return true;
        }
        let held = self.ft_balances.get(&token_id).map(|b| b.0).unwrap_or(0);
        self.ft_balances
            .insert(token_id.clone(), U128(held.saturating_add(amount.0)));
        emit_event(
            "owner_ft_withdrawal_reverted",
            near_sdk::serde_json::json!({ "token_id": token_id, "amount": amount }),
        );
        false
    }

    /// Set an agent's spending policy for one token. Owner only.
    #[payable]
    pub fn set_ft_policy(
        &mut self,
        agent_id: AccountId,
        token_id: AccountId,
        per_tx_cap: U128,
        daily_cap: U128,
        allowlist: Vec<AccountId>,
    ) {
        self.assert_owner();
        require!(
            self.accepted_tokens.contains(&token_id),
            "token not accepted"
        );
        require!(self.agents.contains_key(&agent_id), "unknown agent");
        Self::validate_policy(per_tx_cap, daily_cap, &allowlist);
        let key = ft_key(&agent_id, &token_id);
        let now = env::block_timestamp();
        match self.ft_policies.get_mut(&key) {
            Some(existing) => {
                existing.per_tx_cap = per_tx_cap;
                existing.daily_cap = daily_cap;
                existing.allowlist = allowlist.clone();
                existing.enabled = true;
            }
            None => {
                require!(
                    self.ft_policies.len() < MAX_FT_POLICIES,
                    "token policy limit reached"
                );
                self.ft_policies.insert(
                    key,
                    AgentPolicy {
                        enabled: true,
                        per_tx_cap,
                        daily_cap,
                        window_start_ns: U64(now),
                        spent_in_window: U128(0),
                        lifetime_spent: U128(0),
                        allowed_count: 0,
                        denied_count: 0,
                        allowlist: allowlist.clone(),
                    },
                );
            }
        }
        emit_event(
            "ft_policy_set",
            near_sdk::serde_json::json!({
                "agent_id": agent_id, "token_id": token_id,
                "per_tx_cap": per_tx_cap, "daily_cap": daily_cap,
                "allowlist": allowlist,
            }),
        );
    }

    /// Remove an agent's policy for one token. Owner only.
    #[payable]
    pub fn revoke_ft_policy(&mut self, agent_id: AccountId, token_id: AccountId) {
        self.assert_owner();
        require!(
            self.ft_policies
                .remove(&ft_key(&agent_id, &token_id))
                .is_some(),
            "no policy for that agent and token"
        );
        emit_event(
            "ft_policy_revoked",
            near_sdk::serde_json::json!({ "agent_id": agent_id, "token_id": token_id }),
        );
    }

    /// NEP-141 deposit hook. The token contract calls this when someone sends
    /// tokens here. Returns the unused amount, which is zero: the vault keeps
    /// what it is given, provided the token was opted into.
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let token_id = env::predecessor_account_id();
        require!(msg.len() <= MAX_MEMO, "msg too long");
        // Refuse unknown tokens by returning the full amount, which makes the
        // token contract refund the sender. Accepting would let anyone grow
        // our state for free.
        if !self.accepted_tokens.contains(&token_id) {
            emit_event(
                "ft_deposit_refused",
                near_sdk::serde_json::json!({
                    "token_id": token_id, "from": sender_id,
                    "amount": amount, "reason": "token_not_accepted",
                }),
            );
            return PromiseOrValue::Value(amount);
        }
        let held = self.ft_balances.get(&token_id).map(|b| b.0).unwrap_or(0);
        self.ft_balances
            .insert(token_id.clone(), U128(held.saturating_add(amount.0)));
        emit_event(
            "ft_deposit",
            near_sdk::serde_json::json!({
                "token_id": token_id, "from": sender_id, "amount": amount, "msg": msg,
            }),
        );
        PromiseOrValue::Value(U128(0))
    }

    /// Request a token spend. Mirrors `request_spend` exactly, against the
    /// policy registered for this agent and token.
    pub fn request_spend_ft(
        &mut self,
        token_id: AccountId,
        recipient: AccountId,
        amount: U128,
        memo: Option<String>,
    ) -> PromiseOrValue<SpendResult> {
        let agent_id = env::predecessor_account_id();
        let key = ft_key(&agent_id, &token_id);
        require!(
            self.ft_policies.contains_key(&key),
            "no policy for that token"
        );
        if let Some(m) = &memo {
            require!(m.len() <= MAX_MEMO, "memo too long");
        }

        let now = env::block_timestamp();
        let paused = self.paused;
        let requested = amount.0;
        let accepted = self.accepted_tokens.contains(&token_id);
        let held = self.ft_balances.get(&token_id).map(|b| b.0).unwrap_or(0);

        let decision = if !accepted {
            let policy = self.ft_policies.get_mut(&key).unwrap();
            policy.denied_count = policy.denied_count.saturating_add(1);
            Err(DenyReason::TokenNotAccepted)
        } else {
            let policy = self.ft_policies.get_mut(&key).unwrap();
            evaluate(policy, paused, now, requested, &recipient, held)
        };

        match decision {
            Err(reason) => {
                self.total_denied = self.total_denied.saturating_add(1);
                emit_event(
                    "ft_spend_denied",
                    near_sdk::serde_json::json!({
                        "agent_id": agent_id, "token_id": token_id,
                        "recipient": recipient, "amount": amount,
                        "reason": reason.as_str(), "memo": memo,
                    }),
                );
                PromiseOrValue::Value(SpendResult {
                    allowed: false,
                    reason: Some(reason),
                })
            }
            Ok(window_start_ns) => {
                // Debit the held balance before scheduling the transfer, for
                // the same reason as the native path.
                self.ft_balances
                    .insert(token_id.clone(), U128(held.saturating_sub(requested)));
                emit_event(
                    "ft_spend_allowed",
                    near_sdk::serde_json::json!({
                        "agent_id": agent_id, "token_id": token_id,
                        "recipient": recipient, "amount": amount, "memo": memo,
                    }),
                );
                PromiseOrValue::Promise(
                    ext_ft::ext(token_id.clone())
                        .with_attached_deposit(NearToken::from_yoctonear(1))
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(recipient.clone(), amount, memo)
                        .then(
                            Self::ext(env::current_account_id())
                                .with_static_gas(FT_CALLBACK_GAS)
                                .on_ft_spend_complete(
                                    agent_id,
                                    token_id,
                                    recipient,
                                    amount,
                                    window_start_ns,
                                ),
                        ),
                )
            }
        }
    }

    /// Settles a token spend, restoring counters and held balance on failure.
    #[private]
    pub fn on_ft_spend_complete(
        &mut self,
        agent_id: AccountId,
        token_id: AccountId,
        recipient: AccountId,
        amount: U128,
        window_start_ns: U64,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> bool {
        if result.is_ok() {
            return true;
        }
        let requested = amount.0;
        let key = ft_key(&agent_id, &token_id);
        if let Some(policy) = self.ft_policies.get_mut(&key) {
            if policy.window_start_ns.0 == window_start_ns.0 {
                policy.spent_in_window = U128(policy.spent_in_window.0.saturating_sub(requested));
            }
            policy.lifetime_spent = U128(policy.lifetime_spent.0.saturating_sub(requested));
            policy.allowed_count = policy.allowed_count.saturating_sub(1);
        }
        let held = self.ft_balances.get(&token_id).map(|b| b.0).unwrap_or(0);
        self.ft_balances
            .insert(token_id.clone(), U128(held.saturating_add(requested)));
        emit_event(
            "ft_spend_reverted",
            near_sdk::serde_json::json!({
                "agent_id": agent_id, "token_id": token_id,
                "recipient": recipient, "amount": amount,
            }),
        );
        false
    }

    // ---------------------------------------------------------------- agent

    /// Request a spend. Called by an agent through a FunctionCall access key
    /// restricted to this contract and this method.
    ///
    /// Returns a value on denial rather than panicking, so the denial is
    /// durably recorded. Unregistered callers panic, writing nothing.
    pub fn request_spend(
        &mut self,
        recipient: AccountId,
        amount: U128,
        memo: Option<String>,
    ) -> PromiseOrValue<SpendResult> {
        let agent_id = env::predecessor_account_id();
        require!(self.agents.contains_key(&agent_id), "unregistered agent");
        if let Some(m) = &memo {
            require!(m.len() <= MAX_MEMO, "memo too long");
        }

        let now = env::block_timestamp();
        let paused = self.paused;
        let available = Self::available_balance_internal().as_yoctonear();
        let requested = amount.0;

        let decision = {
            let policy = self.agents.get_mut(&agent_id).unwrap();
            evaluate(policy, paused, now, requested, &recipient, available)
        };

        match decision {
            Err(reason) => {
                self.total_denied = self.total_denied.saturating_add(1);
                emit_event(
                    "spend_denied",
                    near_sdk::serde_json::json!({
                        "agent_id": agent_id,
                        "recipient": recipient,
                        "amount": amount,
                        "reason": reason.as_str(),
                        "memo": memo,
                    }),
                );
                PromiseOrValue::Value(SpendResult {
                    allowed: false,
                    reason: Some(reason),
                })
            }
            Ok(window_start_ns) => {
                self.total_spent = U128(self.total_spent.0.saturating_add(requested));
                emit_event(
                    "spend_allowed",
                    near_sdk::serde_json::json!({
                        "agent_id": agent_id,
                        "recipient": recipient,
                        "amount": amount,
                        "memo": memo,
                    }),
                );
                PromiseOrValue::Promise(
                    Promise::new(recipient.clone())
                        .transfer(NearToken::from_yoctonear(requested))
                        .then(
                            Self::ext(env::current_account_id())
                                .with_static_gas(CALLBACK_GAS)
                                .on_spend_complete(agent_id, recipient, amount, window_start_ns),
                        ),
                )
            }
        }
    }

    /// Settles a spend. Restores counters if the transfer failed.
    #[private]
    pub fn on_spend_complete(
        &mut self,
        agent_id: AccountId,
        recipient: AccountId,
        amount: U128,
        window_start_ns: U64,
        #[callback_result] result: Result<(), PromiseError>,
    ) -> bool {
        if result.is_ok() {
            return true;
        }

        let requested = amount.0;
        if let Some(policy) = self.agents.get_mut(&agent_id) {
            // Only refund window spend if the window has not rolled over since
            // the debit; otherwise spent_in_window already restarted at zero.
            if policy.window_start_ns.0 == window_start_ns.0 {
                policy.spent_in_window = U128(policy.spent_in_window.0.saturating_sub(requested));
            }
            policy.lifetime_spent = U128(policy.lifetime_spent.0.saturating_sub(requested));
            policy.allowed_count = policy.allowed_count.saturating_sub(1);
        }
        self.total_spent = U128(self.total_spent.0.saturating_sub(requested));

        emit_event(
            "spend_reverted",
            near_sdk::serde_json::json!({
                "agent_id": agent_id,
                "recipient": recipient,
                "amount": amount,
            }),
        );
        false
    }

    // ---------------------------------------------------------------- views

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn get_policy(&self, agent_id: AccountId) -> Option<AgentPolicy> {
        self.agents.get(&agent_id).cloned()
    }

    pub fn get_agent_status(&self, agent_id: AccountId) -> Option<AgentStatus> {
        let policy = self.agents.get(&agent_id)?.clone();
        let now = env::block_timestamp();
        let elapsed = now.saturating_sub(policy.window_start_ns.0);
        let (spent, resets_in) = if elapsed >= DAY_NS {
            (0u128, DAY_NS)
        } else {
            (policy.spent_in_window.0, DAY_NS - elapsed)
        };
        let tokens = self
            .accepted_tokens
            .iter()
            .filter_map(|token_id| {
                let p = self.ft_policies.get(&ft_key(&agent_id, token_id))?.clone();
                let elapsed = now.saturating_sub(p.window_start_ns.0);
                let spent = if elapsed >= DAY_NS {
                    0
                } else {
                    p.spent_in_window.0
                };
                Some(FtStatus {
                    token_id: token_id.clone(),
                    remaining_today: U128(p.daily_cap.0.saturating_sub(spent)),
                    policy: p,
                })
            })
            .collect();
        Some(AgentStatus {
            agent_id,
            remaining_today: U128(policy.daily_cap.0.saturating_sub(spent)),
            window_resets_in_ns: U64(resets_in),
            policy,
            tokens,
        })
    }

    pub fn get_ft_policy(&self, agent_id: AccountId, token_id: AccountId) -> Option<AgentPolicy> {
        self.ft_policies.get(&ft_key(&agent_id, &token_id)).cloned()
    }

    pub fn ft_balance(&self, token_id: AccountId) -> U128 {
        self.ft_balances.get(&token_id).copied().unwrap_or(U128(0))
    }

    pub fn list_tokens(&self) -> Vec<AccountId> {
        self.accepted_tokens.iter().cloned().collect()
    }

    pub fn list_agents(&self) -> Vec<AccountId> {
        self.agents.keys().cloned().collect()
    }

    pub fn vault_balance(&self) -> U128 {
        U128(env::account_balance().as_yoctonear())
    }

    pub fn available_balance(&self) -> U128 {
        U128(Self::available_balance_internal().as_yoctonear())
    }

    pub fn stats(&self) -> near_sdk::serde_json::Value {
        near_sdk::serde_json::json!({
            "total_spent": self.total_spent,
            "total_denied": self.total_denied,
            "agent_count": self.agents.len(),
            "paused": self.paused,
        })
    }

    /// Full dashboard state in one call.
    pub fn dashboard(&self) -> Dashboard {
        let agents: Vec<AgentStatus> = self
            .agents
            .keys()
            .cloned()
            .collect::<Vec<AccountId>>()
            .into_iter()
            .filter_map(|id| self.get_agent_status(id))
            .collect();
        Dashboard {
            owner_id: self.owner_id.clone(),
            paused: self.paused,
            vault_balance: U128(env::account_balance().as_yoctonear()),
            available_balance: U128(Self::available_balance_internal().as_yoctonear()),
            total_spent: self.total_spent,
            total_denied: self.total_denied,
            agents,
            tokens: self
                .accepted_tokens
                .iter()
                .map(|t| TokenHolding {
                    token_id: t.clone(),
                    balance: self.ft_balances.get(t).copied().unwrap_or(U128(0)),
                })
                .collect(),
        }
    }

    // -------------------------------------------------------------- internal

    /// Owner check plus a 1 yoctoNEAR deposit requirement. A FunctionCall key
    /// cannot attach a deposit, so this proves a full-access key signed the
    /// call and a leaked agent key can never reach these methods.
    fn assert_owner(&self) {
        assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    /// Liquid balance, excluding storage staking and the safety buffer.
    fn available_balance_internal() -> NearToken {
        let locked = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128);
        env::account_balance()
            .saturating_sub(locked)
            .saturating_sub(SAFETY_BUFFER)
    }

    fn validate_policy(per_tx_cap: U128, daily_cap: U128, allowlist: &[AccountId]) {
        require!(per_tx_cap.0 > 0, "per_tx_cap must be positive");
        require!(daily_cap.0 > 0, "daily_cap must be positive");
        require!(
            per_tx_cap.0 <= daily_cap.0,
            "per_tx_cap cannot exceed daily_cap"
        );
        require!(allowlist.len() <= MAX_ALLOWLIST, "allowlist too large");
        require!(!allowlist.is_empty(), "allowlist cannot be empty");
        let mut seen = allowlist.to_vec();
        seen.sort();
        seen.dedup();
        require!(seen.len() == allowlist.len(), "duplicate allowlist entries");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, VMContext};

    const ONE_YOCTO: NearToken = NearToken::from_yoctonear(1);

    fn owner() -> AccountId {
        accounts(0)
    }
    fn agent() -> AccountId {
        accounts(1)
    }
    fn allowed_payee() -> AccountId {
        accounts(2)
    }
    fn attacker() -> AccountId {
        accounts(3)
    }
    fn stranger() -> AccountId {
        accounts(4)
    }

    fn ctx(predecessor: AccountId, deposit: NearToken, ts: u64) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(accounts(5))
            .predecessor_account_id(predecessor)
            .attached_deposit(deposit)
            .block_timestamp(ts)
            .account_balance(NearToken::from_near(100))
            .build()
    }

    /// Vault with one agent: 1 NEAR per tx, 3 NEAR per day, one allowed payee.
    fn setup() -> Contract {
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let mut c = Contract::new(owner());
        c.add_agent(
            agent(),
            U128(NearToken::from_near(1).as_yoctonear()),
            U128(NearToken::from_near(3).as_yoctonear()),
            vec![allowed_payee()],
        );
        c
    }

    fn spend(
        c: &mut Contract,
        who: AccountId,
        to: AccountId,
        near_amount: u128,
        ts: u64,
    ) -> SpendResult {
        testing_env!(ctx(who, NearToken::from_yoctonear(0), ts));
        match c.request_spend(
            to,
            U128(NearToken::from_near(near_amount).as_yoctonear()),
            None,
        ) {
            PromiseOrValue::Value(r) => r,
            PromiseOrValue::Promise(_) => SpendResult {
                allowed: true,
                reason: None,
            },
        }
    }

    // ------------------------------------------------------------ happy path

    #[test]
    fn allows_spend_within_policy() {
        let mut c = setup();
        let r = spend(&mut c, agent(), allowed_payee(), 1, 0);
        assert!(r.allowed, "spend within policy should be allowed");
        let p = c.get_policy(agent()).unwrap();
        assert_eq!(p.allowed_count, 1);
        assert_eq!(p.denied_count, 0);
    }

    // -------------------------------------------------- THE ATTACK WE DEFEND

    /// The core scenario: the agent is fully compromised by prompt injection
    /// and tries to send everything to an attacker address. The vault refuses
    /// because the recipient is not on the allowlist.
    #[test]
    fn blocks_prompt_injected_drain_to_unknown_recipient() {
        let mut c = setup();
        let r = spend(&mut c, agent(), attacker(), 1, 0);
        assert!(
            !r.allowed,
            "drain to non-allowlisted address must be denied"
        );
        assert_eq!(r.reason, Some(DenyReason::RecipientNotAllowlisted));
        let p = c.get_policy(agent()).unwrap();
        assert_eq!(p.denied_count, 1, "denial must be recorded, not reverted");
        assert_eq!(p.lifetime_spent.0, 0, "no value may move on a denial");
    }

    #[test]
    fn blocks_oversized_single_transfer() {
        let mut c = setup();
        let r = spend(&mut c, agent(), allowed_payee(), 2, 0);
        assert!(!r.allowed);
        assert_eq!(r.reason, Some(DenyReason::ExceedsPerTxCap));
    }

    #[test]
    fn enforces_daily_cap_across_many_small_spends() {
        let mut c = setup();
        for _ in 0..3 {
            assert!(spend(&mut c, agent(), allowed_payee(), 1, 0).allowed);
        }
        // Fourth spend is within per-tx cap but breaches the 3 NEAR daily cap.
        let r = spend(&mut c, agent(), allowed_payee(), 1, 0);
        assert!(!r.allowed, "daily cap must stop death by a thousand cuts");
        assert_eq!(r.reason, Some(DenyReason::ExceedsDailyCap));
    }

    #[test]
    fn daily_window_resets_after_24h() {
        let mut c = setup();
        for _ in 0..3 {
            assert!(spend(&mut c, agent(), allowed_payee(), 1, 0).allowed);
        }
        assert!(!spend(&mut c, agent(), allowed_payee(), 1, 0).allowed);
        // One nanosecond past the window.
        let r = spend(&mut c, agent(), allowed_payee(), 1, DAY_NS + 1);
        assert!(r.allowed, "window should roll over after 24h");
    }

    #[test]
    fn kill_switch_halts_every_agent() {
        let mut c = setup();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.set_paused(true);
        let r = spend(&mut c, agent(), allowed_payee(), 1, 0);
        assert!(!r.allowed);
        assert_eq!(r.reason, Some(DenyReason::VaultPaused));
    }

    #[test]
    fn disabled_agent_cannot_spend() {
        let mut c = setup();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.set_agent_enabled(agent(), false);
        let r = spend(&mut c, agent(), allowed_payee(), 1, 0);
        assert_eq!(r.reason, Some(DenyReason::AgentDisabled));
    }

    #[test]
    fn zero_amount_is_denied() {
        let mut c = setup();
        testing_env!(ctx(agent(), NearToken::from_yoctonear(0), 0));
        match c.request_spend(allowed_payee(), U128(0), None) {
            PromiseOrValue::Value(r) => assert_eq!(r.reason, Some(DenyReason::AmountZero)),
            _ => panic!("zero amount must not produce a transfer"),
        }
    }

    // ------------------------------------------------- authorization bounds

    /// An unregistered account must write no state at all, otherwise anyone
    /// could inflate our storage for free.
    #[test]
    #[should_panic(expected = "unregistered agent")]
    fn unregistered_caller_is_reverted_not_recorded() {
        let mut c = setup();
        spend(&mut c, stranger(), allowed_payee(), 1, 0);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_add_agent() {
        let mut c = setup();
        testing_env!(ctx(attacker(), ONE_YOCTO, 0));
        c.add_agent(
            attacker(),
            U128(NearToken::from_near(1).as_yoctonear()),
            U128(NearToken::from_near(1).as_yoctonear()),
            vec![attacker()],
        );
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_pause() {
        let mut c = setup();
        testing_env!(ctx(attacker(), ONE_YOCTO, 0));
        c.set_paused(true);
    }

    /// A FunctionCall key cannot attach a deposit, so a zero-deposit call to an
    /// owner method proves the caller was not using a full-access key.
    #[test]
    #[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
    fn owner_methods_reject_function_call_keys() {
        let mut c = setup();
        testing_env!(ctx(owner(), NearToken::from_yoctonear(0), 0));
        c.set_paused(true);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn agent_cannot_widen_its_own_policy() {
        let mut c = setup();
        testing_env!(ctx(agent(), ONE_YOCTO, 0));
        c.update_policy(
            agent(),
            U128(NearToken::from_near(99).as_yoctonear()),
            U128(NearToken::from_near(99).as_yoctonear()),
            vec![attacker()],
        );
    }

    #[test]
    #[should_panic(expected = "unregistered agent")]
    fn revoked_agent_cannot_spend() {
        let mut c = setup();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.revoke_agent(agent());
        spend(&mut c, agent(), allowed_payee(), 1, 0);
    }

    // ------------------------------------------------------ policy validation

    #[test]
    #[should_panic(expected = "per_tx_cap cannot exceed daily_cap")]
    fn rejects_per_tx_above_daily() {
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let mut c = Contract::new(owner());
        c.add_agent(
            agent(),
            U128(NearToken::from_near(5).as_yoctonear()),
            U128(NearToken::from_near(1).as_yoctonear()),
            vec![allowed_payee()],
        );
    }

    #[test]
    #[should_panic(expected = "duplicate allowlist entries")]
    fn rejects_duplicate_allowlist() {
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let mut c = Contract::new(owner());
        c.add_agent(
            agent(),
            U128(NearToken::from_near(1).as_yoctonear()),
            U128(NearToken::from_near(1).as_yoctonear()),
            vec![allowed_payee(), allowed_payee()],
        );
    }

    #[test]
    #[should_panic(expected = "allowlist cannot be empty")]
    fn rejects_empty_allowlist() {
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let mut c = Contract::new(owner());
        c.add_agent(
            agent(),
            U128(NearToken::from_near(1).as_yoctonear()),
            U128(NearToken::from_near(1).as_yoctonear()),
            vec![],
        );
    }

    // ------------------------------------------------------------ accounting

    #[test]
    fn failed_transfer_restores_headroom() {
        let mut c = setup();
        assert!(spend(&mut c, agent(), allowed_payee(), 1, 0).allowed);
        let before = c.get_policy(agent()).unwrap();
        assert_eq!(
            before.spent_in_window.0,
            NearToken::from_near(1).as_yoctonear()
        );

        // Simulate the transfer failing; the private callback refunds headroom.
        testing_env!(ctx(accounts(5), NearToken::from_yoctonear(0), 0));
        c.on_spend_complete(
            agent(),
            allowed_payee(),
            U128(NearToken::from_near(1).as_yoctonear()),
            before.window_start_ns,
            Err(PromiseError::Failed),
        );
        let after = c.get_policy(agent()).unwrap();
        assert_eq!(
            after.spent_in_window.0, 0,
            "failed transfer must refund headroom"
        );
        assert_eq!(after.lifetime_spent.0, 0);
    }

    // ------------------------------------------------------ fungible tokens

    fn token() -> AccountId {
        "usdc.test.near".parse().unwrap()
    }
    fn other_token() -> AccountId {
        "scam.test.near".parse().unwrap()
    }

    /// Vault with one agent and a USDC policy: 10 per tx, 50 per day.
    fn setup_ft() -> Contract {
        let mut c = setup();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.add_token(token());
        c.set_ft_policy(agent(), token(), U128(10), U128(50), vec![allowed_payee()]);
        // Fund the vault with 100 USDC, as the token contract would.
        testing_env!(ctx(token(), NearToken::from_yoctonear(0), 0));
        let _ = c.ft_on_transfer(owner(), U128(100), String::new());
        c
    }

    fn spend_ft(c: &mut Contract, who: AccountId, to: AccountId, amount: u128) -> SpendResult {
        testing_env!(ctx(who, NearToken::from_yoctonear(0), 0));
        match c.request_spend_ft(token(), to, U128(amount), None) {
            PromiseOrValue::Value(r) => r,
            PromiseOrValue::Promise(_) => SpendResult {
                allowed: true,
                reason: None,
            },
        }
    }

    #[test]
    fn accepts_deposits_of_opted_in_tokens() {
        let c = setup_ft();
        assert_eq!(c.ft_balance(token()).0, 100);
    }

    /// An unknown token must be refunded in full and must not create state.
    /// Accepting one would let anyone grow our storage at our expense.
    #[test]
    fn refuses_deposits_of_unknown_tokens() {
        let mut c = setup_ft();
        testing_env!(ctx(other_token(), NearToken::from_yoctonear(0), 0));
        match c.ft_on_transfer(attacker(), U128(500), String::new()) {
            PromiseOrValue::Value(refund) => {
                assert_eq!(refund.0, 500, "the whole deposit must be returned")
            }
            _ => panic!("unknown token must not be accepted"),
        }
        assert_eq!(
            c.ft_balance(other_token()).0,
            0,
            "no balance may be recorded"
        );
        assert!(!c.list_tokens().contains(&other_token()));
    }

    #[test]
    fn allows_token_spend_within_policy() {
        let mut c = setup_ft();
        let r = spend_ft(&mut c, agent(), allowed_payee(), 10);
        assert!(r.allowed);
        assert_eq!(
            c.ft_balance(token()).0,
            90,
            "held balance debited before transfer"
        );
    }

    /// The headline claim, in token form.
    #[test]
    fn blocks_token_drain_to_unknown_recipient() {
        let mut c = setup_ft();
        let r = spend_ft(&mut c, agent(), attacker(), 10);
        assert!(!r.allowed);
        assert_eq!(r.reason, Some(DenyReason::RecipientNotAllowlisted));
        assert_eq!(
            c.ft_balance(token()).0,
            100,
            "no tokens may move on a denial"
        );
    }

    #[test]
    fn enforces_token_per_tx_cap() {
        let mut c = setup_ft();
        let r = spend_ft(&mut c, agent(), allowed_payee(), 11);
        assert_eq!(r.reason, Some(DenyReason::ExceedsPerTxCap));
    }

    #[test]
    fn enforces_token_daily_cap() {
        let mut c = setup_ft();
        for _ in 0..5 {
            assert!(spend_ft(&mut c, agent(), allowed_payee(), 10).allowed);
        }
        let r = spend_ft(&mut c, agent(), allowed_payee(), 10);
        assert_eq!(r.reason, Some(DenyReason::ExceedsDailyCap));
    }

    #[test]
    fn token_spend_cannot_exceed_held_balance() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.set_ft_policy(
            agent(),
            token(),
            U128(500),
            U128(500),
            vec![allowed_payee()],
        );
        let r = spend_ft(&mut c, agent(), allowed_payee(), 200);
        assert_eq!(r.reason, Some(DenyReason::InsufficientVaultBalance));
    }

    #[test]
    fn kill_switch_also_halts_token_spending() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.set_paused(true);
        let r = spend_ft(&mut c, agent(), allowed_payee(), 10);
        assert_eq!(r.reason, Some(DenyReason::VaultPaused));
    }

    #[test]
    fn failed_token_transfer_restores_balance_and_headroom() {
        let mut c = setup_ft();
        assert!(spend_ft(&mut c, agent(), allowed_payee(), 10).allowed);
        assert_eq!(c.ft_balance(token()).0, 90);
        let p = c.get_ft_policy(agent(), token()).unwrap();

        testing_env!(ctx(accounts(5), NearToken::from_yoctonear(0), 0));
        c.on_ft_spend_complete(
            agent(),
            token(),
            allowed_payee(),
            U128(10),
            p.window_start_ns,
            Err(PromiseError::Failed),
        );
        assert_eq!(c.ft_balance(token()).0, 100, "tokens must be credited back");
        let after = c.get_ft_policy(agent(), token()).unwrap();
        assert_eq!(after.spent_in_window.0, 0, "headroom must be restored");
    }

    #[test]
    #[should_panic(expected = "no policy for that token")]
    fn agent_without_token_policy_is_reverted() {
        let mut c = setup_ft();
        testing_env!(ctx(attacker(), NearToken::from_yoctonear(0), 0));
        let _ = c.request_spend_ft(token(), allowed_payee(), U128(1), None);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn agent_cannot_opt_in_a_token() {
        let mut c = setup_ft();
        testing_env!(ctx(agent(), ONE_YOCTO, 0));
        c.add_token(other_token());
    }

    #[test]
    #[should_panic(expected = "token not accepted")]
    fn policy_requires_an_accepted_token() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.set_ft_policy(
            agent(),
            other_token(),
            U128(1),
            U128(1),
            vec![allowed_payee()],
        );
    }

    // ------------------------------------------------- owner token withdrawal

    /// The vault takes NEP-141 deposits, so the owner must be able to take
    /// them out again. Without this the only exit is an agent policy, which
    /// would strand every token the vault was ever sent.
    #[test]
    fn owner_can_withdraw_tokens() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let _ = c.withdraw_ft(token(), U128(40), owner());
        assert_eq!(
            c.ft_balance(token()).0,
            60,
            "held balance debited before transfer"
        );
    }

    /// Removing a token stops new deposits; it must not strand the balance.
    #[test]
    fn removed_token_balance_is_still_withdrawable() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        c.remove_token(token());
        assert!(!c.list_tokens().contains(&token()));
        let _ = c.withdraw_ft(token(), U128(100), owner());
        assert_eq!(c.ft_balance(token()).0, 0);
    }

    #[test]
    #[should_panic(expected = "amount exceeds held balance")]
    fn owner_cannot_withdraw_more_tokens_than_held() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let _ = c.withdraw_ft(token(), U128(101), owner());
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn agent_cannot_withdraw_tokens() {
        let mut c = setup_ft();
        testing_env!(ctx(agent(), ONE_YOCTO, 0));
        let _ = c.withdraw_ft(token(), U128(1), attacker());
    }

    #[test]
    fn failed_ft_withdrawal_restores_held_balance() {
        let mut c = setup_ft();
        testing_env!(ctx(owner(), ONE_YOCTO, 0));
        let _ = c.withdraw_ft(token(), U128(40), owner());
        assert_eq!(c.ft_balance(token()).0, 60);

        testing_env!(ctx(accounts(5), NearToken::from_yoctonear(0), 0));
        c.on_ft_withdraw_complete(token(), U128(40), Err(PromiseError::Failed));
        assert_eq!(
            c.ft_balance(token()).0,
            100,
            "a failed withdrawal must credit the balance back"
        );
    }

    #[test]
    fn status_reports_remaining_headroom() {
        let mut c = setup();
        spend(&mut c, agent(), allowed_payee(), 1, 0);
        testing_env!(ctx(owner(), NearToken::from_yoctonear(0), 0));
        let s = c.get_agent_status(agent()).unwrap();
        assert_eq!(s.remaining_today.0, NearToken::from_near(2).as_yoctonear());
    }
}
