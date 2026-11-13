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
use near_sdk::store::IterableMap;
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};

/// Length of the rolling spend window: 24 hours in nanoseconds.
const DAY_NS: u64 = 86_400_000_000_000;
/// Maximum recipients per agent. Bounds storage and gas on policy writes.
const MAX_ALLOWLIST: usize = 20;
/// Maximum registered agents. Bounds `list_agents` gas.
const MAX_AGENTS: u32 = 50;
/// Maximum memo length in bytes.
const MAX_MEMO: usize = 256;
/// Gas reserved for the spend callback.
const CALLBACK_GAS: Gas = Gas::from_tgas(5);
/// Liquid NEAR always retained above storage staking, so the vault can never
/// transfer itself into a state where it cannot pay for its own storage.
const SAFETY_BUFFER: NearToken = NearToken::from_millinear(50);

#[derive(BorshStorageKey)]
#[near(serializers = [borsh])]
enum StorageKey {
    Agents,
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

/// Live view of an agent, including remaining headroom.
#[near(serializers = [json])]
pub struct AgentStatus {
    pub agent_id: AccountId,
    pub policy: AgentPolicy,
    pub remaining_today: U128,
    pub window_resets_in_ns: U64,
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
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    paused: bool,
    agents: IterableMap<AccountId, AgentPolicy>,
    total_spent: U128,
    total_denied: u64,
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

            // Roll the 24h window forward before evaluating the daily cap.
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
            } else if !policy.allowlist.contains(&recipient) {
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
                    // Debit BEFORE scheduling the transfer. A concurrent
                    // request during the pending callback sees the reduced
                    // headroom and cannot double-spend.
                    policy.spent_in_window =
                        U128(policy.spent_in_window.0.saturating_add(requested));
                    policy.lifetime_spent = U128(policy.lifetime_spent.0.saturating_add(requested));
                    policy.allowed_count = policy.allowed_count.saturating_add(1);
                    Ok(policy.window_start_ns)
                }
            }
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
        Some(AgentStatus {
            agent_id,
            remaining_today: U128(policy.daily_cap.0.saturating_sub(spent)),
            window_resets_in_ns: U64(resets_in),
            policy,
        })
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

    #[test]
    fn status_reports_remaining_headroom() {
        let mut c = setup();
        spend(&mut c, agent(), allowed_payee(), 1, 0);
        testing_env!(ctx(owner(), NearToken::from_yoctonear(0), 0));
        let s = c.get_agent_status(agent()).unwrap();
        assert_eq!(s.remaining_today.0, NearToken::from_near(2).as_yoctonear());
    }
}
