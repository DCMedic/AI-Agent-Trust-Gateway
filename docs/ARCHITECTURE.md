# Architecture

## Design principle

The gateway treats model output as a **proposal**, not an instruction with inherent authority.

The execution path is deliberately decomposed:

1. authenticate or identify the proposing agent
2. parse a structured `ActionProposal`
3. evaluate explicit policy
4. validate arguments against constraints
5. classify risk
6. require proposal-bound approval when policy demands it
7. invoke only a registered constrained adapter
8. independently verify resulting state
9. persist tamper-evident audit events

No step relies on the model's confidence or natural-language justification as an authorization primitive.

## Components

### Action proposal model
A typed request containing agent identity, tool, action, arguments, declared purpose, proposal ID, and timestamp. A canonical SHA-256 digest binds approvals to the exact proposal.

### Policy decision point
`PolicyEngine` loads a declarative JSON policy. Unknown identities and capabilities are denied by default. Rules may constrain argument names, required values, lengths, and enumerated values.

### Approval control
High-risk actions return `require_approval`. Approval includes the exact proposal digest, human approver identity, and expiration time. A modified or expired proposal fails closed.

### Tool registry
Adapters are explicitly registered. The reference implementation does not expose shell execution, arbitrary HTTP requests, filesystem traversal, or dynamic import as agent tools.

### Verification layer
Tool invocation and outcome verification are separate. A production adapter should verify using evidence that is meaningfully independent of the command path whenever possible.

### Audit journal
Security-relevant transitions are written as JSONL records linked by SHA-256 hashes. This is tamper-evident, not tamper-proof; production deployment should write to separately protected append-only storage.

## Security state machine

```text
PROPOSED
   |
   v
POLICY_EVALUATED ----deny----> DENIED
   |
   +----allow-----------------> EXECUTING
   |
   +----approval required-----> PENDING_APPROVAL
                                  |
                        invalid/expired -> DENIED
                                  |
                                valid
                                  v
                              EXECUTING
                                  |
                         adapter success/fail
                         /                \
                    FAILED            VERIFYING
                                         |
                              verified / not verified
                               /                 \
                         COMPLETED      VERIFICATION_FAILED
```

## Why approval is digest-bound

A generic approval such as "allow the agent to restart a service" is vulnerable to ambiguity and replay. AATG instead approves a digest of the entire proposal. If the agent changes the service, argument set, stated purpose, ID, or timestamp, the digest changes and the approval no longer matches.

## Production evolution

A hardened implementation should replace demonstration components with:

- workload identity and signed agent credentials
- external policy decision points or formally versioned policy bundles
- secret-scoped capability tokens
- durable approval workflows with strong human identity
- nonce/replay protection and single-use approvals
- remote immutable audit storage and signatures
- process/container isolation for adapters
- outbound network allowlists
- budgets, rate limits, and transactional compensating actions
- independent state/evidence providers
- policy and adversarial-evaluation telemetry
