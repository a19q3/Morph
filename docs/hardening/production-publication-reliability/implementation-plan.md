# Implementation plan

1. Add typed CKB RPC access for fee estimates, confirmed fee statistics,
   tx-pool limits, transaction replacement fees, and devnet truncation.
2. Add a validated publication profile and pure fee/window calculations with
   overflow-safe unit tests.
3. Refactor signed-package publication so participant private keys are not part
   of the watchtower runtime contract.
4. Build carrier transactions repeatedly from immutable signed state evidence;
   select the initial rate from node observations and replace only within both
   sponsor and operator caps.
5. Persist JSONL attempt records before/after submissions. Include operator id,
   intent id, state number, fee/rate, tx hash, node observations, and outcome.
6. Add operator id and profile/attempt-log paths to config, reports, and health.
7. Add a devnet reliability smoke that covers a fee-floor rejection, successful
   RBF, delayed observation, chain truncation/recovery, and two operator scopes.
8. Add a challenge-window measurement command/report and fail-closed assessment.
9. Update runbooks/readiness status only where supported by generated evidence.
10. Run focused tests, `make ci`, and the real devnet rehearsal. Do not change CI/CD.

Rollback is operational: disable the new publication profile and return to the
legacy fixed-fee devnet path. No contract or signed-data rollback is needed
because this work does not change on-chain or package wire formats.
