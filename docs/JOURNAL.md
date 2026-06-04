# Investigation journal

Dated notes throughout the RE. Hypotheses, tests, results, dead-ends.

---

## 2026-06-04 — Phase 0: Recon

- Project initialized (empty). Setup: Mac + iPhone + Android. Ring = **Oura Ring 4**.
- Research: the Ring 4 BLE protocol is already publicly RE'd (`open_ring`,
  `ringverse`). See `docs/PROTOCOL.md`.
- **Decision**: current goal = pair with the ring **without the Oura app** (from
  scratch, in Swift, clean-room). Long-term goal (standalone app after onboarding
  once) documented for later.
- **Wall identified**: 16-byte `auth_key` handshake, code `0x03` if not onboarded.
- **Next pivot**: investigate the origin of the `auth_key` (ring-derived vs server
  randomness) = go/no-go. See `docs/STRATEGY.md`.

### Don't forget
- ⚠️ DO NOT reset the ring before sniffing the official onboarding.

### Open questions
- Is the `auth_key` derivable from a secret present in the ring?
- Is the BLE bond (problem A) acceptable to a reset ring from an arbitrary central?
- Is the `98ed00xx` service actually exposed by our ring (to confirm via GATT dump)?
