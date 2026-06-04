
---

## Update — ResetMemory (0x1A) auth gating (static analysis, 2026-06-04)

### SOLID (read in code)
- `ResetMemory.java`: `ResetMemory(true)` → `[0x1A,0x01,0x01]`; `ResetMemory(false)` → `[0x1A,0x00]`.
- The operation queue (`execSingle`, `m.java`) does NOT enforce auth-first at the
  code level → an operation can be queued on a fresh link.
- State machine has `IN_FACTORY_RESET` state + a `CLEAR_AUTH` operation
  (`b0.java`, `RingStateMachine$Transition.java`).
- No "charger required" string constraint found in the operations package.

### DOUBTFUL — DO NOT ACT ON (likely agent over-interpretation)
The agent proposed a "takeover recipe": send SetAuthKey(our key) on a claimed ring
→ ring replies 0x00 → Authenticate fails 0x02 → machine clears auth & resets.
**This is logically suspect**: if SetAuthKey succeeded (0x00) on an already-claimed
ring, there'd be no security at all. The agent likely conflated APP behavior
(what the phone sends) with FIRMWARE behavior (what the ring actually permits).

### The honest truth
Decompiled app code tells us what the APP SENDS, not what the ring's FIRMWARE
ACCEPTS. The acceptance conditions for SetAuthKey / ResetMemory on a claimed ring
can ONLY be determined by talking to the real ring (or capturing a real onboarding).
Treat all "takeover sequence" claims as HYPOTHESES to test empirically, low confidence.

### What we'll actually test (safe, ordered)
1. Free the ring from the iPhone (BT off) → confirm it advertises → Mac sees it.
2. Connect (read-only) → dump GATT → confirm service 98ed0001 + state.
3. Only THEN, carefully, probe what the ring accepts (GetAuthNonce/Authenticate
   responses tell us its state: 0x02 factory-reset vs 0x03 claimed).
