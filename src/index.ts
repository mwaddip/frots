/**
 * `frots` — pure-TypeScript port of FROST(secp256k1, SHA-256-TR).
 *
 * Step 4 public API (dealer flow): the high-level wrappers below let a
 * consumer drive the FROST signing pipeline end-to-end without touching
 * the lower-level primitives in src/sign.ts / src/keys.ts directly:
 *
 *     finalizeKeygen   →  build a per-party KeyPackage from a dealer-issued
 *                         SecretShare (runs VSS verification)
 *     signRound1       →  derive private nonces + public commitments
 *     signRound2       →  produce a per-signer SignatureShare
 *     signAggregate    →  combine SignatureShares into a 64-byte BIP340
 *                         signature, with bundled BIP340 verification
 *     verifySignature  →  standalone public-side BIP340 verification
 *
 * The DKG-flow wrappers (dkgRound1, dkgRound2, finalizeKeygen for DKG)
 * are pending — see PLAN.md Step 4 sub-step 6.
 *
 * The fixture-loading and RNG-replay exports below the line are test
 * helpers, kept on the public surface so external test harnesses (and
 * the project's own byte-equality tests) can reach them.
 */

// =============================================================================
// Step 4 — public signing API
// =============================================================================

export type {
  KeyPackage,
  PublicKeyPackage,
  SecretShare,
} from './keys.ts';

export { finalizeKeygen } from './keys.ts';

export type {
  Rng,
  Round1Output,
  SignatureShare,
  SigningCommitment,
  SigningNonces,
} from './sign.ts';

export {
  signAggregate,
  signRound1,
  signRound2,
  verifySignature,
} from './sign.ts';

// =============================================================================
// Fixture-loading and RNG replay (test helpers)
// =============================================================================

export type {
  BindingFactorEntry,
  Config,
  DealerFixture,
  DealerInputs,
  DkgData,
  DkgFixture,
  DkgInputs,
  DkgPart1Party,
  DkgPart2Party,
  DkgPart2Share,
  DkgPart3Party,
  FinalOutput,
  Fixture,
  FixtureName,
  LagrangeCoefficientEntry,
  ParticipantShare,
  RngCall,
  RoundOneOutput,
  RoundOneOutputs,
  RoundTwoOutput,
  RoundTwoOutputs,
  SigningIntermediates,
} from './fixture.ts';

export {
  ALL_FIXTURE_NAMES,
  loadDealerFixture,
  loadDkgFixture,
} from './fixture.ts';

export { FixtureRng, bytesToHex, hexToBytes } from './rng-replay.ts';
