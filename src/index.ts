/**
 * `frots` — pure-TypeScript port of FROST (RFC 9591).
 *
 * Top-level barrel that re-exports the secp256k1-tr ciphersuite as the
 * default, plus test helpers for internal byte-equality tests.
 *
 * Consumers should import from 'frots' or 'frots/secp256k1-tr'.
 */

// =============================================================================
// Public API — re-exported from the secp256k1-tr ciphersuite
// =============================================================================

export * from './secp256k1-tr/index.ts';

// =============================================================================
// Test helpers (fixture loading, RNG replay, hex utils)
// These are NOT part of the published package API — they exist for the
// project's own byte-equality test suite and reference fixture data on
// disk that does not ship with the npm package.
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
