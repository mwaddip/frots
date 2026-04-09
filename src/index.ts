/**
 * `frots` — pure-TypeScript port of FROST(secp256k1, SHA-256-TR).
 *
 * Public surface for Step 2 (skeleton). Step 3 will add the primitive
 * implementations (hash-to-scalar, polynomial generation, signing nonces,
 * etc.) bottom-up. Step 4 will compose them into the public DKG / sign /
 * aggregate API. See `PLAN.md`.
 */

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
