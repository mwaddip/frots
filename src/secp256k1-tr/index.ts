/**
 * `frots/secp256k1-tr` — FROST(secp256k1, SHA-256-TR) public API.
 *
 * Pure-TypeScript port of the Zcash Foundation's audited `frost-secp256k1-tr`
 * Rust crate, validated byte-for-byte against the reference implementation.
 *
 * Two key-generation flows:
 *
 * **Dealer flow** (trusted dealer distributes shares):
 *     finalizeKeygen → signRound1 → signRound2 → signAggregate
 *
 * **DKG flow** (distributed, no dealer):
 *     dkgRound1 → dkgRound2 → dkgFinalize → signRound1 → signRound2 → signAggregate
 */

// Key generation — dealer flow
export type { KeyPackage, PublicKeyPackage, SecretShare } from './keys.ts';
export { finalizeKeygen } from './keys.ts';

// Key generation — DKG flow
export type {
  Round1Package,
  Round1SecretPackage,
  Round2Package,
  Round2SecretPackage,
} from './dkg.ts';

export {
  dkgFinalize,
  dkgRound1,
  dkgRound2,
  dkgVerifyProofOfKnowledge,
} from './dkg.ts';

// Signing (both flows)
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
