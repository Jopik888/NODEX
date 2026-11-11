const CID_V0_PATTERN = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
const CID_V1_BASE32_PATTERN = /^b[a-z2-7]{20,120}$/;

/**
 * Checks the supported textual CID shapes before forwarding a request to Kubo.
 * This is intentionally a shape check, not a replacement for Kubo's multihash validation.
 */
export function isPlausibleIpfsCid(value) {
  return typeof value === 'string' &&
    (CID_V0_PATTERN.test(value) || CID_V1_BASE32_PATTERN.test(value));
}
