import { isPlausibleIpfsCid } from './ipfs-cid.js';

export function parseKuboAddResponse(rawText) {
  if (typeof rawText !== 'string') {
    throw new TypeError('Kubo upload response must be text.');
  }

  const rows = rawText.trim().split(/\r?\n/).filter(Boolean);
  let result;
  try {
    result = rows.length ? JSON.parse(rows.at(-1)) : null;
  } catch {
    throw new Error('Kubo upload response is not valid newline-delimited JSON.');
  }

  if (!result || typeof result.Hash !== 'string' || !isPlausibleIpfsCid(result.Hash)) {
    throw new Error('Kubo upload response does not contain a valid content identifier.');
  }

  return { Hash: result.Hash, Size: String(result.Size || '') };
}
