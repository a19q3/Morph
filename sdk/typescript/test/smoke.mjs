import assert from "node:assert/strict";

import {
  createSignedPaymentPayload,
  deriveMorphAccountId,
  MorphAgentClient,
  verifySignedPaymentPayload,
} from "../dist/index.js";

const requirements = {
  requirement_id: `0x${"11".repeat(32)}`,
  payment_hash: `0x${"22".repeat(32)}`,
  payer: "0xc3884ddf5c0e66af9bd067147e948641917a9fd9df768dc299172e35a613a6e8",
  payee: `0x${"99".repeat(32)}`,
};
const payload = createSignedPaymentPayload(
  requirements,
  `0x${"07".repeat(32)}`,
);

assert.equal(
  payload.payer_pubkey_sec1,
  "0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
);
assert.equal(
  payload.payer,
  "0xc3884ddf5c0e66af9bd067147e948641917a9fd9df768dc299172e35a613a6e8",
);
assert.equal(
  deriveMorphAccountId(Buffer.from(payload.payer_pubkey_sec1.slice(2), "hex")),
  payload.payer,
);
assert.equal(verifySignedPaymentPayload(requirements, payload), true);
assert.equal(
  verifySignedPaymentPayload(
    { ...requirements, payment_hash: `0x${"23".repeat(32)}` },
    payload,
  ),
  false,
);

assert.throws(
  () => new MorphAgentClient("http://agent.example.com"),
  /must use HTTPS/,
);
assert.doesNotThrow(() => new MorphAgentClient("http://127.4.3.2:4617"));

const apiBearerToken = "m".repeat(32);
const originalFetch = globalThis.fetch;
globalThis.fetch = async (_url, init) => {
  assert.equal(init.headers.authorization, `Bearer ${apiBearerToken}`);
  return new Response(JSON.stringify({ network: "morph-ckb" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
try {
  const client = new MorphAgentClient("https://agent.example.com", { apiBearerToken });
  assert.deepEqual(await client.supported(), { network: "morph-ckb" });
} finally {
  globalThis.fetch = originalFetch;
}
