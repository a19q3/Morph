import assert from "node:assert/strict";

import {
  createSignedPaymentPayload,
  deriveMorphAccountId,
  MorphAgentClient,
  MorphHubClient,
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
assert.doesNotThrow(() => new MorphHubClient("http://127.0.0.1:4617"));
assert.throws(
  () => new MorphHubClient("http://hub.example.com"),
  /must use HTTPS/,
);

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

const maxU64 = "18446744073709551615";
const conditionalPackage = {
  schema: "morph.conditional_batch_package",
  channel_id: "0x01",
  funding_context_id: "0x02",
  state_number: maxU64,
  batch_id: "0x03",
  application_context_commitment: "0x04",
  participants: [
    { settlement_lock_hash: "0x05", settled_capacity: maxU64 },
    { settlement_lock_hash: "0x06", settled_capacity: "0" },
  ],
  transfers: [{
    transfer_id: "0x07",
    payer_lock_hash: "0x05",
    hash_algorithm: "sha256",
    payment_hash: "0x08",
    amount: maxU64,
    refund_after_block: maxU64,
  }],
  resolutions: [{ kind: "refund", transfer_id: "0x07" }],
  input_since: maxU64,
  descriptor_hex: "0x09",
  descriptor_commitment: "0x0a",
  resolution_witness_hex: "0x0b",
  resolved_capacities: [maxU64, "0"],
  signed_state_header_hex: "0x0c",
  signed_state_witness_hex: "0x0d",
};
let postedConditionalBody;
globalThis.fetch = async (_url, init) => {
  postedConditionalBody = init.body;
  return new Response(JSON.stringify({ imported: true }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
try {
  const client = new MorphHubClient("https://hub.example.com");
  assert.deepEqual(await client.importConditionalBatch(conditionalPackage), { imported: true });
  assert.equal(JSON.parse(postedConditionalBody).state_number, maxU64);
  assert.throws(
    () => client.importConditionalBatch({ ...conditionalPackage, input_since: "01" }),
    /canonical unsigned u64/,
  );
  assert.throws(
    () => client.importConditionalBatch({ ...conditionalPackage, state_number: `${maxU64}0` }),
    /canonical unsigned u64/,
  );
} finally {
  globalThis.fetch = originalFetch;
}

globalThis.fetch = async () => new Response(
  new Uint8Array(2 * 1024 * 1024 + 1),
  { status: 200 },
);
try {
  const client = new MorphAgentClient("https://agent.example.com");
  await assert.rejects(
    client.supported(),
    /response exceeds the maximum size/,
  );
} finally {
  globalThis.fetch = originalFetch;
}
