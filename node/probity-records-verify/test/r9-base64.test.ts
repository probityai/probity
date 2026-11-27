// Round r9: every received standard base64 member is read through unb64 (probity_records.core.unb64), so a second
// spelling of the same bytes (nonzero padding bits, a missing or extra "=", a newline, the URL alphabet) is refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { unb64 } from "../src/verify.ts";

test("unb64 reads only the canonical padded spelling", () => {
  for (const text of ["AB==", "AA=", "AA", "AA===", "A\nA==", "_-==", "AB=\n", "", 7, null, undefined]) {
    if (text === "") continue; // the empty text is the empty bytes
    assert.throws(() => unb64(text as never), undefined, String(text));
  }
  assert.deepEqual(unb64("AA=="), Buffer.from([0]));
  assert.deepEqual(unb64(""), Buffer.alloc(0));
});

test("a 32-byte key spelled with stray low bits is not read", () => {
  const raw = Buffer.alloc(32, 7);
  const text = raw.toString("base64"); // 44 digits, one "=": the digit before it has two unused low bits
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const last = alphabet.indexOf(text[42]);
  const stray = text.slice(0, 42) + alphabet[last % 2 === 0 ? last | 1 : last & ~1] + "=";
  assert.notEqual(stray, text);
  assert.deepEqual(Buffer.from(stray, "base64"), raw); // Node's own decoder reads both spellings as the same bytes
  assert.throws(() => unb64(stray));
});
