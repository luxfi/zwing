import { describe, expect, it } from "vitest";

import { XWING_SHARED_SIZE, combineXWing } from "./zwing.js";

// Cross-language KAT shared with Go (../kat_test.go), Rust
// (~/work/zap/zap/src/zwing.rs), and Python (../py/test_zwing.py). If
// this hex changes, Z-Wing has diverged across implementations.
const KAT_HEX =
  "72df2088314a73de80c21d9593f13fcd5629c800c70b1507f0dd918fde5fe4ed";

function repeat(byte: number, len: number): Uint8Array {
  return new Uint8Array(len).fill(byte);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("X-Wing combiner KAT (cross-language)", () => {
  it("matches the canonical KAT for repeated 0x01..0x04 inputs", () => {
    const got = combineXWing(
      repeat(0x01, 32),
      repeat(0x02, 32),
      repeat(0x03, 32),
      repeat(0x04, 32),
    );
    expect(got.length).toBe(XWING_SHARED_SIZE);
    expect(toHex(got)).toBe(KAT_HEX);
  });

  it("is deterministic", () => {
    const a = combineXWing(
      repeat(0x01, 32),
      repeat(0x02, 32),
      repeat(0x03, 32),
      repeat(0x04, 32),
    );
    const b = combineXWing(
      repeat(0x01, 32),
      repeat(0x02, 32),
      repeat(0x03, 32),
      repeat(0x04, 32),
    );
    expect(toHex(a)).toBe(toHex(b));
  });

  it("changes on any input flip", () => {
    const base = combineXWing(
      repeat(0x01, 32),
      repeat(0x02, 32),
      repeat(0x03, 32),
      repeat(0x04, 32),
    );
    const flipped = repeat(0x01, 32);
    flipped[0] ^= 0x01;
    const mutated = combineXWing(
      flipped,
      repeat(0x02, 32),
      repeat(0x03, 32),
      repeat(0x04, 32),
    );
    expect(toHex(base)).not.toBe(toHex(mutated));
  });

  it("rejects wrong-size inputs", () => {
    expect(() =>
      combineXWing(
        repeat(0x00, 31),
        repeat(0x00, 32),
        repeat(0x00, 32),
        repeat(0x00, 32),
      ),
    ).toThrow();
  });
});
