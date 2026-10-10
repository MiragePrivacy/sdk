import { bytesToHex, hexToBytes, type Hex } from "viem";

export type Json = null | boolean | string | number | Json[] | { [key: string]: Json };
export const utf8 = (value: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(value);

/** Wire hex is lowercase, 0x-prefixed, with no alternative spellings. */
export function bytes(value: Hex, length?: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(value) ||
      (length !== undefined && value.length !== length * 2 + 2)) {
    throw new Error("Invalid workspace hex encoding");
  }
  return new Uint8Array(hexToBytes(value));
}

export function uint(value: number, bits = 53, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum ||
      value > (bits === 53 ? Number.MAX_SAFE_INTEGER : 2 ** bits - 1)) {
    throw new Error("Invalid workspace integer");
  }
  return value;
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export const randomId = (length: 16 | 32 = 16): Hex => bytesToHex(randomBytes(length));

function validString(value: string): void {
  // JSON permits lone surrogates; the UTF-8 wire protocol does not.
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("Invalid Unicode");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error("Invalid Unicode");
  }
}

/** Canonical JSON subset: safe integers; decimal strings for amounts; UTF-16 key order. */
export function canonicalJson(value: Json): string {
  const seen = new Set<object>();
  function visit(input: Json, depth: number): string {
    if (depth > 64) throw new Error("Workspace JSON is too deeply nested");
    if (input === null || typeof input === "boolean") return JSON.stringify(input);
    if (typeof input === "string") { validString(input); return JSON.stringify(input); }
    if (typeof input === "number") {
      if (!Number.isSafeInteger(input) || Object.is(input, -0)) throw new Error("Use decimal strings for non-integer or large values");
      return JSON.stringify(input);
    }
    if (typeof input !== "object" || seen.has(input)) throw new Error("Invalid workspace JSON");
    if (Object.getOwnPropertySymbols(input).length) throw new Error("Invalid workspace JSON");
    seen.add(input);
    let result: string;
    if (Array.isArray(input)) {
      const descriptors = Object.getOwnPropertyDescriptors(input);
      if (Object.keys(descriptors).length !== input.length + 1) throw new Error("Invalid workspace JSON array");
      const parts: string[] = [];
      for (let i = 0; i < input.length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new Error("Invalid workspace JSON array");
        parts.push(visit(descriptor.value, depth + 1));
      }
      result = `[${parts.join(",")}]`;
    } else {
      if (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
        throw new Error("Workspace JSON requires plain objects");
      const descriptors = Object.getOwnPropertyDescriptors(input);
      result = `{${Object.keys(descriptors).sort().map(key => {
        validString(key);
        const descriptor = descriptors[key];
        if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("Invalid workspace JSON");
        return `${JSON.stringify(key)}:${visit(descriptor.value, depth + 1)}`;
      }).join(",")}}`;
    }
    seen.delete(input);
    return result;
  }
  return visit(value, 0);
}

export function buffer(value: Uint8Array): ArrayBuffer { return new Uint8Array(value).buffer; }
