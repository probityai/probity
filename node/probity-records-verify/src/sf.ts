// Structured Field Values for HTTP (RFC 8941), the subset the agent stamp reads: the TypeScript twin of
// agent_evidence_verify.structured_fields. Dictionaries, Items and Inner Lists; bare items of type String, Token,
// Integer, Decimal, Byte Sequence and Boolean; parameters. It is as strict as the Python reader: a repeated
// Dictionary key or parameter name is refused, numbers are read from the digits 0 to 9 only, and a Byte Sequence
// accepts missing padding and non-zero pad bits as RFC 8941 section 4.2.7 says a parser SHOULD.

export class SFError extends Error {}

/** A Token bare item, kept apart from Strings. */
export class Token { readonly value: string; constructor(value: string) { this.value = value; } }
/** A Decimal bare item, kept as its text: the stamp reads none, it only refuses one where an Integer belongs. */
export class Decimal { readonly text: string; constructor(text: string) { this.text = text; } }

export type BareItem = string | Token | number | Decimal | Buffer | boolean;
export interface Item { kind: "item"; value: BareItem; params: Map<string, BareItem> }
export interface InnerList { kind: "inner"; items: Item[]; params: Map<string, BareItem> }
export type Member = Item | InnerList;

const TOKEN_START = /[A-Za-z*]/;
const TOKEN_CHARS = /[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/;
const KEY_START = /[a-z*]/;
const KEY_CHARS = /[a-z0-9_\-.*]/;
const NUMBER = /-?([0-9]+)(\.[0-9]+)?/y;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

class Parser {
  i = 0;
  readonly s: string;
  constructor(s: string) { this.s = s; }
  peek(): string { return this.i < this.s.length ? this.s[this.i] : ""; }
  take(): string { const c = this.peek(); this.i += 1; return c; }
  done(): boolean { return this.i >= this.s.length; }
  fail(why: string): SFError { return new SFError(`${why} at offset ${this.i}`); }
  skipSp(): void { while (this.peek() === " ") this.i += 1; }
  skipOws(): void { while (this.peek() === " " || this.peek() === "\t") this.i += 1; }

  dictionary(): Map<string, Member> {
    const out = new Map<string, Member>();
    while (!this.done()) {
      const key = this.key();
      if (out.has(key)) throw this.fail("repeated dictionary key");
      if (this.peek() === "=") { this.take(); out.set(key, this.peek() === "(" ? this.innerList() : this.item()); }
      else out.set(key, { kind: "item", value: true, params: this.parameters() });
      this.skipOws();
      if (this.done()) return out;
      if (this.take() !== ",") throw this.fail("expected ','");
      this.skipOws();
      if (this.done()) throw this.fail("trailing comma");
    }
    return out;
  }

  innerList(): InnerList {
    if (this.take() !== "(") throw this.fail("expected '('");
    const items: Item[] = [];
    while (!this.done()) {
      this.skipSp();
      if (this.peek() === ")") { this.take(); return { kind: "inner", items, params: this.parameters() }; }
      items.push(this.item());
      if (this.peek() !== " " && this.peek() !== ")") throw this.fail("expected space or ')'");
    }
    throw this.fail("unterminated inner list");
  }

  item(): Item { const value = this.bareItem(); return { kind: "item", value, params: this.parameters() }; }

  parameters(): Map<string, BareItem> {
    const params = new Map<string, BareItem>();
    while (this.peek() === ";") {
      this.take();
      this.skipSp();
      const name = this.key();
      if (params.has(name)) throw this.fail("repeated parameter");
      if (this.peek() === "=") { this.take(); params.set(name, this.bareItem()); } else params.set(name, true);
    }
    return params;
  }

  key(): string {
    if (!KEY_START.test(this.peek() || "\0")) throw this.fail("expected a key");
    const start = this.i;
    while (!this.done() && KEY_CHARS.test(this.peek())) this.i += 1;
    return this.s.slice(start, this.i);
  }

  bareItem(): BareItem {
    const c = this.peek();
    if (c === "") throw this.fail("expected a bare item");
    if (c === "-" || (c >= "0" && c <= "9")) return this.number();
    if (c === '"') return this.string();
    if (TOKEN_START.test(c)) return this.token();
    if (c === ":") return this.bytes();
    if (c === "?") return this.boolean();
    throw this.fail("unexpected character");
  }

  number(): number | Decimal {
    NUMBER.lastIndex = this.i;
    const m = NUMBER.exec(this.s);
    if (m === null) throw this.fail("expected a number");
    this.i = NUMBER.lastIndex;
    if (m[2] === undefined) {
      if (m[1].length > 15) throw this.fail("integer too long");
      return Number(m[0]);
    }
    if (m[1].length > 12 || m[2].length - 1 > 3) throw this.fail("decimal too long");
    return new Decimal(m[0]);
  }

  string(): string {
    if (this.take() !== '"') throw this.fail("expected '\"'");
    let out = "";
    while (!this.done()) {
      const c = this.take();
      if (c === "\\") {
        const n = this.take();
        if (n !== '"' && n !== "\\") throw this.fail("bad escape in string");
        out += n;
      } else if (c === '"') return out;
      else if (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) > 0x7e) throw this.fail("non-ASCII or control character in string");
      else out += c;
    }
    throw this.fail("unterminated string");
  }

  token(): Token {
    const start = this.i;
    this.i += 1;
    while (!this.done() && TOKEN_CHARS.test(this.peek())) this.i += 1;
    return new Token(this.s.slice(start, this.i));
  }

  bytes(): Buffer {
    if (this.take() !== ":") throw this.fail("expected ':'");
    const end = this.s.indexOf(":", this.i);
    if (end < 0) throw this.fail("unterminated byte sequence");
    const raw = this.s.slice(this.i, end);
    this.i = end + 1;
    if (!B64.test(raw) || raw.length % 4 === 1) throw this.fail("bad base64");
    return Buffer.from(raw.replace(/=+$/, ""), "base64");
  }

  boolean(): boolean {
    if (this.take() !== "?") throw this.fail("expected '?'");
    const c = this.take();
    if (c === "1") return true;
    if (c === "0") return false;
    throw this.fail("bad boolean");
  }
}

/** A Dictionary field value, read strictly; SFError otherwise. */
export function parseDictionary(text: string): Map<string, Member> {
  const p = new Parser(text.replace(/^[ \t]+|[ \t]+$/g, ""));
  const out = p.dictionary();
  if (!p.done()) throw p.fail("trailing characters");
  return out;
}

/** The strict RFC 8941 serialisation of a String, Token or Integer bare item (all the stamp re-serialises). */
export function serializeBareItem(value: BareItem): string {
  if (typeof value === "boolean") return value ? "?1" : "?0";
  if (value instanceof Token) return value.value;
  if (typeof value === "number") return String(value);
  if (value instanceof Decimal) throw new SFError("the stamp re-serialises no Decimal");
  if (Buffer.isBuffer(value)) return `:${value.toString("base64")}:`;
  for (const c of value) if (c.charCodeAt(0) < 0x20 || c.charCodeAt(0) > 0x7e) throw new SFError("string contains a non-ASCII or control character");
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function serializeParams(params: Map<string, BareItem>): string {
  let out = "";
  for (const [name, value] of params) out += value === true ? `;${name}` : `;${name}=${serializeBareItem(value)}`;
  return out;
}

/** An Inner List with its parameters, as the RFC 9421 `@signature-params` line carries it. */
export function serializeInnerList(inner: InnerList): string {
  return `(${inner.items.map((i) => serializeBareItem(i.value) + serializeParams(i.params)).join(" ")})${serializeParams(inner.params)}`;
}
