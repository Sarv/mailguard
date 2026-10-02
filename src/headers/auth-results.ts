import { rollUpAuthStatus, unknownAuthStatus, type AuthStatus } from '../verdict.js';

/**
 * Pull the mail-authentication headers out of a raw header block.
 *
 * `Authentication-Results` (RFC 8601) is where the RECEIVING server records
 * its SPF / DKIM / DMARC verdicts; `ARC-Authentication-Results` carries them
 * across forwarders, and `Received-SPF` is the older SPF-only form. Together
 * they are the only evidence of authentication a client ever sees without
 * doing the DNS work itself.
 *
 * Every occurrence is kept, in header order (topmost first): a message that
 * crossed several hops has one line per hop, and deciding which of them to
 * believe is {@link parseAuthenticationHeaders}' job, which needs to see them
 * all and where each one sat. Folded continuation lines are unfolded into one
 * line each.
 *
 * Note what this is NOT: it is not verification. It is a report of what some
 * other machine concluded, and it is only worth what that machine is worth —
 * trustworthy for the hop that your own server wrote, decorative for the ones
 * a forwarder passed along. Actually verifying SPF/DKIM/DMARC needs the
 * network and the original message; that is a separate, opt-in stage.
 *
 * @returns the matching headers as `name: value` lines, or undefined when the
 *   block has none — so a caller stores NULL ("no verdict recorded") rather
 *   than an empty string that would later parse as a verdict of "unknown".
 */
export function extractAuthHeaderBlock(
  rawHeaders: string | Buffer | undefined | null,
): string | undefined {
  if (!rawHeaders) return undefined;
  const text = typeof rawHeaders === 'string' ? rawHeaders : rawHeaders.toString('utf8');
  // Header name anchored at the start of the block or after a newline; value
  // runs until the next UNFOLDED newline (one not followed by whitespace).
  //
  // No `[ \t]*` before the value group, deliberately. It reads as "skip the
  // space after the colon", but the value group accepts those same spaces, so
  // the two can exchange them — polynomial backtracking on a header block an
  // attacker writes. The leading space is removed by the `.trim()` below,
  // which had to happen anyway for the folded case.
  const pattern =
    /(?:^|\r?\n)((?:arc-)?authentication-results|received-spf):([\s\S]*?)(?=\r?\n(?![ \t])|$)/gi;
  const lines: string[] = [];
  for (const match of text.matchAll(pattern)) {
    // Group 2 is not optional in the pattern, so a match always carries it;
    // the index type is `| undefined` only because of `noUncheckedIndexedAccess`.
    const value = (match[2] as string).replace(/\r?\n[ \t]+/g, ' ').trim();
    if (value) lines.push(`${match[1]}: ${value}`);
  }
  return lines.length ? lines.join('\n') : undefined;
}

/**
 * One `method=result` statement from an `Authentication-Results` header
 * (RFC 8601 §2.2), e.g. `dkim=pass header.d=example.com`.
 */
export interface AuthResult {
  /** The method, lowercased and without its `/version`: `spf`, `dkim`, `dmarc`, `iprev`… */
  method: string;
  /** The result keyword, lowercased: `pass`, `fail`, `softfail`, `temperror`… */
  result: string;
  /**
   * `reason` and every `ptype.property` (`smtp.mailfrom`, `header.from`,
   * `header.d`…), keys lowercased, values unquoted. The first of a repeated
   * key wins. A prototype-less object, so a property named `__proto__` or
   * `constructor` is a plain key and nothing more.
   */
  properties: Record<string, string>;
}

/** One `Authentication-Results` header value, parsed. */
export interface AuthResultsHeader {
  /**
   * Who wrote it: the authserv-id (RFC 8601 §2.5), lowercased. `null` when
   * the header names nobody — Microsoft 365 writes its results straight after
   * the colon — which is a header no configured authserv-id can match.
   */
  authservId: string | null;
  /** Every statement in it, in order. Empty for the `none` form. */
  results: AuthResult[];
}

/** Which `Authentication-Results` to believe. */
export interface AuthResultsOptions {
  /**
   * The authserv-id your own receiving MTA stamps at the start of the
   * `Authentication-Results` it writes — usually its hostname, e.g.
   * `mx.google.com`. Given one (or several), ONLY headers carrying it are
   * believed, wherever in the trace they sit. Absent, `null` or all blank,
   * only the TOPMOST `Authentication-Results` is.
   */
  authserv?: string | readonly string[] | null;
}

/*
 * Why a hand-written tokenizer, when the rest of this package reaches for a
 * library: no maintained RFC 8601 parser clears the bar. `mailauth` has one,
 * but as an internal module (`lib/parse-dkim-headers.js`) outside its public
 * API; it keeps only the LAST result of each method, so `dmarc=fail; dmarc=pass`
 * reads as a pass, and it would drag `mailauth`'s whole dependency tree into
 * the zero-dependency `/headers` entry. The other candidate on npm was three
 * months old with a regex tokenizer. The grammar needed is small — `;`-separated
 * statements, `(comments)` that nest, `"quoted strings"`, `key=value` pairs —
 * and written as the loops below it cannot backtrack on a header a sender wrote.
 */

function isSpace(c: string | undefined): boolean {
  return c === ' ' || c === '\t' || c === '\r' || c === '\n';
}

function skipSpace(text: string, from: number): number {
  let i = from;
  while (i < text.length && isSpace(text[i])) i += 1;
  return i;
}

/**
 * The value's `;`-separated parts, with every comment replaced by a space and
 * every quoted string kept as written.
 *
 * Comments go first because they are free text a server fills with whatever it
 * likes — Gmail writes `(google.com: domain of … designates … as permitted
 * sender)` — and a `;` or an `=` inside one is not a separator. Neither is one
 * inside a quoted string, which a property value may be.
 */
function authResultsParts(value: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  let escaped = false;
  let depth = 0;
  for (const c of value) {
    if (escaped) {
      // A quoted-pair. Kept inside a quoted string (unquoting is the reader's
      // job), dropped with the rest of a comment.
      escaped = false;
      if (depth === 0) current += c;
    } else if (quoted) {
      current += c;
      if (c === '\\') escaped = true;
      else if (c === '"') quoted = false;
    } else if (depth > 0) {
      if (c === '\\') escaped = true;
      else if (c === '(') depth += 1;
      else if (c === ')') {
        depth -= 1;
        if (depth === 0) current += ' ';
      }
    } else if (c === '(') {
      depth = 1;
    } else if (c === ';') {
      parts.push(current);
      current = '';
    } else {
      if (c === '"') quoted = true;
      current += c;
    }
  }
  parts.push(current);
  return parts;
}

/**
 * One value starting at `from`: everything up to the next whitespace, with any
 * quoted stretch unquoted (so `"john smith"@example.com` is one value).
 */
function readValue(text: string, from: number): { value: string; next: number } {
  let value = '';
  let quoted = false;
  let i = from;
  for (; i < text.length; i += 1) {
    const c = text[i] as string;
    if (quoted) {
      if (c === '\\' && i + 1 < text.length) {
        i += 1;
        value += text[i] as string;
      } else if (c === '"') quoted = false;
      else value += c;
    } else if (isSpace(c)) break;
    else if (c === '"') quoted = true;
    else value += c;
  }
  return { value, next: i };
}

/** Advance past a run of characters that ends at whitespace or one of `stops`. */
function readWord(text: string, from: number, stops: string): number {
  let i = from;
  while (i < text.length && !isSpace(text[i]) && !stops.includes(text[i] as string)) i += 1;
  return i;
}

/**
 * One statement: `method[/version] = result [reason=…] [ptype.property=value …]`.
 * Null for anything that is not one — the `none` form, or free text.
 */
function parseStatement(part: string): AuthResult | null {
  let i = skipSpace(part, 0);
  const methodEnd = readWord(part, i, '=/');
  const method = part.slice(i, methodEnd).toLowerCase();
  i = skipSpace(part, methodEnd);
  if (part[i] === '/') {
    // The method version (`dkim/1`), which says nothing about the verdict.
    i = skipSpace(part, readWord(part, skipSpace(part, i + 1), '='));
  }
  if (!method || part[i] !== '=') return null;
  i = skipSpace(part, i + 1);
  const resultEnd = readWord(part, i, '');
  const result = part.slice(i, resultEnd).toLowerCase();
  if (!result) return null;

  const properties = Object.create(null) as Record<string, string>;
  i = resultEnd;
  while (i < part.length) {
    i = skipSpace(part, i);
    const keyEnd = readWord(part, i, '=');
    const key = part.slice(i, keyEnd).toLowerCase();
    i = skipSpace(part, keyEnd);
    // A word that is not `key=value` is skipped, not fatal: servers do write
    // stray words (`action=none` is fine, `compauth=pass reason=100` is fine,
    // but versions of both have shipped with bare tokens in between).
    if (part[i] !== '=') continue;
    const { value, next } = readValue(part, skipSpace(part, i + 1));
    i = next;
    if (key && !(key in properties)) properties[key] = value;
  }
  return { method, result, properties };
}

/**
 * Parse one `Authentication-Results` value — the text after the colon.
 *
 * RFC 8601 §2.2: an authserv-id (a token or quoted string, optionally followed
 * by a version number), then `;`-separated statements. A value whose first part
 * is already a statement has no authserv-id: that is Microsoft 365's format,
 * and it parses, with `authservId: null`.
 */
export function parseAuthResultsHeader(value: string): AuthResultsHeader {
  const [head, ...rest] = authResultsParts(value) as [string, ...string[]];
  const results: AuthResult[] = [];
  let authservId: string | null = null;
  const headStatement = parseStatement(head);
  if (headStatement) {
    results.push(headStatement);
  } else {
    authservId = readValue(head, skipSpace(head, 0)).value.toLowerCase() || null;
  }
  for (const part of rest) {
    const statement = parseStatement(part);
    if (statement) results.push(statement);
  }
  return { authservId, results };
}

/** The configured authserv-ids, trimmed and lowercased, blanks dropped. */
export function normalizeAuthserv(authserv: AuthResultsOptions['authserv']): string[] {
  const wanted = typeof authserv === 'string' ? [authserv] : (authserv ?? []);
  return wanted.map((id) => id.trim().toLowerCase()).filter(Boolean);
}

/**
 * The `Authentication-Results` headers in a block that are worth believing,
 * parsed, topmost first.
 *
 * Only `Authentication-Results`. `ARC-Authentication-Results` is a copy some
 * hop sealed for the NEXT hop to consider, and `Received-SPF` names no author
 * at all; either is exactly as easy to type into a message as a forged
 * `Authentication-Results`, and neither is ever the receiving server's verdict
 * on THIS delivery.
 *
 * Of those, with an authserv-id configured: every header that carries it. RFC
 * 8601 §5 obliges a border MTA to delete any header claiming its own
 * authserv-id that it did not write, so on a conforming server those are all
 * its own — several are normal, one per filter (SPF, DKIM, DMARC) on some
 * setups. On a server that does not strip them, a forged one can get in, which
 * is why their verdicts are combined so that a failure is never outvoted (see
 * {@link parseAuthenticationHeaders}).
 *
 * Without one: the topmost header only. Every hop PREPENDS, so the topmost is
 * the last one written — by the receiving side on every mainstream server —
 * and a verdict a sender typed into the message sits below it. That is a
 * convention, not a guarantee (a server that appends, or writes none at all,
 * leaves a forged header on top), which is why the authserv-id is worth
 * configuring when it is known.
 */
export function trustedAuthResults(
  block: string | null | undefined,
  options: AuthResultsOptions = {},
): AuthResultsHeader[] {
  if (!block) return [];
  const ids = normalizeAuthserv(options.authserv);
  const trusted: AuthResultsHeader[] = [];
  // Unfolded here as well as in the extractor: a caller handing over a raw
  // block must not have a folded header read as two, or its continuation line
  // (which starts with whitespace, not a name) silently dropped.
  for (const line of block.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon < 0 || line.slice(0, colon).trim().toLowerCase() !== 'authentication-results') {
      continue;
    }
    const header = parseAuthResultsHeader(line.slice(colon + 1));
    if (ids.length === 0) return [header];
    if (header.authservId !== null && ids.includes(header.authservId)) trusted.push(header);
  }
  return trusted;
}

type AuthMethod = 'spf' | 'dkim' | 'dmarc';
type AuthValue = AuthStatus['spf'];

/**
 * The results each `AuthStatus` field can hold, per method. Anything else a
 * server writes (`temperror`, `permerror`, `policy`, DKIM's `neutral`,
 * Microsoft's `bestguesspass`) is recorded but not one of these, and reads as
 * `unknown`. `hardfail` is RFC 5451's deprecated spelling of SPF `fail`.
 */
const RESULT_VALUES: Record<AuthMethod, ReadonlyMap<string, AuthValue>> = {
  spf: new Map<string, AuthValue>([
    ['pass', 'pass'],
    ['fail', 'fail'],
    ['hardfail', 'fail'],
    ['softfail', 'softfail'],
    ['neutral', 'neutral'],
    ['none', 'none'],
  ]),
  dkim: new Map<string, AuthValue>([
    ['pass', 'pass'],
    ['fail', 'fail'],
    ['none', 'none'],
  ]),
  dmarc: new Map<string, AuthValue>([
    ['pass', 'pass'],
    ['fail', 'fail'],
    ['none', 'none'],
  ]),
};

/** Worst first: a pass must be unanimous, and one failure is never outvoted. */
const SEVERITY: readonly AuthValue[] = ['fail', 'softfail', 'neutral', 'unknown', 'none', 'pass'];

function worst(values: readonly AuthValue[]): AuthValue {
  return values.reduce((a, b) => (SEVERITY.indexOf(b) < SEVERITY.indexOf(a) ? b : a));
}

/** An SPF result about the HELO identity only (RFC 7208 §2.3). */
function heloOnly(result: AuthResult): boolean {
  return 'smtp.helo' in result.properties && !('smtp.mailfrom' in result.properties);
}

/**
 * One method's verdict across the trusted headers.
 *
 * Across headers, the worst report wins: two headers that disagree are either
 * two filters on the same server, where a failure is the finding that matters,
 * or a real header and a forged one, where the forgery is always the pass.
 *
 * Within ONE header the same holds, with one exception: several DKIM results
 * are several signatures, and one valid signature is a valid signature
 * (RFC 6376 §6.1) — a mailing list that breaks the author's signature and adds
 * its own passes. And an SPF check of the HELO name gives way to the check of
 * the envelope sender when the server ran both, since the envelope sender is
 * the identity DMARC aligns on.
 */
function methodVerdict(headers: readonly AuthResultsHeader[], method: AuthMethod): AuthValue {
  let perHeader = headers.map((header) => header.results.filter((r) => r.method === method));
  if (method === 'spf' && perHeader.some((rs) => rs.some((r) => 'smtp.mailfrom' in r.properties))) {
    perHeader = perHeader.map((rs) => rs.filter((r) => !heloOnly(r)));
  }
  const reports = perHeader
    .filter((rs) => rs.length > 0)
    .map((rs) => {
      const values = rs.map((r) => RESULT_VALUES[method].get(r.result) ?? 'unknown');
      return method === 'dkim' && values.includes('pass') ? 'pass' : worst(values);
    });
  return reports.length > 0 ? worst(reports) : 'unknown';
}

/** The trusted headers' verdicts combined into the stored shape. */
export function authStatusFromResults(headers: readonly AuthResultsHeader[]): AuthStatus {
  const status = unknownAuthStatus();
  status.spf = methodVerdict(headers, 'spf');
  // The worst of values drawn from a method's own table is one of them, so
  // these narrowings hold; the table types are what guarantee it.
  status.dkim = methodVerdict(headers, 'dkim') as AuthStatus['dkim'];
  status.dmarc = methodVerdict(headers, 'dmarc') as AuthStatus['dmarc'];
  status.overall = rollUpAuthStatus(status);
  return status;
}

/**
 * The SPF / DKIM / DMARC verdict of the headers worth believing — see
 * {@link trustedAuthResults} for which those are, and pass `authserv` when you
 * know your receiving server's authserv-id.
 *
 * This is where a forged `Authentication-Results: …; dmarc=pass` is meant to
 * die. Before 0.4.3 it did not: every authentication header in the block was
 * scanned for substrings and `dmarc=pass` was looked for before `dmarc=fail`,
 * so a sender who typed a pass into their own message was believed over the
 * receiving server's failure.
 *
 * Only lines NAMED `Authentication-Results` are read, so handing this a whole
 * raw header block is safe — an `X-Whatever: dmarc=pass` is not in scope — but
 * the usual input is {@link extractAuthHeaderBlock}'s output.
 */
export function parseAuthenticationHeaders(
  block: string | null | undefined,
  options: AuthResultsOptions = {},
): AuthStatus {
  return authStatusFromResults(trustedAuthResults(block, options));
}
