/**
 * The IP address that handed this message to the recipient's mail system —
 * the one input every reputation check (DNS blocklists, reverse DNS) needs.
 *
 * Recorded at scan time even when no reputation stage is enabled, because it
 * cannot be recovered later: by the time anyone wants to ask a blocklist about
 * a message, the headers it came from may be long gone.
 *
 * Two sources, in order of trust:
 *
 *   1. The receiving server's own `Authentication-Results`. This is the SAME
 *      header the authentication verdict is read from, chosen by the same rule
 *      (`trustedAuthResults`): with an authserv-id configured, the headers
 *      that carry it; without one, the topmost. The server names the client it
 *      checked in its SPF and iprev results, either as `smtp.remote-ip=` /
 *      `policy.iprev=` (RFC 8601 §2.7.3; Exim, Fastmail) or inside the SPF
 *      comment (Gmail's "designates x as permitted sender", Microsoft's
 *      "sender IP is x"). This is authoritative: it IS the connecting client
 *      as the server saw it.
 *   2. The `Received:` trace, top down. The first hop written with a `from`
 *      clause naming a PUBLIC address is the last external handoff. This is
 *      the fallback for servers that record no address in a trusted header.
 *      It is a heuristic — a provider whose internal relays use public
 *      addresses will name one of those first — which is why the trusted
 *      header wins when it names one.
 *
 * NOT a source, wherever it sits: `Received-SPF` and
 * `ARC-Authentication-Results`. Earlier releases read the first `client-ip=`
 * anywhere in the authentication block, ahead of every other phrasing. So a
 * sender who typed `Received-SPF: pass … client-ip=<a clean address>` into
 * their own message chose the address every blocklist was asked about, and a
 * listed spam source walked straight past the reputation stage.
 *
 * - An ARC header is a copy one hop sealed for the next to weigh, and anybody
 *   can write one.
 * - `Received-SPF` names no author. RFC 7208's `receiver=` is optional and
 *   Gmail leaves it out, so no authserv-id can be matched against it.
 * - Its POSITION does not tie it to the receiving server either. Postfix's
 *   policy service writes it above the server's own `Received:` line, and
 *   Gmail writes it below. A caller who hands the authentication block and
 *   the trace over separately, as `OriginIpSources` does, has lost the
 *   interleaving anyway.
 *
 * Dropping it costs nothing on the servers seen in practice. Every one that
 * writes a real `Received-SPF` also records the client either in its
 * `Authentication-Results` (Gmail, Microsoft 365) or in its own `Received:`
 * line (Postfix), and the trace reads that line.
 *
 * Private, loopback, link-local, carrier-NAT and IPv4-mapped-private addresses
 * are never returned: they are the receiving side's own plumbing, and a
 * blocklist has nothing to say about them.
 *
 * `ipaddr.js` owns the address grammar and the range classification; the code
 * here only finds candidate tokens and asks it.
 */
import ipaddr from 'ipaddr.js';

import {
  trustedAuthResults,
  type AuthResult,
  type AuthResultsHeader,
  type AuthResultsOptions,
} from './auth-results.js';

const IPV4_SHAPE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * A candidate token as a canonical address string, or null when it is not an
 * IP address at all. Strips the `[...]` and `IPv6:` decoration Received lines
 * use, and folds an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) to its IPv4.
 */
export function normalizeIp(candidate: string | null | undefined): string | null {
  if (!candidate) return null;
  const token = candidate
    .trim()
    .replace(/^\[|\]$/g, '')
    .replace(/^ipv6:/i, '');
  if (!token) return null;
  // Validity is checked BEFORE parsing, so the parsers below cannot throw.
  if (IPV4_SHAPE.test(token)) {
    // Strict dotted-quad only: ipaddr.js also accepts octal, hex and short
    // forms, none of which a mail server writes into a header — and all of
    // which are a way to smuggle a different address past a reader's eye.
    return ipaddr.IPv4.isValidFourPartDecimal(token) ? ipaddr.IPv4.parse(token).toString() : null;
  }
  if (token.includes(':') && ipaddr.IPv6.isValid(token)) {
    return ipaddr.process(token).toString();
  }
  return null;
}

/** True for a routable public unicast address (v4 or v6). */
export function isPublicIp(candidate: string | null | undefined): boolean {
  const ip = normalizeIp(candidate);
  return ip !== null && ipaddr.process(ip).range() === 'unicast';
}

/**
 * The properties a server names the connecting client in: RFC 8601 §2.7.3
 * registers `policy.iprev` for the iprev method, and Exim and Fastmail write
 * `smtp.remote-ip`. Properties are syntax, so they are read before comments.
 */
const CLIENT_IP_PROPERTIES = ['smtp.remote-ip', 'policy.iprev'] as const;

/**
 * True for the two checks that are ABOUT the connecting client: whether it may
 * send for the domain (SPF) and whether its reverse DNS holds up (iprev).
 * Those are the results a server names the client in. DKIM and DMARC judge the
 * message, not the client, so they are not read for an address.
 */
function evaluatesClient(result: AuthResult): boolean {
  return result.method === 'spf' || result.method === 'iprev';
}

/** What ends a word in a comment. */
const WORD_SEPARATORS = ' \t\r\n;,';

/**
 * The words of a comment, lowercased, with every quoted stretch left out.
 *
 * A quoted stretch is how a sender's own words get into the server's comment.
 * Gmail writes "domain of <envelope sender> designates …", and an envelope
 * sender's local part may be a quoted string with spaces in it. Read as words,
 * `"x designates 1.2.3.4 as permitted sender"@evil.example` would put a phrase
 * the sender chose ahead of the server's own. A local part WITHOUT quotes
 * cannot contain a space, so it stays one word and cannot spell a phrase.
 * Commas and semicolons end a word too, so `client-ip=x;` reads as the address
 * alone.
 */
function commentWords(comment: string): string[] {
  const words: string[] = [];
  let word = '';
  let quoted = false;
  let escaped = false;
  const endWord = (): void => {
    if (word) words.push(word.toLowerCase());
    word = '';
  };
  for (const c of comment) {
    if (escaped) {
      escaped = false;
    } else if (quoted) {
      if (c === '\\') escaped = true;
      else if (c === '"') quoted = false;
    } else if (c === '"') {
      quoted = true;
    } else if (WORD_SEPARATORS.includes(c)) {
      endWord();
    } else {
      word += c;
    }
  }
  endWord();
  return words;
}

/**
 * The client addresses a comment names, in the phrasings servers use:
 *
 *   - `designates <ip> as permitted sender` (Gmail, and the many servers that
 *     copy its wording), and the failing form `does not designate <ip> as
 *     permitted sender`;
 *   - `<ip> is neither permitted nor denied` (Gmail's neutral);
 *   - `sender IP is <ip>` (Microsoft 365, for every result);
 *   - `client-ip=<ip>` (an SPF comment written in `Received-SPF` style).
 *
 * The failing forms matter as much as the passing one. Spam is the mail whose
 * SPF fails, and an address missed there is a blocklist never asked. Each
 * candidate is the word in the address slot; the caller drops any that is not
 * an address.
 */
function commentAddresses(comment: string): (string | undefined)[] {
  const words = commentWords(comment);
  const found: (string | undefined)[] = [];
  words.forEach((word, i) => {
    if (word.startsWith('client-ip=')) {
      found.push(word.slice('client-ip='.length));
    } else if (
      (word === 'designates' || word === 'designate') &&
      words[i + 2] === 'as' &&
      words[i + 3] === 'permitted'
    ) {
      found.push(words[i + 1]);
    } else if (word === 'sender' && words[i + 1] === 'ip' && words[i + 2] === 'is') {
      found.push(words[i + 3]);
    } else if (words[i + 1] === 'is' && words[i + 2] === 'neither') {
      found.push(word);
    }
  });
  return found;
}

/** Every address one result names as the client: properties first, then comments. */
function clientAddresses(result: AuthResult): (string | undefined)[] {
  return [
    ...CLIENT_IP_PROPERTIES.map((name) => result.properties[name]),
    ...result.comments.flatMap(commentAddresses),
  ];
}

/**
 * The client's address from the trusted `Authentication-Results`, read from
 * ONE header: the topmost trusted header that reports an SPF or iprev result.
 *
 * With an authserv-id configured, several headers can carry it. Some are
 * honest: a server may write one per filter. But a sender can also copy the id
 * onto a header of their own. RFC 8601 §5 tells the server to strip such a
 * header, and not every server does. The forgery always sits BELOW the real
 * header, because it was in the message before the server prepended anything.
 * So the topmost header that checked the client is the server's own. If that
 * header names no address, a header further down cannot be told apart from a
 * forgery, so none is taken and the trace answers instead. Gmail's SPF `none`
 * is such a header: "does not designate permitted sender hosts", and no
 * address.
 */
function originIpFromTrusted(headers: readonly AuthResultsHeader[]): string | null {
  const header = headers.find((candidate) => candidate.results.some(evaluatesClient));
  for (const result of header?.results.filter(evaluatesClient) ?? []) {
    for (const candidate of clientAddresses(result)) {
      const ip = normalizeIp(candidate);
      if (ip && isPublicIp(ip)) return ip;
    }
  }
  return null;
}

/**
 * The connecting client's address, as the receiving server's own
 * `Authentication-Results` records it. See the module comment for which
 * header that is, and for why `Received-SPF` and ARC headers are never read.
 *
 * Pass the `authserv` you pass `parseAuthenticationHeaders`, so the address
 * and the verdict come from the same header.
 */
export function originIpFromAuthHeaders(
  block: string | null | undefined,
  options: AuthResultsOptions = {},
): string | null {
  return originIpFromTrusted(trustedAuthResults(block, options));
}

/**
 * The last external hop from the `Received:` lines, top-down (the order the
 * header block lists them — newest first). Only the `from` clause of each line
 * is read: the `by` clause names the receiving side, whose address is not the
 * one being judged.
 */
export function originIpFromReceived(
  received: readonly string[] | null | undefined,
): string | null {
  if (!received?.length) return null;
  for (const raw of received) {
    // Whitespace is collapsed first, so the clause can be walked token by
    // token rather than matched. The regex this replaces —
    // `/^from\s+(.*?)(?:\s+by\s+|\s*;|$)/i` — had three quantifiers that
    // could exchange the same spaces with each other, which is polynomial
    // backtracking on a `Received:` line, i.e. on text the sender writes. A
    // split and a loop cannot backtrack at all, and say the same thing more
    // plainly.
    const tokens = raw.replace(/\s+/g, ' ').trim().split(' ');
    if (tokens[0]?.toLowerCase() !== 'from') continue;
    for (const token of tokens.slice(1)) {
      // `by` hands over to the RECEIVING side, whose address is not the one
      // being judged; `;` ends the clause and starts the timestamp.
      if (token.toLowerCase() === 'by') break;
      const beforeSemicolon = token.split(';')[0] as string;
      for (const piece of beforeSemicolon.split(/[()[\]]+/)) {
        const ip = normalizeIp(piece);
        if (ip && isPublicIp(ip)) return ip;
      }
      if (token.includes(';')) break;
    }
  }
  return null;
}

export interface OriginIpSources {
  /** The {@link extractAuthHeaderBlock} output for this message, if any. */
  authHeaders?: string | null;
  /** Every `Received:` value, unfolded, in header order (newest first). */
  received?: readonly string[] | null;
  /**
   * The receiving server's authserv-id(s), the same value
   * `parseAuthenticationHeaders` takes. Given one, the address comes only from
   * that server's `Authentication-Results`. Absent, it comes from the topmost
   * one, which a server that writes none leaves to whoever wrote one.
   */
  authserv?: AuthResultsOptions['authserv'];
}

/** The one address to record, or null when no source names a public one. */
export function extractOriginIp(sources: OriginIpSources): string | null {
  return (
    originIpFromAuthHeaders(sources.authHeaders, { authserv: sources.authserv }) ??
    originIpFromReceived(sources.received)
  );
}
