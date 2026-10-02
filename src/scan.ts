/**
 * `scan(rawMessage)` — the whole pipeline over one RFC 5322 message, and
 * `scanMany` for a mailbox full of them.
 *
 * Everything else in this package takes pieces a caller already has: an
 * envelope, a header block, a body part. That suits a mail client, which has
 * them anyway. It does not suit the other half of the audience — somebody with
 * a maildir, an archive, or a gateway handing them bytes — who would otherwise
 * have to reimplement the MIME parsing and, more importantly, reimplement the
 * decisions this file makes about what to believe.
 *
 * The output is JSON: numbers, strings and named reason ids, no classes and no
 * functions, so it can be stored, sent over a wire, and read back months later
 * by `spamVerdict` and `parseSpamReasons` alone.
 *
 * WHAT IT DOES NOT DO. No network, no DNS, no live SPF/DKIM verification. The
 * authentication verdict is READ from the headers, which is why this file
 * spends more code on deciding which of those headers to believe than it does
 * on anything else. A caller who wants the real thing runs
 * `verifyAuthentication` from `./verify.js` — which is async, optional and
 * theirs to call — and hands the answer back here as `options.auth`. That way
 * round, `scan` stays a function that CANNOT make a network call, which is a
 * far easier thing to reason about in an ingest loop than one that sometimes
 * does. `options.reputation` is the same arrangement for blocklists: the DNS
 * happens in `./reputation.js`, and only its assessment arrives here.
 * Attachments are inspected structurally — name, declared
 * type, magic bytes, zip directory — and never opened, unpacked or executed:
 * this is a spam scanner, and a clean attachment verdict means "nothing
 * deceptive about this file", never "safe to open".
 */
import PostalMime, { type Address, type Email } from 'postal-mime';

import { assessAttachmentSignals } from './attachments/rules.js';
import { assessContentSignals } from './content/rules.js';
import {
  authStatusFromResults,
  extractAuthHeaderBlock,
  normalizeAuthserv,
  parseAuthResultsHeader,
  trustedAuthResults,
} from './headers/auth-results.js';
import { headerLookupFromText, headerValuesFromText } from './headers/lookup.js';
import { extractOriginIp } from './headers/origin-ip.js';
import { receivedAt } from './headers/received-date.js';
import { domainOfAddress, type ProtectedBrand } from './identity.js';
import { assessSpamSignals } from './rules/header-rules.js';
import {
  mergeAssessments,
  spamVerdict,
  type AuthStatus,
  type SpamAssessment,
  type SpamReason,
  type SpamVerdict,
} from './verdict.js';

/** Anything `postal-mime` can parse: a string, bytes, a Blob or a stream. */
export type RawMessage = Parameters<typeof PostalMime.parse>[0];

export interface ScanOptions {
  /** The user has already reported this sender (a categorical 5-point rule). */
  knownSpammer?: boolean;
  /** The user's own outgoing mail. Never scored — see `ScanResult.assessed`. */
  ownMail?: boolean;
  /**
   * When the receiving system took delivery, unix SECONDS. Defaults to the
   * timestamp on the topmost `Received:` header; pass an IMAP INTERNALDATE
   * here when you have one, because you trust your own server's clock more
   * than a header. Without either, the date-skew rule cannot fire.
   */
  receivedAt?: number | null;
  /**
   * The authserv-id your own boundary MTA writes into `Authentication-Results`
   * (RFC 8601) — typically its hostname, e.g. `mx.google.com`. Given one, ONLY
   * that server's verdicts are believed.
   *
   * Supply it if you can. An `Authentication-Results` header is plain text that
   * anybody upstream can write, including the sender: without an authserv-id to
   * check, "DMARC passed" means "somebody, somewhere in the delivery chain,
   * wrote that down". See `trustedAuthHeaders` for what happens without it.
   */
  authserv?: string | readonly string[];
  /**
   * A verdict from `verifyAuthentication()` (the `/verify` entry point), used
   * INSTEAD of the one read from `Authentication-Results`.
   *
   * This is how real SPF/DKIM/DMARC verification reaches the rules: you do the
   * DNS work, on your own schedule and with your own timeout, and the scanner
   * scores the answer. It is worth more than the header verdict for the reason
   * the header verdict is hedged everywhere in this file — one is a fact you
   * established, the other is a sentence somebody typed.
   *
   * `null` or absent falls back to the headers, so a verification that timed
   * out degrades to what the trusted headers said rather than to nothing.
   */
  auth?: AuthStatus | null;
  /**
   * An assessment from `assessReputation()` (the `/reputation` entry point),
   * folded into this message's score.
   *
   * Same bargain as `auth`, and for the same reason: the blocklist queries are
   * DNS, so they happen outside this function, on your schedule, against the
   * zones you chose and are entitled to query. What arrives here is the
   * result, which scores like any other stage.
   *
   * `null` or absent simply contributes nothing. A lookup that failed, or one
   * you decided not to run, leaves the score exactly where the message's own
   * contents put it — never lower, and never a penalty for the silence.
   */
  reputation?: SpamAssessment | null;
  /**
   * The protected brands the sender name and the link text are judged
   * against. Defaults to `PROTECTED_BRANDS`; pass `[...PROTECTED_BRANDS, own]`
   * to protect the recipient's own organisation too.
   */
  brands?: readonly ProtectedBrand[];
}

/** The parts of the message a caller usually wants back alongside the verdict. */
export interface ScannedMessage {
  messageId: string | null;
  subject: string | null;
  fromName: string | null;
  fromAddress: string | null;
  /** The `Date:` header as the sender wrote it, unix SECONDS; null if absent or unparseable. */
  date: number | null;
  /**
   * Filenames and declared MIME types, for a caller listing what arrived.
   *
   * The bytes ARE scored — see the `attachment-*` reasons — but they are not
   * returned here: an attachment's content is the largest thing in a message
   * and a caller who wants it already has the message it came from.
   */
  attachments: { filename: string | null; mimeType: string }[];
}

export interface ScanResult {
  /** `false` for own mail: "not judged", which is not the same fact as "judged clean". */
  assessed: boolean;
  score: number;
  /** `null` for own mail — never judged, which a UI must not render as a green tick. */
  verdict: SpamVerdict | null;
  isSpam: boolean;
  suspicious: boolean;
  /** Header stage first, then content, then attachments, so it reads top-down. */
  reasons: SpamReason[];
  /** What the trusted `Authentication-Results` said; null when there was none to trust. */
  auth: AuthStatus | null;
  /** The public address the message came from, or null when the trace names none. */
  originIp: string | null;
  message: ScannedMessage;
}

/** `postal-mime` returns a group (`undisclosed-recipients:;`) where a mailbox may be. */
function mailboxes(
  address: Address | readonly Address[] | undefined,
): { name: string; address: string }[] {
  const list = address === undefined ? [] : Array.isArray(address) ? address : [address as Address];
  return list.flatMap((entry: Address) =>
    // Narrowing on `group` picks the mailbox variant, where `address` is a
    // required string — no `?? ''` fallback, which would be a branch no input
    // can reach and the coverage gate could never honestly meet.
    entry.group === undefined ? [{ name: entry.name, address: entry.address }] : entry.group,
  );
}

/** The addresses of a header, comma-joined the way the envelope-shaped rules expect. */
function addressList(address: Address | readonly Address[] | undefined): string | null {
  const joined = mailboxes(address)
    .map((mailbox) => mailbox.address)
    .filter(Boolean)
    .join(', ');
  return joined || null;
}

/** A Date header as unix seconds; null when absent or unparseable. */
function headerDate(value: string | undefined): number | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/** Header names carrying a verdict somebody else computed. Lowercase, as `postal-mime` reports them. */
const AUTH_HEADER_KEYS = new Set([
  'authentication-results',
  'arc-authentication-results',
  'received-spf',
]);

/**
 * The authentication header lines `scan` reads, as raw text: the origin IP
 * comes out of these, and so does the verdict — through
 * `parseAuthenticationHeaders`' own rule, which believes only the
 * `Authentication-Results` among them (see `trustedAuthResults`).
 *
 * This is the one security decision `scan` makes on the caller's behalf, so it
 * is worth being exact about. Every hop PREPENDS its headers, so the topmost
 * `Authentication-Results` is the one written by the machine that delivered the
 * message — the receiving end. Everything below it was written by a hop the
 * reader does not control, and the bottom of the trace is where a sender who
 * has simply typed `Authentication-Results: dmarc=pass` into their own message
 * puts it.
 *
 * So: with an `authserv` configured, only that server's `Authentication-Results`
 * are kept, which is exactly what RFC 8601 gives the authserv-id for — read
 * with the real parser, so a version number (`mx.example.com 1;`) or a comment
 * after the id does not hide the server's own header. Without one, only the
 * FIRST line of each header name is kept — the conventional assumption that
 * your own MTA is the most recent hop. That assumption is usually right and
 * occasionally not (a forwarder in front of you also prepends), which is why
 * `authserv` exists and why this returns what it kept rather than hiding it.
 */
export function trustedAuthHeaders(
  headerLines: readonly { key: string; line: string }[],
  authserv?: string | readonly string[],
): string {
  const ids = normalizeAuthserv(authserv);
  const kept: string[] = [];
  const seen = new Set<string>();

  for (const { key, line } of headerLines) {
    if (!AUTH_HEADER_KEYS.has(key)) continue;
    if (ids.length > 0) {
      // Only an `Authentication-Results` names its author; an ARC copy or a
      // `Received-SPF` line cannot be matched to a server, so none is kept.
      if (key !== 'authentication-results') continue;
      const { authservId } = parseAuthResultsHeader(line.slice(line.indexOf(':') + 1));
      if (authservId === null || !ids.includes(authservId)) continue;
    } else {
      if (seen.has(key)) continue;
      seen.add(key);
    }
    kept.push(line);
  }
  return kept.join('\n');
}

/** Scan one raw message. Rejects only if the bytes cannot be parsed as a message at all. */
export async function scan(raw: RawMessage, options: ScanOptions = {}): Promise<ScanResult> {
  return scanParsed(await PostalMime.parse(raw), options);
}

/**
 * The same scan over an already-parsed message.
 *
 * Exported because a caller who has parsed the MIME for their own reasons —
 * to store the body, to render it — should not pay to parse it twice, and
 * because it is the seam every test in this file uses.
 */
export function scanParsed(email: Email, options: ScanOptions = {}): ScanResult {
  const headerText = email.headerLines.map((header) => header.line).join('\n');
  const authBlock = extractAuthHeaderBlock(trustedAuthHeaders(email.headerLines, options.authserv));
  // Null when nothing survived — "no verdict to trust" — not an all-unknown
  // verdict that would read as though a server had been asked.
  const trustedResults = trustedAuthResults(authBlock, { authserv: options.authserv });
  const auth =
    options.auth ?? (trustedResults.length > 0 ? authStatusFromResults(trustedResults) : null);
  const lookup = headerLookupFromText(headerText);
  const received = headerValuesFromText(headerText, 'received');
  const from = mailboxes(email.from)[0];

  const message: ScannedMessage = {
    messageId: email.messageId ?? null,
    subject: email.subject ?? null,
    fromName: from?.name || null,
    fromAddress: from?.address || null,
    date: headerDate(email.date),
    attachments: email.attachments.map((attachment) => ({
      filename: attachment.filename,
      mimeType: attachment.mimeType,
    })),
  };

  const originIp = extractOriginIp({ authHeaders: authBlock, received });

  if (options.ownMail) {
    return {
      assessed: false,
      score: 0,
      verdict: null,
      isSpam: false,
      suspicious: false,
      reasons: [],
      auth,
      originIp,
      message,
    };
  }

  const headerAssessment = assessSpamSignals({
    fromAddress: message.fromAddress,
    fromName: message.fromName,
    replyTo: addressList(email.replyTo),
    toAddress: addressList(email.to),
    ccAddress: addressList(email.cc),
    subject: message.subject,
    // The id AS RECEIVED. `postal-mime` synthesises nothing, so an absent
    // header arrives here as null and the missing-message-id rule can fire.
    messageId: message.messageId,
    inReplyTo: email.inReplyTo ?? null,
    references: email.references ?? null,
    date: message.date,
    internalDate: options.receivedAt ?? receivedAt(received),
    auth,
    headers: lookup,
    knownSpammer: options.knownSpammer === true,
    brands: options.brands,
  });

  const contentAssessment = assessContentSignals({
    subject: message.subject,
    text: email.text ?? null,
    html: email.html ?? null,
    // Whose name a deceptive link may borrow to look like the reader's own
    // site: everyone the message was addressed to.
    brands: options.brands,
    recipientDomains: [...mailboxes(email.to), ...mailboxes(email.cc)].map((mailbox) =>
      domainOfAddress(mailbox.address),
    ),
  });

  // The bytes as the parser decoded them, so the magic-number and zip-directory
  // rules read the real file rather than its base64. Nothing is executed,
  // unpacked or inflated — see `attachments/zip.ts` for why that matters.
  const attachmentAssessment = assessAttachmentSignals(
    email.attachments.map((attachment) => ({
      filename: attachment.filename,
      mimeType: attachment.mimeType,
      content: typeof attachment.content === 'string' ? null : attachment.content,
    })),
  );

  const merged = mergeAssessments(
    headerAssessment,
    contentAssessment,
    attachmentAssessment,
    options.reputation,
  );
  return {
    assessed: true,
    score: merged.score,
    verdict: spamVerdict(merged.score),
    isSpam: merged.isSpam,
    suspicious: merged.suspicious,
    reasons: merged.reasons,
    auth,
    originIp,
    message,
  };
}

/** One message on the way in. `id` is echoed back so a caller can match up results. */
export interface BulkScanInput {
  id?: string;
  raw: RawMessage;
  options?: ScanOptions;
}

/**
 * One result on the way out. Exactly one of `result` / `error` is set: a
 * message that cannot be parsed is reported, never thrown, because in a bulk
 * run over a real mailbox one unparseable message must not end the run and
 * lose the thousands behind it.
 */
export interface BulkScanResult {
  id?: string;
  result: ScanResult | null;
  error: Error | null;
}

export interface BulkScanOptions extends ScanOptions {
  /**
   * How many messages to parse at once. MIME parsing is the expensive part and
   * it is all CPU, so there is nothing to gain past a handful.
   */
  concurrency?: number;
}

const DEFAULT_CONCURRENCY = 4;

function asError(cause: unknown): Error {
  return cause instanceof Error ? cause : new Error(String(cause));
}

async function scanOne(input: BulkScanInput, shared: ScanOptions): Promise<BulkScanResult> {
  try {
    return {
      id: input.id,
      result: await scan(input.raw, { ...shared, ...input.options }),
      error: null,
    };
  } catch (cause) {
    return { id: input.id, result: null, error: asError(cause) };
  }
}

/**
 * Scan many messages, yielding one result each, IN INPUT ORDER.
 *
 * Order is preserved even though the scans overlap, because a bulk API whose
 * output order depends on how long each message happened to take is one nobody
 * can write a stable test — or a resumable job — against. The cost is that one
 * slow message holds up the results behind it; they are still scanned, just not
 * yielded yet.
 *
 * Takes any iterable or async iterable, so a directory listing, a database
 * cursor and an array all work without adapting anything, and consumes it
 * lazily: at most `concurrency` messages are held in memory at a time, which is
 * what makes this usable on a mailbox bigger than RAM.
 */
export async function* scanMany(
  source: Iterable<BulkScanInput> | AsyncIterable<BulkScanInput>,
  options: BulkScanOptions = {},
): AsyncGenerator<BulkScanResult> {
  const { concurrency, ...shared } = options;
  const width = Math.max(1, Math.floor(concurrency ?? DEFAULT_CONCURRENCY));
  const inFlight: Promise<BulkScanResult>[] = [];

  for await (const input of source) {
    inFlight.push(scanOne(input, shared));
    // Yield the HEAD, not whichever finished first: `shift` before `await` so
    // the ones behind it keep running while this one is handed to the caller.
    if (inFlight.length >= width) yield await (inFlight.shift() as Promise<BulkScanResult>);
  }
  while (inFlight.length > 0) yield await (inFlight.shift() as Promise<BulkScanResult>);
}
