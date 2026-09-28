/**
 * The header-only rule set — the offline stage of the scanner.
 *
 * Runs before a body exists, over headers a sync already pays for: From /
 * Reply-To / Subject / Message-ID / Date / threading, the receiving server's
 * authentication verdict, the bulk-mail headers, and any verdict an upstream
 * filter (SpamAssassin, rspamd, Exchange) already stamped on. Deterministic and
 * local; nothing leaves the machine and nothing is looked up over the network.
 *
 * The shape is SpamAssassin's: each rule contributes points and a reason, and
 * the total is compared with {@link SPAM_THRESHOLD}. A single rule decides on
 * its own only where the evidence is categorical — an upstream filter said so,
 * or the user themselves reported the sender. Every other rule sits below the
 * line, because each has a benign explanation alone: a forwarder breaks DKIM,
 * a home address in Reply-To, a cron job with no Message-ID. It is the
 * COMBINATION that is unmistakable, and the weights are chosen so the classic
 * ones cross the line — a spoofed display name on a message that failed DMARC
 * (3 + 3), a forged "Re:" from an unauthenticated sender (2 + 3) — while any
 * single benign anomaly does not.
 *
 * Reputation signals (DNS blocklists, reverse DNS, sender history) are a later
 * stage: they need the network, and they hang off the origin IP recorded
 * alongside this score. Their points add to these; they do not replace them.
 */
import emailAddresses from 'email-addresses';

import { FREEMAIL_DOMAINS } from '../data/freemail-domains.js';
import { bulkHeaderSignals } from '../headers/bulk.js';
import type { HeaderLookup } from '../headers/lookup.js';
import { assessSender, domainOfAddress, type ProtectedBrand } from '../identity.js';
import { hasReplyPrefix, isValidMessageId } from '../rfc.js';
import {
  assessmentOf,
  type AuthStatus,
  type SpamAssessment,
  type SpamReason,
  type SpamReasonId,
} from '../verdict.js';

/**
 * Headers this stage reads beyond the envelope and `BULK_HEADER_NAMES`.
 * Exported so an IMAP fetch asks for exactly these — a header read here but
 * never fetched is a rule that silently never fires.
 */
export const SPAM_HEADER_NAMES: readonly string[] = [
  'x-spam-flag', // SpamAssassin / rspamd: "YES"
  'x-spam-status', // SpamAssassin: "Yes, score=7.1 required=5.0 ..."
  'x-ms-exchange-organization-scl', // Exchange / Microsoft 365 spam confidence level
];

/**
 * A Date header this far from the server's own receive time is a forgery tell
 * (SpamAssassin's DATE_IN_FUTURE_96_XX / DATE_IN_PAST_96_XX). Four days, not
 * hours: a queue can legitimately retry for days, a laptop clock can be off by
 * hours.
 */
export const DATE_SKEW_SECONDS = 96 * 3600;

export interface SpamSignalInput {
  fromAddress?: string | null;
  fromName?: string | null;
  replyTo?: string | null;
  toAddress?: string | null;
  ccAddress?: string | null;
  subject?: string | null;
  /** The Message-ID AS RECEIVED — empty/null when the sender sent none, never a synthesised one. */
  messageId?: string | null;
  inReplyTo?: string | null;
  references?: string | null;
  /** Date header, unix SECONDS; null when the header is absent. */
  date?: number | null;
  /** The server's own receive time (IMAP INTERNALDATE), unix SECONDS; null when unknown. */
  internalDate?: number | null;
  /** The receiving server's SPF/DKIM/DMARC verdict, when it recorded one. */
  auth?: AuthStatus | null;
  /** Lookup over the fetched header block; null when only the envelope is known. */
  headers?: HeaderLookup | null;
  /** The user has already reported this sender. */
  knownSpammer?: boolean;
  /**
   * The protected brands a display name is judged against for
   * `brand-impersonation`. Defaults to `PROTECTED_BRANDS`; a mail client adds
   * the mailbox owner's own organisation with `[...PROTECTED_BRANDS, own]`.
   */
  brands?: readonly ProtectedBrand[];
}

const FREEMAIL = new Set<string>(FREEMAIL_DOMAINS);

/** Is this a consumer webmail address (gmail, yahoo, outlook, ...)? */
export function isFreemailAddress(address: string | null | undefined): boolean {
  if (!address) return false;
  const at = address.lastIndexOf('@');
  if (at < 0) return false;
  const host = address
    .slice(at + 1)
    .trim()
    .toLowerCase();
  if (FREEMAIL.has(host)) return true;
  const registrable = domainOfAddress(address);
  return !!registrable && FREEMAIL.has(registrable);
}

/** RFC 5322 (with RFC 6532 UTF-8) says this is one deliverable address. */
function isDeliverableAddress(address: string): boolean {
  try {
    const parsed = emailAddresses.parseOneAddress({ input: address, rfc6532: true });
    return !!parsed && 'address' in parsed && !!parsed.address;
  } catch {
    return false;
  }
}

/** Score one message from its headers alone. Pure; safe to run per message at ingest. */
export function assessSpamSignals(input: SpamSignalInput): SpamAssessment {
  const reasons: SpamReason[] = [];
  const add = (id: SpamReasonId, points: number, detail: string): void => {
    reasons.push({ id, points, detail });
  };
  const header = (name: string): string =>
    input.headers ? (input.headers(name) || '').trim() : '';

  // 1. An upstream filter already decided. Categorical: it saw the body and
  //    the network, which this stage cannot.
  const spamFlag = header('x-spam-flag');
  const spamStatus = header('x-spam-status');
  const scl = Number.parseInt(header('x-ms-exchange-organization-scl'), 10);
  if (/^yes\b/i.test(spamFlag)) {
    add('upstream-spam', 5, 'Your mail server marked it as spam (X-Spam-Flag: YES)');
  } else if (/^yes\b/i.test(spamStatus)) {
    add('upstream-spam', 5, 'Your mail server marked it as spam (X-Spam-Status: Yes)');
  } else if (Number.isFinite(scl) && scl >= 5) {
    add('upstream-spam', 5, `Exchange rated it spam (spam confidence level ${scl})`);
  }

  // 2. The user's own word.
  if (input.knownSpammer) add('known-spammer', 5, 'You reported this sender as spam');

  // 3. Authentication. DMARC is the authoritative verdict; SPF and DKIM are its
  //    inputs and either can fail benignly (a forwarder, a list). Only when the
  //    server recorded no DMARC verdict do both inputs failing stand in for it.
  //    The same rule the security level applies, so a red shield and the
  //    filter's points always agree.
  const auth = input.auth;
  if (auth) {
    const dmarcKnown = auth.dmarc === 'pass' || auth.dmarc === 'fail';
    if (auth.dmarc === 'fail') {
      add('auth-failed', 3, 'DMARC failed — the sender’s domain did not authenticate this message');
    } else if (!dmarcKnown && auth.spf === 'fail' && auth.dkim === 'fail') {
      add(
        'auth-failed',
        3,
        'SPF and DKIM both failed — the sending server is not authorised for this domain',
      );
    }
  }

  // 4. Identity. Three checks, three ids, one call: the shield and the
  //    scorer read the same `assessSender`, so a name the shield paints red is
  //    always a name the filter charged for. A brand name borrowed by a
  //    mailing list or a group is NOT impersonation — a list that rewrites
  //    From for DMARC puts the author's name on its own address, and every
  //    brand that posts to a Google Group would otherwise score here — so the
  //    brand reason is dropped when the message declares itself list mail.
  //    The domain check keeps firing on a list: a list does not put another
  //    domain into the author's name.
  const listMail = !!input.headers && !!bulkHeaderSignals(input.headers).listId;
  for (const reason of assessSender(input.fromName, input.fromAddress, input.brands)) {
    switch (reason.kind) {
      case 'domain':
        add('display-name-spoof', 3, reason.text);
        break;
      case 'brand':
        if (!listMail) add('brand-impersonation', 3, reason.text);
        break;
      default:
        add('sender-punycode', 1, reason.text);
    }
  }
  const from = (input.fromAddress || '').trim();
  if (!from) add('sender-invalid', 2, 'No sender address');
  else if (!isDeliverableAddress(from))
    add('sender-invalid', 2, `The sender address “${from}” is not a valid address`);

  const fromDomain = domainOfAddress(from);
  const replyDomain = domainOfAddress(input.replyTo);
  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    if (isFreemailAddress(input.replyTo) && !isFreemailAddress(from)) {
      add(
        'reply-to-freemail',
        2,
        `Replies go to a free webmail address at ${replyDomain}, while the message claims to be from ${fromDomain}`,
      );
    } else {
      add(
        'reply-to-mismatch',
        1,
        `Replies go to ${replyDomain}, not to the sender’s domain ${fromDomain}`,
      );
    }
  }

  // 5. Plumbing a real mail client always gets right.
  const messageId = (input.messageId || '').trim();
  if (!messageId)
    add('missing-message-id', 2, 'No Message-ID header — every real mail server adds one');
  else if (!isValidMessageId(messageId))
    add('malformed-message-id', 1, 'The Message-ID header is malformed');

  if (input.date == null) {
    add('missing-date', 1, 'No Date header');
  } else if (input.internalDate != null) {
    const skew = input.date - input.internalDate;
    if (Math.abs(skew) > DATE_SKEW_SECONDS) {
      const days = Math.round(Math.abs(skew) / 86_400);
      add(
        'date-skew',
        2,
        skew > 0 ? `Dated ${days} days AFTER it arrived` : `Dated ${days} days before it arrived`,
      );
    }
  }

  // KNOWN LIMITATION: `hasReplyPrefix` also matches forward prefixes (Fwd:,
  // WG:, Doorst:), and a forward composed by a client that does not carry
  // References across is a legitimate message with no threading headers. The
  // rule therefore fires on some honest forwards. It is kept at 2 points —
  // below the suspicious threshold — precisely because it cannot be trusted
  // alone, and it is ported unchanged so that scores stay comparable with
  // those already stored by the codebase this was extracted from. Splitting
  // reply from forward prefixes is tracked as a scoring change, not a fix.
  if (
    hasReplyPrefix(input.subject) &&
    !(input.inReplyTo || '').trim() &&
    !(input.references || '').trim()
  ) {
    add(
      'fake-reply',
      2,
      'Looks like a reply, but it is not replying to anything (no In-Reply-To or References)',
    );
  }

  // A reply to ITSELF. In-Reply-To is supposed to name the message being
  // answered; naming this message's own Message-ID is something a phishing
  // kit does to make a threading view show a conversation already under way
  // — and, it turned out, something a real bank's alert mailer does too: Axis
  // Bank's own AutoPay notices from axis.bank.in (DMARC p=reject) carry it.
  // So it is sloppy plumbing on its own (one point) and a corroborating tell
  // only beside a sender-identity lie (two), which is where the Adobe Sign
  // lure had it: brand-impersonation 3 + this 2 still reaches the spam line
  // on the headers alone.
  const inReplyTo = (input.inReplyTo || '').trim();
  if (messageId && inReplyTo && inReplyTo === messageId) {
    const identityLie = reasons.some(
      (reason) => reason.id === 'brand-impersonation' || reason.id === 'display-name-spoof',
    );
    add(
      'in-reply-to-self',
      identityLie ? 2 : 1,
      'Claims to be a reply to itself — In-Reply-To names this message’s own Message-ID',
    );
  }

  if (!(input.toAddress || '').trim() && !(input.ccAddress || '').trim()) {
    add('no-recipient', 1, 'No visible recipient — sent to undisclosed recipients');
  }

  // 6. Bulk mail that does not play by the bulk-mail rules. A list or campaign
  //    tool is REQUIRED to offer List-Unsubscribe; a blast that hides it is
  //    the kind that never intended to honour one. Auto-generated transactional
  //    mail is exempt — a receipt has nothing to unsubscribe from.
  //    Only List-Id and Precedence DECLARE bulk. Feedback-ID and an ESP's
  //    tracing headers say which pipe the mail went through, and transactional
  //    mail — a bank alert, an OTP, a receipt — goes through the same pipes
  //    without an unsubscribe route, rightly, and often without Auto-Submitted.
  if (input.headers) {
    const bulk = bulkHeaderSignals(input.headers);
    const declaredBulk = bulk.listId || bulk.precedenceBulk;
    if (declaredBulk && !bulk.listUnsubscribe && !bulk.autoSubmitted) {
      add('bulk-no-unsubscribe', 1, 'Bulk mail with no way to unsubscribe');
    }
    if (header('precedence').toLowerCase() === 'junk') {
      add('precedence-junk', 1, 'The sender labelled it junk itself (Precedence: junk)');
    }
  }

  return assessmentOf(reasons);
}
