import { describe, expect, it } from 'vitest';

import { headerLookupFromText } from '../src/headers/lookup.js';
import {
  assessSpamSignals,
  isFreemailAddress,
  DATE_SKEW_SECONDS,
  SPAM_HEADER_NAMES,
} from '../src/rules/header-rules.js';
import type { SpamSignalInput } from '../src/rules/header-rules.js';
import { SPAM_THRESHOLD, SUSPICIOUS_THRESHOLD, type AuthStatus } from '../src/verdict.js';

/** A message with nothing wrong with it — the baseline every rule is measured against. */
const CLEAN: SpamSignalInput = {
  fromAddress: 'alice@example.net',
  fromName: 'Alice Example',
  toAddress: 'bob@sarv.com',
  subject: 'Lunch on Thursday',
  messageId: '<CAF=abc123@mail.example.net>',
  date: 1_758_000_000,
  internalDate: 1_758_000_010,
};

const auth = (over: Partial<AuthStatus> = {}): AuthStatus => ({
  spf: 'pass',
  dkim: 'pass',
  dmarc: 'pass',
  overall: 'pass',
  ...over,
});

const ids = (input: SpamSignalInput): string[] => assessSpamSignals(input).reasons.map((r) => r.id);

describe('assessSpamSignals — the baseline', () => {
  // Regression: this is the most important test in the file. If an ordinary
  // message scores anything at all, every threshold below is meaningless and
  // real mail starts disappearing.
  it('scores an ordinary message zero', () => {
    const result = assessSpamSignals({ ...CLEAN, auth: auth() });
    expect(result.score).toBe(0);
    expect(result.reasons).toEqual([]);
    expect(result.isSpam).toBe(false);
    expect(result.suspicious).toBe(false);
  });

  it('scores an ordinary message zero even with no auth verdict and no header block', () => {
    expect(assessSpamSignals(CLEAN).score).toBe(0);
  });
});

describe('assessSpamSignals — upstream verdicts are categorical', () => {
  it('trusts X-Spam-Flag, X-Spam-Status and the Exchange confidence level, at 5 points each', () => {
    for (const block of [
      'X-Spam-Flag: YES',
      'X-Spam-Status: Yes, score=7.1 required=5.0',
      'X-MS-Exchange-Organization-SCL: 6',
    ]) {
      const result = assessSpamSignals({ ...CLEAN, headers: headerLookupFromText(block) });
      expect(
        result.reasons.map((r) => r.id),
        block,
      ).toContain('upstream-spam');
      expect(result.score, block).toBeGreaterThanOrEqual(SPAM_THRESHOLD);
      expect(result.isSpam, block).toBe(true);
    }
  });

  // Regression: "No" and a low SCL are the NORMAL values on mail that passed
  // an upstream filter. Reading them as positive would mark everything spam.
  it('does not fire on a negative verdict or a low confidence level', () => {
    for (const block of [
      'X-Spam-Flag: NO',
      'X-Spam-Status: No, score=-2.1 required=5.0',
      'X-MS-Exchange-Organization-SCL: 1',
      'X-MS-Exchange-Organization-SCL: -1',
      'X-MS-Exchange-Organization-SCL: not-a-number',
    ]) {
      expect(ids({ ...CLEAN, headers: headerLookupFromText(block) }), block).not.toContain(
        'upstream-spam',
      );
    }
  });

  it('counts the user’s own report as conclusive', () => {
    const result = assessSpamSignals({ ...CLEAN, knownSpammer: true });
    expect(result.reasons.map((r) => r.id)).toContain('known-spammer');
    expect(result.isSpam).toBe(true);
  });
});

describe('assessSpamSignals — authentication', () => {
  it('scores a DMARC failure', () => {
    expect(ids({ ...CLEAN, auth: auth({ dmarc: 'fail' }) })).toContain('auth-failed');
  });

  // Regression: this is the false positive that mattered most. A forwarder or
  // mailing list routinely breaks SPF or DKIM while DMARC still passes. If
  // either input alone scored, legitimate bank and travel mail got flagged.
  it('does NOT score a single broken input when DMARC passed', () => {
    expect(ids({ ...CLEAN, auth: auth({ spf: 'fail' }) })).not.toContain('auth-failed');
    expect(ids({ ...CLEAN, auth: auth({ dkim: 'fail' }) })).not.toContain('auth-failed');
  });

  it('falls back to "both inputs failed" only when there is no DMARC verdict', () => {
    expect(ids({ ...CLEAN, auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'none' }) })).toContain(
      'auth-failed',
    );
    expect(
      ids({ ...CLEAN, auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'unknown' }) }),
    ).toContain('auth-failed');
    // ...and never overrides an explicit DMARC pass.
    expect(
      ids({ ...CLEAN, auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'pass' }) }),
    ).not.toContain('auth-failed');
  });

  it('scores nothing when the server recorded no verdict at all', () => {
    expect(ids({ ...CLEAN, auth: null })).not.toContain('auth-failed');
  });
});

describe('assessSpamSignals — identity', () => {
  it('scores a display name impersonating another domain as danger', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'PayPal Service <service@paypal.com>',
      fromAddress: 'billing@paypal.secure-login.ru',
    });
    expect(result.reasons.map((r) => r.id)).toContain('display-name-spoof');
    expect(result.score).toBeGreaterThanOrEqual(SUSPICIOUS_THRESHOLD);
  });

  // Regression: the limitation this rule shipped with, closed. "PayPal
  // Service" <billing@evil.ru> has no dot in the name, so the domain rule has
  // nothing to resolve; the brand list is what catches it — under the brand's
  // OWN reason id, not display-name-spoof, so a reader can tell the two tells
  // apart.
  it('scores a bare protected brand name on a stranger’s address as brand impersonation', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'PayPal Service',
      fromAddress: 'billing@evil.ru',
    });
    const reason = result.reasons.find((r) => r.id === 'brand-impersonation');
    expect(reason?.points).toBe(3);
    expect(reason?.detail).toContain('PayPal');
    expect(reason?.detail).toContain('evil.ru');
    expect(result.reasons.map((r) => r.id)).not.toContain('display-name-spoof');
  });

  // The lure this rule was written for, headers only: perfect authentication
  // for a domain the attacker owns, a brand name in the display name, nothing
  // else wrong. Suspicious on the name alone — and NOT spam, because one name
  // is one signal and a weight of 3 is the promise that it stays that way.
  it('is suspicious but not filed on the brand name alone, even with DMARC passing', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'Adobe Acrobat Sign',
      fromAddress: 'Adobesign@powersublinks.com',
      auth: auth(),
    });
    expect(result.reasons.map((r) => r.id)).toEqual(['brand-impersonation']);
    expect(result.suspicious).toBe(true);
    expect(result.isSpam).toBe(false);
  });

  it('does not score the brand writing under its own name, from any of its domains', () => {
    expect(
      ids({ ...CLEAN, fromName: 'Adobe Acrobat Sign', fromAddress: 'adobesign@adobesign.com' }),
    ).toEqual([]);
    expect(
      ids({
        ...CLEAN,
        fromName: 'Adobe Acrobat Sign',
        fromAddress: 'echosign@documents.adobe.com',
      }),
    ).toEqual([]);
  });

  // Regression: a Google Group that carries a brand's posts rewrites From to
  // "Brand via Group" <group@googlegroups.com> and sets List-Id. Charging that
  // as impersonation would flag every brand that posts to a list — so both the
  // header the scorer can see and the marker the shield can see are honoured.
  it('exempts list mail — a List-Id, or a " via " rewrite — from the brand rule', () => {
    const listed = assessSpamSignals({
      ...CLEAN,
      fromName: 'DocuSign Support',
      fromAddress: 'group@googlegroups.com',
      headers: headerLookupFromText(
        'List-Id: <group.googlegroups.com>\r\nList-Unsubscribe: <https://x/u>',
      ),
    });
    expect(listed.reasons.map((r) => r.id)).not.toContain('brand-impersonation');
    expect(
      ids({
        ...CLEAN,
        fromName: 'DocuSign Support via Vendors',
        fromAddress: 'vendors@groups.example',
      }),
    ).not.toContain('brand-impersonation');
  });

  // One display name is one lie: a name that embeds PayPal's domain AND
  // PayPal's brand must be charged once, by the more specific rule.
  it('does not charge the brand rule on top of the domain rule for one name', () => {
    const reasons = ids({
      ...CLEAN,
      fromName: 'PayPal <service@paypal.com>',
      fromAddress: 'billing@evil.ru',
    });
    expect(reasons).toContain('display-name-spoof');
    expect(reasons).not.toContain('brand-impersonation');
  });

  it('flags a punycode sender domain as a caution, not a verdict', () => {
    const reasons = assessSpamSignals({ ...CLEAN, fromAddress: 'a@xn--80ak6aa92e.com' }).reasons;
    expect(reasons.map((r) => r.id)).toContain('sender-punycode');
    expect(reasons.find((r) => r.id === 'sender-punycode')?.points).toBe(1);
  });

  it('scores a missing or undeliverable sender address', () => {
    expect(ids({ ...CLEAN, fromAddress: '' })).toContain('sender-invalid');
    expect(ids({ ...CLEAN, fromAddress: 'not an address' })).toContain('sender-invalid');
  });

  it('separates a free-webmail Reply-To from an ordinary cross-domain one', () => {
    expect(ids({ ...CLEAN, replyTo: 'alice.private@gmail.com' })).toContain('reply-to-freemail');
    expect(ids({ ...CLEAN, replyTo: 'support@other-company.com' })).toContain('reply-to-mismatch');
  });

  // Regression: a Reply-To on the sender's OWN domain is ordinary (a support
  // alias, a no-reply box). Scoring it would hit most transactional mail.
  it('does not score a Reply-To on the sender’s own registrable domain', () => {
    const reasons = ids({ ...CLEAN, replyTo: 'support@mail.example.net' });
    expect(reasons).not.toContain('reply-to-mismatch');
    expect(reasons).not.toContain('reply-to-freemail');
  });

  // A freemail sender replying to freemail is two consumers talking, not a tell.
  it('does not score freemail-to-freemail as the freemail Reply-To rule', () => {
    const reasons = ids({ ...CLEAN, fromAddress: 'a@gmail.com', replyTo: 'b@yahoo.com' });
    expect(reasons).not.toContain('reply-to-freemail');
    expect(reasons).toContain('reply-to-mismatch');
  });
});

describe('assessSpamSignals — plumbing a real client always gets right', () => {
  it('scores a missing and a malformed Message-ID differently', () => {
    expect(ids({ ...CLEAN, messageId: null })).toContain('missing-message-id');
    expect(ids({ ...CLEAN, messageId: '   ' })).toContain('missing-message-id');
    expect(ids({ ...CLEAN, messageId: 'no-brackets@example.net' })).toContain(
      'malformed-message-id',
    );
  });

  it('scores a missing Date', () => {
    expect(ids({ ...CLEAN, date: null })).toContain('missing-date');
  });

  it('scores a Date far from the receive time, in either direction', () => {
    const base = CLEAN.internalDate as number;
    const future = assessSpamSignals({ ...CLEAN, date: base + DATE_SKEW_SECONDS + 86_400 });
    const past = assessSpamSignals({ ...CLEAN, date: base - DATE_SKEW_SECONDS - 86_400 });
    expect(future.reasons.map((r) => r.id)).toContain('date-skew');
    expect(future.reasons.find((r) => r.id === 'date-skew')?.detail).toContain('AFTER');
    expect(past.reasons.find((r) => r.id === 'date-skew')?.detail).toContain('before');
  });

  // Regression: a queue can retry for days and a laptop clock can be hours
  // out. The window has to stay generous or ordinary delayed mail scores.
  it('tolerates skew inside the window, and needs an internal date to compare against', () => {
    const base = CLEAN.internalDate as number;
    expect(ids({ ...CLEAN, date: base + DATE_SKEW_SECONDS - 60 })).not.toContain('date-skew');
    expect(
      ids({ ...CLEAN, date: base + 10 * DATE_SKEW_SECONDS, internalDate: null }),
    ).not.toContain('date-skew');
  });

  it('scores a reply prefix with nothing to reply to, and not one with threading headers', () => {
    expect(ids({ ...CLEAN, subject: 'Re: your invoice' })).toContain('fake-reply');
    expect(ids({ ...CLEAN, subject: 'Re: your invoice', inReplyTo: '<a@b.com>' })).not.toContain(
      'fake-reply',
    );
    expect(ids({ ...CLEAN, subject: 'Re: your invoice', references: '<a@b.com>' })).not.toContain(
      'fake-reply',
    );
  });

  // Regression: the header forgery the Adobe Sign lure carried. In-Reply-To
  // naming the message's own Message-ID is something no client produces, and
  // it must be its own reason so a reader is told the threading was forged.
  it('scores an In-Reply-To that names the message’s own Message-ID', () => {
    const own = CLEAN.messageId as string;
    const reason = assessSpamSignals({ ...CLEAN, inReplyTo: own }).reasons.find(
      (r) => r.id === 'in-reply-to-self',
    );
    expect(reason?.points).toBe(1);
    expect(ids({ ...CLEAN, inReplyTo: '<other@example.net>' })).not.toContain('in-reply-to-self');
    // No Message-ID at all is the missing-message-id rule's business, not this one's.
    expect(ids({ ...CLEAN, messageId: null, inReplyTo: '' })).not.toContain('in-reply-to-self');
  });

  // Regression: a self-reply beside a sender-identity lie is the Adobe Sign
  // lure's pair, and must still weigh 2 so the headers alone reach the spam
  // line (brand 3 + 2). If this drops, that lure lands in the inbox green.
  it('weighs a self-reply 2 when the sender name lies about who sent it', () => {
    const own = CLEAN.messageId as string;
    const brandLie = assessSpamSignals({
      ...CLEAN,
      fromName: 'Adobe Acrobat Sign',
      fromAddress: 'adobesign@powersublinks.com',
      inReplyTo: own,
      auth: auth(),
    });
    expect(brandLie.reasons.find((r) => r.id === 'in-reply-to-self')?.points).toBe(2);
    expect(brandLie.score).toBeGreaterThanOrEqual(SPAM_THRESHOLD);
    const domainLie = assessSpamSignals({
      ...CLEAN,
      fromName: 'service@paypal.com',
      fromAddress: 'x@evil.example',
      inReplyTo: own,
    });
    expect(domainLie.reasons.find((r) => r.id === 'in-reply-to-self')?.points).toBe(2);
  });

  // Regression, from a live mailbox 2026-09-27: Axis Bank's genuine AutoPay
  // notice from axis.bank.in (DMARC p=reject) names its own Message-ID in
  // In-Reply-To and travels through an ESP with a Feedback-ID but no
  // unsubscribe. It scored 6 and was filed as spam. Honest mail with sloppy
  // plumbing must stay below the warning line.
  it('keeps a genuine bank alert with a self-reply and an ESP trace below suspicious', () => {
    const messageId = '<20260927.abc@axis.bank.in>';
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'Axis Bank Alerts',
      fromAddress: 'alerts@axis.bank.in',
      subject: 'AutoPay for Anthropic: ACTIVATED',
      messageId,
      inReplyTo: messageId,
      auth: auth(),
      headers: headerLookupFromText(
        'Feedback-ID: 1:alerts:axis:netcore\r\nX-SES-Outgoing: 2026.09.27',
      ),
    });
    expect(result.reasons.map((r) => r.id)).toEqual(['in-reply-to-self']);
    expect(result.score).toBeLessThan(SUSPICIOUS_THRESHOLD);
  });

  it('scores a message with no visible recipient', () => {
    expect(ids({ ...CLEAN, toAddress: null, ccAddress: null })).toContain('no-recipient');
    expect(ids({ ...CLEAN, toAddress: null, ccAddress: 'x@sarv.com' })).not.toContain(
      'no-recipient',
    );
  });
});

describe('assessSpamSignals — bulk mail that breaks the bulk-mail rules', () => {
  it('scores declared bulk mail that offers no unsubscribe', () => {
    const block = 'List-Id: <promo.example.net>';
    expect(ids({ ...CLEAN, headers: headerLookupFromText(block) })).toContain(
      'bulk-no-unsubscribe',
    );
  });

  // Regression: a newsletter you asked for sets List-Id AND List-Unsubscribe,
  // and a receipt is auto-submitted with nothing to unsubscribe from. Both are
  // legitimate and must not score.
  it('exempts bulk mail that does offer one, and transactional auto-submitted mail', () => {
    const withUnsub = 'List-Id: <news.example.net>\r\nList-Unsubscribe: <https://x/u>';
    const receipt = 'Feedback-ID: 1:2:3:mc\r\nAuto-Submitted: auto-generated';
    expect(ids({ ...CLEAN, headers: headerLookupFromText(withUnsub) })).not.toContain(
      'bulk-no-unsubscribe',
    );
    expect(ids({ ...CLEAN, headers: headerLookupFromText(receipt) })).not.toContain(
      'bulk-no-unsubscribe',
    );
  });

  // Regression: Feedback-ID and ESP tracing headers name the pipe, not the
  // kind of mail — a bank alert or OTP sent through SES or Netcore carries
  // them with no unsubscribe, rightly. Only List-Id / Precedence declare bulk;
  // if these start scoring, every transactional mail through an ESP gains a
  // point toward the spam line.
  it('does not treat Feedback-ID or an ESP trace as a bulk declaration', () => {
    for (const block of [
      'Feedback-ID: 1:2:3:ses',
      'X-SES-Outgoing: 2026.09.27-1.2.3.4',
      'X-Mailer: SendGrid',
    ]) {
      expect(ids({ ...CLEAN, headers: headerLookupFromText(block) }), block).not.toContain(
        'bulk-no-unsubscribe',
      );
    }
    expect(ids({ ...CLEAN, headers: headerLookupFromText('Precedence: bulk') })).toContain(
      'bulk-no-unsubscribe',
    );
  });

  it('scores a sender that labelled its own mail junk', () => {
    expect(ids({ ...CLEAN, headers: headerLookupFromText('Precedence: junk') })).toContain(
      'precedence-junk',
    );
  });

  it('reads no bulk rules at all when the caller has no header block', () => {
    const reasons = ids({ ...CLEAN, headers: null });
    expect(reasons).not.toContain('bulk-no-unsubscribe');
    expect(reasons).not.toContain('precedence-junk');
  });
});

describe('assessSpamSignals — the combinations the weights were chosen for', () => {
  // These two are the reason no single heuristic is worth 5. Each pair is a
  // classic phishing shape, and each must cross the line together while
  // neither half crosses it alone.
  it('a spoofed display name on a DMARC failure reaches spam (3 + 3)', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'PayPal Service <service@paypal.com>',
      fromAddress: 'billing@paypal.secure-login.ru',
      auth: auth({ dmarc: 'fail' }),
    });
    expect(result.score).toBeGreaterThanOrEqual(SPAM_THRESHOLD);
    expect(result.isSpam).toBe(true);
  });

  it('a forged reply from an unauthenticated sender reaches spam (2 + 3)', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      subject: 'Re: your overdue invoice',
      auth: auth({ dmarc: 'fail' }),
    });
    expect(result.score).toBeGreaterThanOrEqual(SPAM_THRESHOLD);
  });

  // The Adobe Sign lure, headers only: a borrowed brand name and forged
  // threading on a domain that authenticated perfectly. 3 + 2 crosses the line
  // with no help from the body — and no help from authentication, which passed.
  it('a borrowed brand name with forged threading reaches spam (3 + 2)', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      fromName: 'Adobe Acrobat Sign',
      fromAddress: 'Adobesign@powersublinks.com',
      messageId: '<H2BLQ5A3@powersublinks.com>',
      inReplyTo: '<H2BLQ5A3@powersublinks.com>',
      auth: auth(),
    });
    expect(result.score).toBe(SPAM_THRESHOLD);
    expect(result.isSpam).toBe(true);
  });

  // Regression: two weak signals must NOT add up to a filing decision. A
  // person mailing from a client with no Message-ID, to an undisclosed list,
  // is odd — not spam.
  it('two weak signals stay below the spam threshold', () => {
    const result = assessSpamSignals({
      ...CLEAN,
      messageId: null,
      toAddress: null,
      ccAddress: null,
    });
    expect(result.score).toBe(3);
    expect(result.isSpam).toBe(false);
    expect(result.suspicious).toBe(true);
  });
});

describe('isFreemailAddress', () => {
  it('recognises consumer webmail, including on a subdomain', () => {
    expect(isFreemailAddress('a@gmail.com')).toBe(true);
    expect(isFreemailAddress('a@YAHOO.COM')).toBe(true);
    expect(isFreemailAddress('a@mail.gmail.com')).toBe(true);
  });

  it('is false for a company domain and for unusable input', () => {
    expect(isFreemailAddress('a@sarv.com')).toBe(false);
    expect(isFreemailAddress('no-at-sign')).toBe(false);
    expect(isFreemailAddress('')).toBe(false);
    expect(isFreemailAddress(null)).toBe(false);
    expect(isFreemailAddress(undefined)).toBe(false);
  });
});

describe('SPAM_HEADER_NAMES', () => {
  // Regression: a header read by a rule but absent from this list is a rule
  // that silently never fires, because the fetch never asks for it.
  it('names every extra header the rules read', () => {
    expect([...SPAM_HEADER_NAMES].sort()).toEqual(
      ['x-ms-exchange-organization-scl', 'x-spam-flag', 'x-spam-status'].sort(),
    );
  });
});

describe('assessSpamSignals — a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };
  // Regression: the scorer must judge the name against the SAME list the
  // shield does, or the two disagree about one message.
  it('charges brand impersonation for a brand only the caller protects', () => {
    const input = { ...CLEAN, fromName: 'Acme Corp Billing', fromAddress: 'x@evil.example' };
    expect(ids(input)).not.toContain('brand-impersonation');
    expect(ids({ ...input, brands: [ACME] })).toContain('brand-impersonation');
  });
});
