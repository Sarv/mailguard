import type { Email } from 'postal-mime';
import { describe, expect, it } from 'vitest';

import { assessReputation, type ReputationResult } from '../src/reputation.js';
import { scan, scanMany, scanParsed, trustedAuthHeaders, type BulkScanInput } from '../src/scan.js';
import { verifyAuthentication } from '../src/verify.js';

import {
  fakeResolver,
  signedMessage,
  PASSING_ZONE,
  SENDER_IP,
  SIGNING_DOMAIN,
  SIGNING_SUPPORTED,
} from './dkim-fixture.js';
import { ADOBE_SIGN_LURE } from './phish-fixture.js';

/** A raw RFC 5322 message. Headers as given, then a blank line, then the body. */
function message(headers: string[], body = 'Hello, the invoice is attached.\r\n'): string {
  return `${headers.join('\r\n')}\r\n\r\n${body}`;
}

/** A lookup that reached every zone and found nothing. */
const NO_HITS: ReputationResult = {
  ip: '93.184.216.34',
  domain: 'example.com',
  listed: false,
  hits: [],
  checked: ['zen.spamhaus.org'],
  errors: [],
  completed: true,
};

const RECEIVED = 'Received: by mx.test.com with ESMTPS id abc; Wed, 3 Sep 2026 10:11:12 +0000';
const CLEAN = [
  RECEIVED,
  'Authentication-Results: mx.test.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
  'Message-ID: <abc123@example.com>',
  'Date: Wed, 3 Sep 2026 10:11:00 +0000',
  'From: Alex Carter <alex@example.com>',
  'To: Sam Riley <sam@test.com>',
  'Subject: Q3 invoice',
];

describe('scan', () => {
  it('scores an ordinary authenticated message clean, and reports what it read', async () => {
    const result = await scan(message(CLEAN));
    expect(result.assessed).toBe(true);
    expect(result.reasons).toEqual([]);
    expect(result.score).toBe(0);
    expect(result.verdict).toBe('clean');
    expect(result.isSpam).toBe(false);
    expect(result.auth?.dmarc).toBe('pass');
    expect(result.message).toEqual({
      messageId: '<abc123@example.com>',
      subject: 'Q3 invoice',
      fromName: 'Alex Carter',
      fromAddress: 'alex@example.com',
      date: Math.floor(Date.UTC(2026, 8, 3, 10, 11, 0) / 1000),
      attachments: [],
    });
  });

  // Regression: the whole point of item 3. A caller with raw bytes must get
  // BOTH stages out of one call — a header-only answer would silently be a
  // different verdict from the one this library documents.
  it('merges the header stage and the content stage into one verdict', async () => {
    const result = await scan(
      message(
        [
          RECEIVED,
          'Authentication-Results: mx.test.com; dmarc=fail header.from=paypal.com',
          'Message-ID: <x@evil.example>',
          'Date: Wed, 3 Sep 2026 10:11:00 +0000',
          'From: "PayPal Security - paypal.com" <billing@evil.example>',
          'To: Sam Riley <sam@test.com>',
          'Subject: Verify your account',
          'Content-Type: text/html; charset=utf-8',
        ],
        '<p>Please <a href="https://evil.example/login">https://paypal.com/login</a> to confirm your password.</p>\r\n',
      ),
    );
    const ids = result.reasons.map((reason) => reason.id);
    expect(ids).toContain('auth-failed');
    expect(ids).toContain('display-name-spoof');
    expect(ids).toContain('content-spam-vocabulary');
    expect(ids).toContain('link-display-mismatch');
    expect(result.isSpam).toBe(true);
    expect(result.verdict).toBe('spam');
  });

  // The campaign these rules were written for, end to end: a brand name on an
  // attacker-owned domain that passed every authentication check, forged
  // threading, and a link dressed as the recipient's own domain. Headers alone
  // are 3 + 2; with the body it is well over the line — and `auth-failed` is
  // NOT among the reasons, because nothing about the authentication was wrong.
  it('files the authenticated brand-impersonation lure as spam', async () => {
    const result = await scan(ADOBE_SIGN_LURE);
    const ids = result.reasons.map((reason) => reason.id);
    expect(ids).toContain('brand-impersonation');
    expect(ids).toContain('in-reply-to-self');
    expect(ids).toContain('link-display-mismatch');
    expect(result.reasons.find((r) => r.id === 'link-display-mismatch')?.points).toBe(4);
    expect(ids).not.toContain('auth-failed');
    expect(result.auth?.dmarc).toBe('pass');
    expect(result.isSpam).toBe(true);
    expect(result.verdict).toBe('spam');
  });

  // Regression: the recipient domains come from To AND Cc — a lure sent to a
  // list of colleagues with the reader on Cc still names the reader's domain.
  it('reads the recipient domains from both To and Cc', async () => {
    const lure = (to: string, cc: string): string =>
      message(
        [
          RECEIVED,
          'From: docs@sender.example',
          `To: ${to}`,
          `Cc: ${cc}`,
          'Subject: Document',
          'Content-Type: text/html; charset=utf-8',
        ],
        '<a href="https://evil.example/x">example.org portal</a>\r\n',
      );
    const viaCc = await scan(lure('someone@other.example', 'me@example.org'));
    expect(viaCc.reasons.find((r) => r.id === 'link-display-mismatch')?.points).toBe(4);
    const unrelated = await scan(lure('someone@other.example', 'x@third.example'));
    expect(unrelated.reasons.find((r) => r.id === 'link-display-mismatch')?.points).toBe(2);
  });

  // Regression: header reasons must come first, because that is the order the
  // explanation is read in and the order every other caller of
  // `mergeAssessments` produces.
  it('orders the reasons header stage first', async () => {
    const result = await scan(
      message([RECEIVED, 'From: a@example.com', 'Subject: Re: hello'], 'you have won a prize\r\n'),
    );
    const ids = result.reasons.map((reason) => reason.id);
    expect(ids.indexOf('fake-reply')).toBeLessThan(ids.indexOf('content-spam-vocabulary'));
  });

  // Regression: own mail is NOT JUDGED, which is a different fact from judged
  // clean. A UI that gets `verdict: 'clean'` here shows a green tick on mail
  // nothing ever looked at.
  it('does not judge own mail, but still reports the headers it read', async () => {
    const result = await scan(message(CLEAN), { ownMail: true });
    expect(result.assessed).toBe(false);
    expect(result.verdict).toBeNull();
    expect(result.score).toBe(0);
    expect(result.reasons).toEqual([]);
    expect(result.auth?.dmarc).toBe('pass');
    expect(result.message.subject).toBe('Q3 invoice');
  });

  it('passes the caller´s categorical flag through to the header rules', async () => {
    const result = await scan(message(CLEAN), { knownSpammer: true });
    expect(result.reasons.map((reason) => reason.id)).toContain('known-spammer');
    expect(result.isSpam).toBe(true);
  });

  // Regression: a raw file has no INTERNALDATE, so without the Received trace
  // the date-skew rule can never fire and a message dated years out scores the
  // same as one dated correctly.
  it('takes the delivery time from the Received trace, and lets the caller override it', async () => {
    const skewed = message([
      RECEIVED,
      'Message-ID: <x@example.com>',
      'Date: Mon, 1 Jan 2001 00:00:00 +0000',
      'From: alex@example.com',
      'To: sam@test.com',
      'Subject: hello',
    ]);
    expect((await scan(skewed)).reasons.map((reason) => reason.id)).toContain('date-skew');
    // Told the delivery actually happened then, the skew disappears.
    const atTheTime = Math.floor(Date.UTC(2001, 0, 1, 0, 30, 0) / 1000);
    expect(
      (await scan(skewed, { receivedAt: atTheTime })).reasons.map((reason) => reason.id),
    ).not.toContain('date-skew');
  });

  // Regression: the attachment stage has to reach the DECODED bytes. The
  // wire carries base64, and a scanner that sniffs the base64 sees a text
  // file every time — every magic-number and zip rule silently stops firing,
  // and the only symptom is attachments that never score.
  it('scores an attachment from its decoded bytes, end to end', async () => {
    // `TVqQAAMAAAA=` is `MZ\x90\0\x03\0\0\0` — a Windows executable, sent
    // under a document name and declared as a PDF.
    const raw = [
      'From: alex@example.com',
      'To: sam@test.com',
      'Subject: Invoice',
      'Message-ID: <att2@example.com>',
      'Date: Wed, 3 Sep 2026 10:11:00 +0000',
      RECEIVED,
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--B',
      'Content-Type: application/pdf; name="invoice.pdf.exe"',
      'Content-Disposition: attachment; filename="invoice.pdf.exe"',
      'Content-Transfer-Encoding: base64',
      '',
      'TVqQAAMAAAA=',
      '--B--',
      '',
    ].join('\r\n');

    const result = await scan(raw);
    const ids = result.reasons.map((reason) => reason.id);
    expect(ids).toContain('attachment-double-extension');
    expect(ids).toContain('attachment-executable');
    expect(ids).toContain('attachment-type-mismatch');
    expect(result.isSpam).toBe(true);
    // The names and types are still reported; the bytes are not.
    expect(result.message.attachments).toEqual([
      { filename: 'invoice.pdf.exe', mimeType: 'application/pdf' },
    ]);
  });

  // Regression: `postal-mime` types an attachment's content as
  // `ArrayBuffer | Uint8Array | string`, and the string case is real — an
  // attachment the parser handed back as text. Passing a string into the
  // byte rules would sniff a type off characters that are not the file, so
  // the scan drops it and keeps the name-based rules.
  it('scores the name when a parser hands back attachment content as text', () => {
    const parsed = {
      headerLines: [],
      from: { name: 'Alex Carter', address: 'alex@example.com' },
      to: [{ name: 'Sam Riley', address: 'sam@test.com' }],
      subject: 'Invoice',
      messageId: '<text@example.com>',
      date: 'Wed, 3 Sep 2026 10:11:00 +0000',
      text: 'See attached.',
      attachments: [
        {
          filename: 'invoice.pdf.exe',
          mimeType: 'application/pdf',
          disposition: 'attachment',
          content: 'not really bytes',
        },
      ],
    } as unknown as Email;

    const result = scanParsed(parsed, {
      receivedAt: Math.floor(Date.UTC(2026, 8, 3, 10, 11, 0) / 1000),
    });
    const ids = result.reasons.map((reason) => reason.id);
    // Read from the name, which is all there is.
    expect(ids).toContain('attachment-double-extension');
    expect(ids).toContain('attachment-executable');
    // Not read from the string: nothing may be sniffed out of it.
    expect(ids).not.toContain('attachment-type-mismatch');
  });

  it('reports attachment names and types without claiming to have scored them', async () => {
    const raw = [
      'From: alex@example.com',
      'To: sam@test.com',
      'Subject: Invoice',
      'Message-ID: <att@example.com>',
      'Date: Wed, 3 Sep 2026 10:11:00 +0000',
      RECEIVED,
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--B',
      'Content-Type: application/pdf; name="invoice.pdf"',
      'Content-Disposition: attachment; filename="invoice.pdf"',
      'Content-Transfer-Encoding: base64',
      '',
      'JVBERi0xLjQK',
      '--B--',
      '',
    ].join('\r\n');
    const result = await scan(raw);
    expect(result.message.attachments).toEqual([
      { filename: 'invoice.pdf', mimeType: 'application/pdf' },
    ]);
  });

  // Note the address: the documentation ranges (198.51.100.0/24 and friends)
  // are reserved, and `extractOriginIp` rejects every reserved range on
  // purpose, so a fixture using one tests nothing.
  it('reads the origin IP out of the trusted authentication headers', async () => {
    const result = await scan(
      message([
        'Received: from sender.example ([93.184.216.34]) by mx.test.com; Wed, 3 Sep 2026 10:11:12 +0000',
        'Received-SPF: pass (mx.test.com: domain of example.com designates 93.184.216.34 as permitted sender) client-ip=93.184.216.34;',
        ...CLEAN.slice(2),
      ]),
    );
    expect(result.originIp).toBe('93.184.216.34');
  });

  // Regression: the trace is the fallback when no authentication header names
  // an address, and an internal relay hop must not be reported as the origin.
  it('walks the Received trace when the authentication headers name no address', async () => {
    const result = await scan(
      message([
        'Received: from relay.internal ([10.0.0.8]) by mx.test.com; Wed, 3 Sep 2026 10:11:12 +0000',
        'Received: from sender.example ([93.184.216.34]) by relay.internal; Wed, 3 Sep 2026 10:11:10 +0000',
        ...CLEAN.slice(2),
      ]),
    );
    expect(result.originIp).toBe('93.184.216.34');
  });

  // Regression: `undisclosed-recipients:;` is a GROUP, not a mailbox, and an
  // address-less mailbox is legal too. Either one used to be read as a
  // recipient that is not there — or crash the mapping on its way past.
  it('reads a group recipient and an address-less mailbox without inventing one', async () => {
    const result = await scan(
      message([
        RECEIVED,
        'Message-ID: <g@example.com>',
        'Date: Wed, 3 Sep 2026 10:11:00 +0000',
        'From: Alex Carter <alex@example.com>',
        'To: undisclosed-recipients:;',
        'Cc: Sam Riley <sam@test.com>',
        'Subject: hello',
      ]),
    );
    expect(result.assessed).toBe(true);
    expect(result.reasons.map((reason) => reason.id)).not.toContain('no-recipient');
  });

  // Regression: a `Date:` nobody can parse is not a `Date:` — treating it as
  // one feeds NaN into the skew arithmetic, and NaN compares false against
  // everything, so the rule silently passes every malformed message.
  it('treats an unparseable Date header as no date at all', async () => {
    const result = await scan(
      message([
        RECEIVED,
        'Message-ID: <d@example.com>',
        'Date: whenever it suits you',
        'From: Alex Carter <alex@example.com>',
        'To: sam@test.com',
        'Subject: hello',
      ]),
    );
    expect(result.message.date).toBeNull();
    expect(result.reasons.map((reason) => reason.id)).toContain('missing-date');
  });

  it('reports a missing subject as null rather than an empty string', async () => {
    const result = await scan(
      message([
        RECEIVED,
        'Message-ID: <s@example.com>',
        'Date: Wed, 3 Sep 2026 10:11:00 +0000',
        'From: Alex Carter <alex@example.com>',
        'To: sam@test.com',
      ]),
    );
    expect(result.message.subject).toBeNull();
  });

  it('scores a message with no headers worth the name, without throwing', async () => {
    const result = await scan('Subject: nothing\r\n\r\nhello\r\n');
    expect(result.assessed).toBe(true);
    expect(result.reasons.map((reason) => reason.id)).toEqual(
      expect.arrayContaining([
        'sender-invalid',
        'missing-message-id',
        'missing-date',
        'no-recipient',
      ]),
    );
    expect(result.auth).toBeNull();
    expect(result.originIp).toBeNull();
  });
});

describe('trustedAuthHeaders', () => {
  const line = (key: string, value: string): { key: string; line: string } => ({
    key,
    line: `${key}: ${value}`,
  });

  // Regression: THE security property of `scan`. `Authentication-Results` is
  // plain text anybody can write, and a sender who types `dmarc=pass` into
  // their own message puts it at the BOTTOM of the trace, below everything the
  // receiving chain prepended. Believing it turns the auth-failed rule into a
  // rule the spammer controls.
  it('keeps only the topmost line of each name when no authserv is configured', () => {
    const kept = trustedAuthHeaders([
      line('authentication-results', 'mx.test.com; dmarc=fail header.from=paypal.com'),
      line('authentication-results', 'evil.example; dmarc=pass header.from=paypal.com'),
    ]);
    expect(kept).toContain('dmarc=fail');
    expect(kept).not.toContain('dmarc=pass');
  });

  it('keeps one of each distinct name, not just one line overall', () => {
    const kept = trustedAuthHeaders([
      line('received-spf', 'pass (mx.test.com) client-ip=198.51.100.20;'),
      line('authentication-results', 'mx.test.com; dmarc=pass'),
      line('arc-authentication-results', 'i=1; mx.test.com; dmarc=pass'),
      line('authentication-results', 'evil.example; dmarc=pass'),
    ]);
    expect(kept.split('\n')).toHaveLength(3);
  });

  // Regression: a forwarder in front of you also prepends, so "topmost" is a
  // convention, not a guarantee. An authserv-id is the RFC 8601 answer and
  // must win over position entirely — including when the trusted server's line
  // is NOT the topmost one.
  it('believes only the configured authserv-id, wherever in the trace it sits', () => {
    const lines = [
      line('authentication-results', 'forwarder.example; dmarc=fail'),
      line('authentication-results', 'mx.test.com; dmarc=pass header.from=example.com'),
      line('authentication-results', 'evil.example; dmarc=pass'),
    ];
    const kept = trustedAuthHeaders(lines, 'mx.test.com');
    expect(kept).toBe('authentication-results: mx.test.com; dmarc=pass header.from=example.com');
    expect(trustedAuthHeaders(lines, ['mx.test.com', 'mx2.test.com']).split('\n')).toHaveLength(1);
  });

  it('is empty when the configured authserv wrote nothing, rather than falling back', () => {
    const kept = trustedAuthHeaders(
      [line('authentication-results', 'evil.example; dmarc=pass')],
      'mx.test.com',
    );
    expect(kept).toBe('');
  });

  it('ignores headers that are not authentication verdicts, and blank authserv entries', () => {
    const lines = [
      line('subject', 'hello'),
      line('authentication-results', 'mx.test.com; dmarc=pass'),
    ];
    expect(trustedAuthHeaders(lines)).toBe('authentication-results: mx.test.com; dmarc=pass');
    expect(trustedAuthHeaders(lines, ['  ', ''])).toBe(
      'authentication-results: mx.test.com; dmarc=pass',
    );
  });
});

describe('scan with an authserv configured', () => {
  // Regression: end to end, the forged verdict must not reach the rules. This
  // is the difference between "DMARC passed" meaning something and meaning
  // "somebody, somewhere, wrote that down".
  it('ignores a forged pass that a sender appended below the real verdict', async () => {
    const raw = message([
      RECEIVED,
      'Authentication-Results: mx.test.com; dmarc=fail header.from=paypal.com',
      'Message-ID: <x@evil.example>',
      'Date: Wed, 3 Sep 2026 10:11:00 +0000',
      'From: billing@evil.example',
      'To: sam@test.com',
      'Subject: hello',
      'Authentication-Results: evil.example; spf=pass dkim=pass dmarc=pass',
    ]);
    for (const options of [{}, { authserv: 'mx.test.com' }]) {
      const result = await scan(raw, options);
      expect(result.auth?.dmarc).toBe('fail');
      expect(result.reasons.map((reason) => reason.id)).toContain('auth-failed');
    }
  });
});

describe('scan with a verified authentication verdict', () => {
  // THE point of the option. The headers on this message say every check
  // passed; the verification says DMARC failed. A verdict you established
  // outranks a sentence somebody typed into a header, and if it did not, doing
  // the DNS work would buy nothing.
  it('believes the verified verdict over the one written in the headers', async () => {
    const result = await scan(message(CLEAN), {
      auth: { spf: 'pass', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
    });

    expect(result.auth).toEqual({ spf: 'pass', dkim: 'fail', dmarc: 'fail', overall: 'fail' });
    expect(result.reasons.map((reason) => reason.id)).toContain('auth-failed');
  });

  // Regression: a verification that timed out hands back no verdict, and the
  // message must still be scored on what the trusted headers said rather than
  // dropping to "nothing is known" — which would silently disable the
  // authentication rules for the whole duration of a DNS outage.
  it('falls back to the headers when no verified verdict was reached', async () => {
    const result = await scan(message(CLEAN), { auth: null });

    expect(result.auth).toEqual({ spf: 'pass', dkim: 'pass', dmarc: 'pass', overall: 'pass' });
  });

  // Regression: the header block is still read even when its verdict is
  // overridden, because the origin IP is extracted from those same headers. An
  // implementation that skipped the block once it had an answer would lose the
  // address, and with it every rule that depends on where the message came
  // from.
  it('still reads the origin IP out of the headers it overrode', async () => {
    const raw = message([
      'Received: from sender.example ([93.184.216.34]) by mx.test.com; Wed, 3 Sep 2026 10:11:12 +0000',
      'Authentication-Results: mx.test.com; spf=pass smtp.mailfrom=example.com',
      ...CLEAN.slice(2),
    ]);
    const result = await scan(raw, {
      auth: { spf: 'fail', dkim: 'unknown', dmarc: 'unknown', overall: 'fail' },
    });

    expect(result.auth?.spf).toBe('fail');
    expect(result.originIp).toBe('93.184.216.34');
  });

  // The seam itself, end to end: the shape `verifyAuthentication` returns is
  // the shape `scan` accepts. Nothing else proves the two halves of this
  // feature were built against the same type, and a mismatch would only show
  // up in a consumer's code.
  // Skipped where `mailauth` cannot load (Node < 22.19 — see SIGNING_SUPPORTED).
  it.skipIf(!SIGNING_SUPPORTED)(
    'accepts what verifyAuthentication returns, over a really signed message',
    async () => {
      const raw = await signedMessage();
      const verification = await verifyAuthentication(raw, {
        ip: SENDER_IP,
        helo: `mx.${SIGNING_DOMAIN}`,
        mailFrom: `ankur@${SIGNING_DOMAIN}`,
        resolver: fakeResolver(PASSING_ZONE),
      });

      const result = await scan(raw, { auth: verification.auth });

      expect(result.auth).toEqual({ spf: 'pass', dkim: 'pass', dmarc: 'pass', overall: 'pass' });
      expect(result.reasons.map((reason) => reason.id)).not.toContain('auth-failed');
    },
  );
});

describe('scan with a reputation assessment', () => {
  /** What `assessReputation` hands back for a listed sending address. */
  const listed = assessReputation({
    ip: '93.184.216.34',
    domain: null,
    listed: true,
    hits: [
      {
        name: 'spamhaus-zen',
        zone: 'zen.spamhaus.org',
        kind: 'ip',
        target: '93.184.216.34',
        codes: ['127.0.0.2'],
        meanings: ['SBL: a known source of spam'],
        categories: ['spam'],
        points: 4,
        text: null,
      },
    ],
    checked: ['zen.spamhaus.org'],
    errors: [],
    completed: true,
  });

  // THE point of the option, and the seam between the two halves: the shape
  // `assessReputation` returns is the shape `scan` accepts, and its reasons
  // reach the same score and the same stored `reasons` array as every other
  // stage. A mismatch here would only ever show up in a consumer's code.
  it("folds a listing into the score alongside the message's own signals", async () => {
    const clean = await scan(message(CLEAN));
    const result = await scan(message(CLEAN), { reputation: listed });

    expect(result.score).toBe(clean.score + 4);
    expect(result.reasons).toEqual([
      ...clean.reasons,
      {
        id: 'reputation-ip-listed',
        points: 4,
        detail:
          'The sending address 93.184.216.34 is listed by spamhaus-zen (SBL: a known source of spam).',
      },
    ]);
    expect(result.verdict).toBe('suspicious');
  });

  // Regression: a blocklist lookup that failed, timed out, or was never run
  // must cost the message nothing. Treating silence as a penalty would file
  // mail as spam for the duration of a DNS outage — and treating it as a
  // bonus would do the reverse.
  it('scores a message identically when no reputation was supplied', async () => {
    const baseline = await scan(message(CLEAN));

    for (const options of [{}, { reputation: null }, { reputation: assessReputation(NO_HITS) }]) {
      const result = await scan(message(CLEAN), options);
      expect(result.score).toBe(baseline.score);
      expect(result.reasons).toEqual(baseline.reasons);
    }
  });
});

describe('scanMany', () => {
  const collect = async (
    source: Iterable<BulkScanInput> | AsyncIterable<BulkScanInput>,
    options?: Parameters<typeof scanMany>[1],
  ): Promise<{ id?: string; verdict: string | null; error: string | null }[]> => {
    const out = [];
    for await (const item of scanMany(source, options)) {
      out.push({
        id: item.id,
        verdict: item.result?.verdict ?? null,
        error: item.error?.message ?? null,
      });
    }
    return out;
  };

  it('yields one result per message, echoing the caller´s id back', async () => {
    const results = await collect([
      { id: 'a', raw: message(CLEAN) },
      { id: 'b', raw: message(CLEAN, 'you have won a prize, claim your prize now\r\n') },
    ]);
    expect(results.map((item) => item.id)).toEqual(['a', 'b']);
    expect(results[0]?.verdict).toBe('clean');
  });

  // Regression: a bulk API whose output order depends on how long each message
  // took is one nobody can write a stable test — or a resumable job — against.
  it('preserves input order even though the scans overlap', async () => {
    const inputs: BulkScanInput[] = Array.from({ length: 12 }, (_, index) => ({
      id: String(index),
      raw: message([...CLEAN, `X-Index: ${index}`]),
    }));
    const results = await collect(inputs, { concurrency: 5 });
    expect(results.map((item) => item.id)).toEqual(inputs.map((input) => input.id));
  });

  // Regression: one message that cannot be read, in a mailbox of 50,000, must
  // not end the run and lose the rest. A stream that fails mid-read is the
  // realistic version of that — a disk error, a truncated download — and it is
  // the one input that genuinely throws: `postal-mime` parses even nonsense
  // bytes into an empty message rather than raising.
  it('reports a message it cannot read and keeps going', async () => {
    const unreadable = new ReadableStream({
      start(controller) {
        controller.error(new Error('disk read failed'));
      },
    });
    const results = await collect([
      { id: 'ok-1', raw: message(CLEAN) },
      { id: 'bad', raw: unreadable },
      { id: 'ok-2', raw: message(CLEAN) },
    ]);
    expect(results.map((item) => item.id)).toEqual(['ok-1', 'bad', 'ok-2']);
    expect(results[1]?.error).toBe('disk read failed');
    expect(results[1]?.verdict).toBeNull();
    expect(results[2]?.verdict).toBe('clean');
  });

  // Regression: a stream can be failed with anything at all, not just an
  // Error. Handing the caller a `null` where the error goes, or letting a
  // string escape as a thrown value, loses the only record of what went wrong.
  it('reports a failure that was not an Error as one', async () => {
    const results = await collect([
      {
        id: 'bad',
        raw: new ReadableStream({
          start(controller) {
            controller.error('just a string');
          },
        }),
      },
    ]);
    expect(results[0]?.error).toBe('just a string');
  });

  it('takes an async iterable, so a cursor or a directory walk needs no adapter', async () => {
    async function* source(): AsyncGenerator<BulkScanInput> {
      yield { id: 'a', raw: message(CLEAN) };
      yield { id: 'b', raw: message(CLEAN) };
    }
    expect((await collect(source())).map((item) => item.id)).toEqual(['a', 'b']);
  });

  it('lets a per-message option override the shared one', async () => {
    const results = await collect(
      [
        { id: 'shared', raw: message(CLEAN) },
        { id: 'own', raw: message(CLEAN), options: { ownMail: true } },
      ],
      { knownSpammer: true },
    );
    expect(results[0]?.verdict).toBe('spam');
    expect(results[1]?.verdict).toBeNull();
  });

  it('accepts an empty source, and clamps a nonsense concurrency rather than hanging', async () => {
    expect(await collect([])).toEqual([]);
    expect((await collect([{ id: 'a', raw: message(CLEAN) }], { concurrency: 0 })).length).toBe(1);
    expect((await collect([{ id: 'a', raw: message(CLEAN) }], { concurrency: -3 })).length).toBe(1);
  });

  // Regression: the bulk API exists so that a 50,000-message mailbox can be
  // scanned without holding 50,000 messages in memory. That only works if the
  // source is read lazily, and the window is what bounds it: at most
  // `concurrency` messages have been pulled and not yet handed back, however
  // long the stream runs. Drain the source eagerly — or keep finished results
  // in a growing buffer — and the memory is the mailbox, not the window.
  it('never reads more than concurrency messages ahead of the ones it has yielded', async () => {
    let pulled = 0;
    let yielded = 0;
    let widest = 0;
    async function* source(): AsyncGenerator<BulkScanInput> {
      for (let index = 0; index < 500; index += 1) {
        pulled += 1;
        widest = Math.max(widest, pulled - yielded);
        yield { id: String(index), raw: message([...CLEAN, `X-Index: ${index}`]) };
      }
    }

    for await (const item of scanMany(source(), { concurrency: 4 })) {
      expect(item.error).toBeNull();
      yielded += 1;
    }

    // Four scans in flight; the fifth pull is what forces the head out. The
    // number is the concurrency, not a function of the 500 messages behind it.
    expect(yielded).toBe(500);
    expect(widest).toBe(4);
  });

  // Regression: a consumer that walks away — a preview of the first page, a
  // cancelled job, a `find` that stops at the first hit — leaves scans in
  // flight, and some of those scans are failing. A rejected promise nobody is
  // left to await is an unhandled rejection, which on a default Node 15+
  // runtime terminates the host process: a mail server killed by a cancelled
  // preview. `scanOne` catching everything is what makes that impossible, so
  // it must stay caught. The source must also stop being pulled, or breaking
  // early still reads the whole mailbox.
  it('pulls no further and rejects nothing when the consumer breaks early', async () => {
    const unhandled: unknown[] = [];
    const record = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', record);

    let pulled = 0;
    const failing = (): ReadableStream =>
      new ReadableStream({
        start(controller) {
          controller.error(new Error('disk read failed'));
        },
      });
    async function* source(): AsyncGenerator<BulkScanInput> {
      for (let index = 0; index < 200; index += 1) {
        pulled += 1;
        // Every third message fails, so the abandoned window holds rejections.
        yield index % 3 === 0
          ? { id: String(index), raw: failing() }
          : { id: String(index), raw: message([...CLEAN, `X-Index: ${index}`]) };
      }
    }

    let seen = 0;
    for await (const item of scanMany(source(), { concurrency: 8 })) {
      void item;
      seen += 1;
      if (seen === 5) break;
    }

    // Long enough for an unhandled rejection to be reported if one exists.
    await new Promise((resolve) => setTimeout(resolve, 50));
    process.off('unhandledRejection', record);

    expect(unhandled).toEqual([]);
    expect(seen).toBe(5);
    // The five yielded, plus at most one window still in flight when we left.
    expect(pulled).toBeLessThanOrEqual(seen + 8);
  });
});

describe('scan with a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };
  it('judges the sender name and the link text against it', async () => {
    const raw = message(
      [
        RECEIVED,
        'From: "Acme Corp Billing" <billing@evil.example>',
        'To: sam@test.com',
        'Subject: Invoice',
        'Content-Type: text/html; charset=utf-8',
      ],
      '<a href="https://evil.example/x">https://acme.example/pay</a>\r\n',
    );
    const plain = await scan(raw);
    expect(plain.reasons.map((r) => r.id)).not.toContain('brand-impersonation');
    const guarded = await scan(raw, { brands: [ACME] });
    expect(guarded.reasons.map((r) => r.id)).toContain('brand-impersonation');
    expect(guarded.reasons.find((r) => r.id === 'link-display-mismatch')?.points).toBe(3);
  });
});
