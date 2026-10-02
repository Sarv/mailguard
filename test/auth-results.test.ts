import { describe, expect, it } from 'vitest';

import {
  extractAuthHeaderBlock,
  parseAuthenticationHeaders,
  parseAuthResultsHeader,
  trustedAuthResults,
} from '../src/headers/auth-results.js';

/**
 * Collecting the mail-authentication headers at sync time.
 *
 * What this protects: these headers are the ONLY evidence of SPF / DKIM /
 * DMARC the client ever gets, and until now they were fetched for nothing —
 * the stored verdict was parsed from an empty string and read "unknown" for
 * every message. A regex over hostile header text is exactly where a folded
 * line or an odd casing quietly turns a real "dmarc=fail" back into "unknown".
 */
const CRLF = (...lines: string[]) => lines.join('\r\n');

describe('extractAuthHeaderBlock', () => {
  it('returns undefined for an empty or absent block, never an empty string', () => {
    // An empty string would parse as a verdict of "unknown"; undefined stores
    // NULL — "no verdict recorded" — which the level treats differently.
    expect(extractAuthHeaderBlock(undefined)).toBeUndefined();
    expect(extractAuthHeaderBlock(null)).toBeUndefined();
    expect(extractAuthHeaderBlock('')).toBeUndefined();
    expect(extractAuthHeaderBlock('From: a@b.c\r\nSubject: hi')).toBeUndefined();
  });

  it('picks out Authentication-Results and leaves the rest', () => {
    const out = extractAuthHeaderBlock(
      CRLF(
        'From: a@b.c',
        'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=b.c; dkim=pass; dmarc=pass',
        'Subject: hi',
      ),
    );
    expect(out).toBe(
      'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=b.c; dkim=pass; dmarc=pass',
    );
  });

  // THE folding case. Real servers wrap this header across several lines; the
  // old header helper had a documented bug where `$` with the m flag stopped at
  // the first physical line, truncating a multi-line value to its first token.
  it('unfolds a value continued across lines', () => {
    const out = extractAuthHeaderBlock(
      CRLF(
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@sarv.com;',
        '       spf=pass smtp.mailfrom=sarv.com;',
        '       dmarc=pass (p=REJECT) header.from=sarv.com',
        'From: x@sarv.com',
      ),
    );
    expect(out).toBe(
      'Authentication-Results: mx.google.com; dkim=pass header.i=@sarv.com; spf=pass smtp.mailfrom=sarv.com; dmarc=pass (p=REJECT) header.from=sarv.com',
    );
  });

  // One line per hop is normal; dropping all but the first would lose the
  // verdict the LAST (our own) server recorded.
  it('keeps every occurrence, one per hop', () => {
    const out = extractAuthHeaderBlock(
      CRLF(
        'Authentication-Results: hop1; spf=none',
        'Received: from somewhere',
        'Authentication-Results: hop2; spf=pass; dkim=pass; dmarc=pass',
      ),
    );
    expect(out?.split('\n')).toHaveLength(2);
  });

  it('collects ARC-Authentication-Results and Received-SPF too', () => {
    const out = extractAuthHeaderBlock(
      CRLF(
        'ARC-Authentication-Results: i=1; mx; dkim=pass',
        'Received-SPF: pass (sender IP is 1.2.3.4)',
      ),
    );
    expect(out).toContain('ARC-Authentication-Results: i=1; mx; dkim=pass');
    expect(out).toContain('Received-SPF: pass (sender IP is 1.2.3.4)');
  });

  it('is case-insensitive on the header name', () => {
    expect(extractAuthHeaderBlock('AUTHENTICATION-RESULTS: mx; dmarc=fail')).toContain(
      'dmarc=fail',
    );
  });

  // A header whose NAME merely contains the word must not match — otherwise a
  // sender could plant "X-Authentication-Results: dmarc=pass" and be believed.
  it('does not match a look-alike header name', () => {
    expect(extractAuthHeaderBlock('X-Authentication-Results: mx; dmarc=pass')).toBeUndefined();
    expect(extractAuthHeaderBlock('Old-Authentication-Results: mx; dmarc=pass')).toBeUndefined();
  });

  it('accepts a Buffer as the raw block', () => {
    expect(
      extractAuthHeaderBlock(Buffer.from('Authentication-Results: mx; spf=pass', 'utf8')),
    ).toBe('Authentication-Results: mx; spf=pass');
  });
});

describe('end to end: block → stored verdict', () => {
  // The whole point: a real Gmail header block must come out as a real verdict.
  it('turns a passing Gmail block into an all-pass verdict', () => {
    const block = extractAuthHeaderBlock(
      CRLF(
        'Authentication-Results: mx.google.com;',
        '       dkim=pass header.i=@sarv.com header.s=google;',
        '       spf=pass (google.com: domain of x@sarv.com designates 1.2.3.4 as permitted sender);',
        '       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sarv.com',
      ),
    );
    expect(parseAuthenticationHeaders(block)).toEqual({
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      overall: 'pass',
    });
  });

  it('turns a failing block into a fail — the signal the danger level keys on', () => {
    const block = extractAuthHeaderBlock(
      'Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail (p=REJECT)',
    );
    expect(parseAuthenticationHeaders(block).overall).toBe('fail');
  });
});

/** One `Authentication-Results` line, the way the extractor writes it. */
const AR = (value: string) => `Authentication-Results: ${value}`;
/** Several lines, topmost first — the order the extractor keeps. */
const block = (...lines: string[]) => lines.join('\n');

/**
 * The parser's own branches.
 *
 * These did not exist before the extraction. Sarv Inbox tested
 * `parseAuthenticationHeaders` only through the two end-to-end cases above —
 * an all-pass Gmail block and an all-fail one — so every intermediate verdict
 * it can return was shipping untested. The 100% gate is what surfaced that,
 * and these are the cases it was missing.
 *
 * CHANGED in 0.4.3: each case is a real `Authentication-Results` line. The old
 * substring reader also took a bare `spf=softfail` with no header name at all;
 * the parser now reads only lines named `Authentication-Results`, which is the
 * point — an `X-Whatever: dmarc=pass` must not count.
 */
describe('parseAuthenticationHeaders', () => {
  it('records no verdict at all for an empty block', () => {
    // Not "none": nothing was asserted, so nothing may be claimed.
    expect(parseAuthenticationHeaders(undefined)).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
    expect(parseAuthenticationHeaders('')).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
  });

  // softfail and neutral are the two SPF results that mean "the domain owner
  // declined to vouch for this server" rather than "this is a forgery". A
  // reader that renders either as a failure puts a red shield on a forwarded
  // mail, which teaches people to ignore red.
  it('distinguishes softfail and neutral from fail', () => {
    expect(parseAuthenticationHeaders(AR('mx; spf=softfail')).spf).toBe('softfail');
    expect(parseAuthenticationHeaders(AR('mx; spf=neutral')).spf).toBe('neutral');
    expect(parseAuthenticationHeaders(AR('mx; spf=none')).spf).toBe('none');
  });

  it('records an explicit "none" for DKIM and DMARC', () => {
    const status = parseAuthenticationHeaders(AR('mx; dkim=none; dmarc=none'));
    expect(status.dkim).toBe('none');
    expect(status.dmarc).toBe('none');
  });

  // The overall roll-up, every arm. `fail` wins over any number of passes
  // because one failed component is the one that matters.
  it('rolls up: any fail is fail, two passes is pass, one is partial', () => {
    expect(parseAuthenticationHeaders(AR('mx; spf=pass; dkim=pass; dmarc=fail')).overall).toBe(
      'fail',
    );
    expect(parseAuthenticationHeaders(AR('mx; spf=pass; dkim=pass')).overall).toBe('pass');
    expect(parseAuthenticationHeaders(AR('mx; spf=pass')).overall).toBe('partial');
    expect(parseAuthenticationHeaders(AR('mx; spf=none; dkim=none')).overall).toBe('none');
  });

  // Results a server may write that are none of the stored values. Reading
  // `temperror` as a failure would put a red shield on mail whose check merely
  // timed out; reading Microsoft's `bestguesspass` as a pass would claim a
  // DMARC policy the domain never published.
  it('reads results outside the stored vocabulary as unknown, and hardfail as fail', () => {
    const status = parseAuthenticationHeaders(
      AR('mx; spf=temperror; dkim=neutral (body hash did not verify); dmarc=bestguesspass'),
    );
    expect(status).toEqual({ spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', overall: 'none' });
    // RFC 5451's deprecated spelling of SPF `fail`; old evaluators still write it.
    expect(parseAuthenticationHeaders(AR('mx; spf=hardfail')).spf).toBe('fail');
  });

  // Regression: a bare statement, or a look-alike header name in a raw block,
  // is text a sender controls. Only a line NAMED Authentication-Results counts,
  // and an ARC copy or a Received-SPF line never does (see the forgery block).
  it('reads only lines named Authentication-Results, so a raw header block is safe', () => {
    expect(parseAuthenticationHeaders('dmarc=pass').dmarc).toBe('unknown');
    expect(
      parseAuthenticationHeaders(
        block('X-Authentication-Results: mx; dmarc=pass', 'Subject: dmarc=pass', 'no colon here'),
      ).dmarc,
    ).toBe('unknown');
    expect(parseAuthenticationHeaders(block('Received-SPF: pass (mx) client-ip=1.2.3.4')).spf).toBe(
      'unknown',
    );
  });

  // Regression: the parser unfolds for itself. Handed a raw block with a
  // folded header, it must not read the continuation (which starts with
  // whitespace, not a name) as a separate line and drop the verdict on it.
  it('unfolds a folded header in a raw block, and matches the name case-insensitively', () => {
    const raw =
      'authentication-results : mx.example.com;\r\n\tspf=pass;\r\n dmarc=fail\r\nFrom: a@b.c';
    expect(parseAuthenticationHeaders(raw)).toEqual({
      spf: 'pass',
      dkim: 'unknown',
      dmarc: 'fail',
      overall: 'fail',
    });
  });
});

/**
 * Forged verdicts — the reason this parser exists.
 *
 * `Authentication-Results` is plain text; a sender can type one into their own
 * message before sending it. Sarv Inbox reads the verdict to decide whether a
 * "trusted" sender's mail bypasses the spam filter, whether a sender's images
 * load on their own, and whether the phishing banner shows. Before 0.4.3 every
 * authentication header in the block was scanned for substrings and a pass
 * was looked for before a fail, so ONE forged `dmarc=pass` anywhere made a
 * failing message read as authenticated.
 */
describe('parseAuthenticationHeaders: forged headers', () => {
  const REAL = AR(
    'mx.test.com; spf=fail smtp.mailfrom=paypal.com; dkim=none; dmarc=fail header.from=paypal.com',
  );
  const FORGED = AR('mx.evil.example; spf=pass; dkim=pass; dmarc=pass header.from=paypal.com');

  // The common case: the receiving server prepends, so the sender's forgery
  // sits BELOW the real verdict. With or without an authserv-id, the real one
  // must be the only one read.
  it('ignores a forged header below the real one', () => {
    for (const options of [{}, { authserv: 'mx.test.com' }]) {
      const status = parseAuthenticationHeaders(block(REAL, FORGED), options);
      expect(status.dmarc).toBe('fail');
      expect(status.spf).toBe('fail');
    }
  });

  // A server that APPENDS its header (or a forwarder in front of it) puts the
  // forgery on top. The authserv-id is what rescues that case: position means
  // nothing once the author is known.
  it('ignores a forged header above the real one when the authserv-id is known', () => {
    const status = parseAuthenticationHeaders(block(FORGED, REAL), { authserv: 'mx.test.com' });
    expect(status.dmarc).toBe('fail');
    expect(status.overall).toBe('fail');
  });

  // KNOWN GAP, pinned so nobody mistakes it for an accident: with no
  // authserv-id the topmost header is believed, and a forgery can only be on
  // top if the receiving server appends its header or writes none at all. The
  // fix is to configure `authserv` — which is why the option exists.
  it('LIMITATION: without an authserv-id, believes whatever header is on top', () => {
    expect(parseAuthenticationHeaders(block(FORGED, REAL)).dmarc).toBe('pass');
  });

  // Regression: a forged header that copies the real server's authserv-id.
  // RFC 8601 §5 obliges the border MTA to delete it, but not every MTA does.
  // Then the two disagree, and a failure must never be outvoted by a pass —
  // above or below.
  it('lets a real failure outvote a forged pass that claims the same authserv-id', () => {
    const sameId = AR('mx.test.com; spf=pass; dkim=pass; dmarc=pass header.from=paypal.com');
    for (const order of [block(sameId, REAL), block(REAL, sameId)]) {
      const status = parseAuthenticationHeaders(order, { authserv: 'mx.test.com' });
      expect(status.dmarc).toBe('fail');
      expect(status.spf).toBe('fail');
      // DKIM: `none` in the real header, `pass` in the forgery. A pass has to
      // be unanimous, so the forgery cannot upgrade it either.
      expect(status.dkim).toBe('none');
    }
  });

  // Regression: ARC-Authentication-Results is a copy a hop sealed for the NEXT
  // hop to weigh, and anybody can write one. It must never supply a verdict —
  // not above the real header, and not in place of a missing one.
  it('never reads a verdict from ARC-Authentication-Results', () => {
    const arc = 'ARC-Authentication-Results: i=1; mx.test.com; spf=pass; dkim=pass; dmarc=pass';
    for (const options of [{}, { authserv: 'mx.test.com' }]) {
      expect(parseAuthenticationHeaders(block(arc, REAL), options).dmarc).toBe('fail');
      expect(parseAuthenticationHeaders(arc, options)).toEqual({
        spf: 'unknown',
        dkim: 'unknown',
        dmarc: 'unknown',
        overall: 'none',
      });
    }
  });

  // Regression: when the configured server wrote nothing, nothing is trusted —
  // falling back to "the topmost header" would hand the verdict straight to
  // whoever wrote one.
  it('trusts nothing when the configured authserv-id wrote no header', () => {
    expect(parseAuthenticationHeaders(FORGED, { authserv: 'mx.test.com' }).dmarc).toBe('unknown');
  });
});

describe('parseAuthenticationHeaders: combining trusted headers', () => {
  // Some servers write one header per filter — SPF, DKIM, DMARC each their
  // own. All carry the server's authserv-id and all are its own verdicts; read
  // only the first and the other two checks look as if they never ran.
  it('combines several real headers from the configured server', () => {
    const lines = block(
      AR('mx.test.com; spf=pass smtp.mailfrom=example.com'),
      'Received: from x by mx.test.com',
      AR('mx.test.com; dkim=pass header.d=example.com'),
      AR('upstream.example; dkim=fail'),
      AR('MX.Test.com 1; dmarc=pass header.from=example.com'),
    );
    expect(parseAuthenticationHeaders(lines, { authserv: 'mx.test.com' })).toEqual({
      spf: 'pass',
      dkim: 'pass',
      dmarc: 'pass',
      overall: 'pass',
    });
    // Without the id, only the topmost is read: the others go unknown rather
    // than being taken from a header of unknown authorship.
    expect(parseAuthenticationHeaders(lines)).toEqual({
      spf: 'pass',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'partial',
    });
  });

  // Several ids — a provider with more than one receiving hostname — and the
  // configured ids are compared the way the parser reads the header's:
  // trimmed and case-insensitive. Blank entries configure nothing.
  it('accepts a list of authserv-ids, case- and whitespace-insensitively', () => {
    const lines = block(AR('mx1.test.com; spf=pass'), AR('mx2.test.com; dkim=pass'));
    expect(
      parseAuthenticationHeaders(lines, { authserv: [' MX1.test.com ', 'mx2.test.com'] }),
    ).toMatchObject({ spf: 'pass', dkim: 'pass' });
    expect(parseAuthenticationHeaders(lines, { authserv: ['  ', ''] })).toMatchObject({
      spf: 'pass',
      dkim: 'unknown',
    });
    expect(parseAuthenticationHeaders(lines, { authserv: null }).dkim).toBe('unknown');
  });

  // Conflicting verdicts inside ONE header too: `dmarc=pass; dmarc=fail`
  // cannot be written by an honest server, but it can come from one that
  // copies an unquoted envelope address containing `;` into its header.
  it('lets fail win over pass within one header, whichever comes first', () => {
    expect(parseAuthenticationHeaders(AR('mx; dmarc=pass; dmarc=fail')).dmarc).toBe('fail');
    expect(parseAuthenticationHeaders(AR('mx; dmarc=fail; dmarc=pass')).dmarc).toBe('fail');
    // And a pass is unanimous or nothing: `none` beside it is not a pass.
    expect(parseAuthenticationHeaders(AR('mx; dmarc=none; dmarc=pass')).dmarc).toBe('none');
  });

  // Several DKIM results in one header are several SIGNATURES, and one valid
  // signature is a valid signature (RFC 6376 §6.1). A mailing list breaks the
  // author's and adds its own; reading that as a DKIM failure would put a
  // "fail" on every list message.
  it('reads one passing DKIM signature among several as a pass', () => {
    const status = parseAuthenticationHeaders(
      AR('mx; dkim=fail header.d=author.example; dkim=pass header.d=list.example; dmarc=pass'),
    );
    expect(status.dkim).toBe('pass');
    expect(status.overall).toBe('pass');
    // Without any passing signature, the worst of them stands.
    expect(parseAuthenticationHeaders(AR('mx; dkim=none; dkim=fail')).dkim).toBe('fail');
  });

  // An SPF check of the HELO name gives way to the check of the envelope
  // sender (RFC 7208 §2.3/§2.4) — the identity DMARC aligns on. Some
  // evaluators write both; reading the HELO `none` as the verdict would
  // downgrade every such message.
  it('prefers the envelope-sender SPF result over a HELO-only one', () => {
    expect(
      parseAuthenticationHeaders(
        block(
          AR('mx; spf=none smtp.helo=mail.example.com'),
          AR('mx; spf=pass smtp.mailfrom=example.com'),
        ),
        { authserv: 'mx' },
      ).spf,
    ).toBe('pass');
    // With only a HELO result, that result is the verdict.
    expect(parseAuthenticationHeaders(AR('mx; spf=softfail smtp.helo=mail.example.com')).spf).toBe(
      'softfail',
    );
  });
});

/**
 * The RFC 8601 grammar, piece by piece. A header is text a server fills with
 * free-form comments and quoted values; each case below is a construct that a
 * `split(';')`-and-`includes('=')` reader gets wrong.
 */
describe('parseAuthResultsHeader', () => {
  it('reads the authserv-id and each statement with its properties', () => {
    expect(
      parseAuthResultsHeader(
        ' mx.google.com; dkim=pass header.i=@sarv.com header.s=google; spf=pass smtp.mailfrom=sarv.com',
      ),
    ).toEqual({
      authservId: 'mx.google.com',
      results: [
        {
          method: 'dkim',
          result: 'pass',
          properties: { 'header.i': '@sarv.com', 'header.s': 'google' },
          comments: [],
        },
        {
          method: 'spf',
          result: 'pass',
          properties: { 'smtp.mailfrom': 'sarv.com' },
          comments: [],
        },
      ],
    });
  });

  // Microsoft 365 omits the authserv-id and starts with a statement. Reading
  // `spf=pass …` as the authserv-id would lose the SPF verdict, and a header
  // with no id must never match a configured one.
  it('reads a header with no authserv-id, as Microsoft 365 writes it', () => {
    const header = parseAuthResultsHeader(
      'spf=pass (sender IP is 40.107.1.2) smtp.mailfrom=contoso.com; dkim=pass (signature was verified) header.d=contoso.com;dmarc=pass action=none header.from=contoso.com;compauth=pass reason=100',
    );
    expect(header.authservId).toBeNull();
    expect(header.results.map((r) => `${r.method}=${r.result}`)).toEqual([
      'spf=pass',
      'dkim=pass',
      'dmarc=pass',
      'compauth=pass',
    ]);
    expect(header.results[3]?.properties).toEqual({ reason: '100' });
    // Such a header is believed when it is the topmost and no id is configured…
    expect(parseAuthenticationHeaders(AR('spf=pass; dmarc=pass')).dmarc).toBe('pass');
    // …and never when one is: it names nobody, so it cannot be that server's.
    expect(parseAuthenticationHeaders(AR('spf=pass; dmarc=pass'), { authserv: 'mx' }).dmarc).toBe(
      'unknown',
    );
  });

  // A `;` or `=` inside a comment is not syntax: Gmail's SPF comment alone
  // carries a colon and an address. Comments nest, and a quoted-pair inside
  // one escapes a parenthesis. The comment comes back as text on its
  // statement, and never as a statement or a property.
  it('keeps comments out of the syntax, nested ones included', () => {
    const header = parseAuthResultsHeader(
      'mx.example.com (the MX; dmarc=pass (nested \\) paren) here); spf=fail (google.com: dmarc=pass; x=y) smtp.mailfrom=a.example',
    );
    expect(header).toEqual({
      authservId: 'mx.example.com',
      results: [
        {
          method: 'spf',
          result: 'fail',
          properties: { 'smtp.mailfrom': 'a.example' },
          comments: ['google.com: dmarc=pass; x=y'],
        },
      ],
    });
    // An unterminated comment swallows the rest of the value, as the grammar
    // says. What it swallowed is still the server's text, so it is kept.
    expect(parseAuthResultsHeader('mx; spf=pass (unterminated; dmarc=pass').results).toEqual([
      { method: 'spf', result: 'pass', properties: {}, comments: ['unterminated; dmarc=pass'] },
    ]);
  });

  // The comments are kept because two of the biggest receivers record the
  // client's address in one: without them the origin IP of every Gmail and
  // Microsoft 365 message falls back to the Received trace. Each statement gets
  // its own; the authserv-id's comment and an empty `()` are nobody's. Kept
  // RAW: unescaping `\"` would erase where a quoted envelope address inside
  // the comment ends, which is how origin-ip.ts keeps a sender's words out.
  it('hands each statement its own comments, as written', () => {
    const header = parseAuthResultsHeader(
      'mx.example.com (head); spf=pass (one) smtp.mailfrom=a.example (two (nested)) (); dkim=pass (a \\) b "q\\"x")',
    );
    expect(header.results.map((result) => result.comments)).toEqual([
      ['one', 'two (nested)'],
      ['a \\) b "q\\"x"'],
    ]);
    expect(header.results[0]?.properties).toEqual({ 'smtp.mailfrom': 'a.example' });
  });

  // A `;` inside a quoted value is not a separator either: an envelope address
  // may have a quoted local part, and a reason is a quoted sentence.
  it('keeps quoted strings whole and unquotes them', () => {
    const header = parseAuthResultsHeader(
      'mx; dkim=fail reason="signature; \\"bad\\"" header.d=example.com; spf=pass smtp.mailfrom="john; dmarc=pass"@example.com',
    );
    expect(header.results).toEqual([
      {
        method: 'dkim',
        result: 'fail',
        properties: { reason: 'signature; "bad"', 'header.d': 'example.com' },
        comments: [],
      },
      {
        method: 'spf',
        result: 'pass',
        properties: { 'smtp.mailfrom': 'john; dmarc=pass@example.com' },
        comments: [],
      },
    ]);
  });

  // The optional pieces RFC 8601 allows around the syntax: a version after the
  // authserv-id, a version on the method, whitespace around `=`, a quoted id.
  it('reads versions, spaced `=` signs and a quoted authserv-id', () => {
    expect(
      parseAuthResultsHeader('mx.example.com 1; dkim/1 = pass header.d = example.com'),
    ).toEqual({
      authservId: 'mx.example.com',
      results: [
        { method: 'dkim', result: 'pass', properties: { 'header.d': 'example.com' }, comments: [] },
      ],
    });
    expect(parseAuthResultsHeader('"MX Example"; spf=pass').authservId).toBe('mx example');
    expect(parseAuthResultsHeader('dkim / 1=pass').results[0]?.method).toBe('dkim');
  });

  // The no-result form, an empty id, and junk: none may invent a statement.
  it('reads the "none" form, a missing id and free text as no statement', () => {
    expect(parseAuthResultsHeader('mx.example.com; none')).toEqual({
      authservId: 'mx.example.com',
      results: [],
    });
    expect(parseAuthResultsHeader('; spf=pass').authservId).toBeNull();
    expect(parseAuthResultsHeader('mx; just words; =pass; spf=; ').results).toEqual([]);
  });

  // Property edge cases: a stray word between pairs, a pair with no key, a
  // repeated key (the first wins), and a key that is an Object prototype name,
  // which must stay a plain key and never reach the prototype chain.
  it('skips stray words and keyless pairs, keeps the first of a repeated key', () => {
    const [result] = parseAuthResultsHeader(
      'mx; dmarc=pass stray header.from=a.example =orphan header.from=b.example __proto__=x constructor=y',
    ).results;
    expect(result?.properties['header.from']).toBe('a.example');
    expect(Object.keys(result?.properties ?? {})).toEqual([
      'header.from',
      '__proto__',
      'constructor',
    ]);
    expect(Object.getPrototypeOf(result?.properties)).toBeNull();
    // A trailing backslash inside an unterminated quote is kept as written.
    expect(parseAuthResultsHeader('mx; spf=pass reason="x\\').results[0]?.properties.reason).toBe(
      'x\\',
    );
  });

  // Result lookups must not reach the prototype chain either: a result named
  // after an Object method is unknown, not a function.
  it('reads a result named after an Object property as unknown', () => {
    expect(parseAuthenticationHeaders(AR('mx; dmarc=constructor; spf=__proto__'))).toMatchObject({
      spf: 'unknown',
      dmarc: 'unknown',
    });
  });
});

describe('trustedAuthResults', () => {
  it('returns nothing for an empty block', () => {
    expect(trustedAuthResults(undefined)).toEqual([]);
    expect(trustedAuthResults('')).toEqual([]);
  });

  // What was trusted is exported so a caller can show it, and so `scan` can
  // tell "no verdict worth trusting" (null) from "a trusted server said
  // nothing conclusive" (all unknown).
  it('returns the headers it believed, parsed, topmost first', () => {
    const lines = block(
      AR('evil.example; dmarc=pass'),
      AR('mx.test.com; dmarc=fail'),
      AR('mx.test.com; spf=pass'),
    );
    expect(
      trustedAuthResults(lines, { authserv: 'mx.test.com' }).map((h) => h.results[0]?.method),
    ).toEqual(['dmarc', 'spf']);
    expect(trustedAuthResults(lines).map((h) => h.authservId)).toEqual(['evil.example']);
  });
});
