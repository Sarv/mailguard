import { describe, expect, it } from 'vitest';

import {
  extractOriginIp,
  isPublicIp,
  normalizeIp,
  originIpFromAuthHeaders,
  originIpFromReceived,
} from '../src/headers/origin-ip.js';

/**
 * The connecting client's IP, recorded per message for the reputation stage.
 *
 * What this protects: a blocklist lookup on the WRONG address is worse than
 * none — it clears a spammer (we asked about our own relay) or condemns a
 * neighbour (we asked about the recipient's provider). So the tests pin which
 * address wins from real header shapes (Gmail, Microsoft 365, Postfix,
 * qmail), and that no private or reserved address ever comes out.
 */

// Genuinely public addresses. The RFC 5737 documentation ranges (203.0.113/24
// etc.) are classified RESERVED by ipaddr.js — correctly — so they cannot be
// used as the "public" fixture here.
const GOOGLE = '209.85.220.41';
const M365 = '40.107.22.33';
const HOST = '185.199.108.1';
const GOOGLE6 = '2a00:1450:4864:20::32a';

describe('normalizeIp', () => {
  it('strips Received-line decoration and canonicalises', () => {
    expect(normalizeIp(`[${GOOGLE}]`)).toBe(GOOGLE);
    expect(normalizeIp(`IPv6:${GOOGLE6}`)).toBe(GOOGLE6);
    expect(normalizeIp(`[IPv6:${GOOGLE6}]`)).toBe(GOOGLE6);
    expect(normalizeIp(` ${HOST} `)).toBe(HOST);
  });

  it('folds an IPv4-mapped IPv6 address to its IPv4', () => {
    expect(normalizeIp(`::ffff:${HOST}`)).toBe(HOST);
  });

  // Hostnames, short forms and out-of-range octets are not addresses. ipaddr.js
  // would accept `1.2.3` and octal forms; a mail server never writes those.
  it('rejects anything that is not a dotted quad or an IPv6 literal', () => {
    for (const bad of [
      'mail.example.com',
      '1.2.3',
      '999.1.1.1',
      '0x7f.1',
      'port=25',
      '',
      null,
      undefined,
    ]) {
      expect(normalizeIp(bad)).toBeNull();
    }
  });
});

describe('isPublicIp', () => {
  it('accepts routable unicast addresses, v4 and v6', () => {
    expect(isPublicIp(GOOGLE)).toBe(true);
    expect(isPublicIp(GOOGLE6)).toBe(true);
    expect(isPublicIp(`::ffff:${HOST}`)).toBe(true);
  });

  // The receiving side's own plumbing. A blocklist has nothing to say about
  // these, and returning one would make the reputation stage look up nothing.
  it('rejects private, loopback, link-local, carrier-NAT, reserved and mapped-private addresses', () => {
    for (const bad of [
      '10.0.0.1',
      '172.16.5.5',
      '192.168.1.1',
      '127.0.0.1',
      '169.254.1.1',
      '100.64.0.1',
      '203.0.113.5',
      '0.0.0.0',
      '::1',
      'fe80::1',
      'fc00::1',
      '::ffff:10.0.0.1',
      '2002:c000:0204::',
    ]) {
      expect(isPublicIp(bad), bad).toBe(false);
    }
  });
});

/** One header line, as `extractAuthHeaderBlock` hands it over. */
const AR = (value: string): string => `Authentication-Results: ${value}`;
const block = (...lines: string[]): string => lines.join('\n');

describe('originIpFromAuthHeaders', () => {
  it('reads "sender IP is" from a Microsoft 365 Authentication-Results', () => {
    expect(
      originIpFromAuthHeaders(
        AR(`spf=pass (sender IP is ${M365}) smtp.mailfrom=sarv.com; dkim=pass`),
      ),
    ).toBe(M365);
  });

  it('reads the SPF comment "designates x as permitted sender", as Gmail writes it', () => {
    expect(
      originIpFromAuthHeaders(
        AR(
          `mx.google.com; spf=pass (google.com: domain of a@b.c designates ${GOOGLE} as permitted sender) smtp.mailfrom=a@b.c`,
        ),
      ),
    ).toBe(GOOGLE);
  });

  // Regression: spam is the mail whose SPF FAILS. Gmail words a failure, a
  // softfail and a neutral differently from a pass; the old reader knew only
  // the pass wording and got the address from Gmail's Received-SPF instead,
  // which is no longer read. Missing these sends exactly the mail that most
  // needs a blocklist lookup to the Received trace.
  it('reads Gmail’s failing and neutral SPF wordings too', () => {
    for (const comment of [
      `google.com: domain of x@evil.example does not designate ${HOST} as permitted sender`,
      `google.com: domain of transitioning x@evil.example does not designate ${HOST} as permitted sender`,
      `google.com: ${HOST} is neither permitted nor denied by best guess record for domain of x@evil.example`,
    ]) {
      expect(
        originIpFromAuthHeaders(AR(`mx.google.com; spf=softfail (${comment}) smtp.mailfrom=x`)),
        comment,
      ).toBe(HOST);
    }
  });

  // Gmail's SPF `none` names no address — the domain publishes no record, so
  // nothing was checked against one. That is "no address here", not an error.
  it('reads nothing from an SPF comment that names no address', () => {
    expect(
      originIpFromAuthHeaders(
        AR(
          'mx.google.com; spf=none (google.com: x@evil.example does not designate permitted sender hosts) smtp.mailfrom=x@evil.example',
        ),
      ),
    ).toBeNull();
  });

  it('reads RFC 8601 policy.iprev= and the smtp.remote-ip= Exim and Fastmail write', () => {
    expect(
      originIpFromAuthHeaders(AR(`mx; iprev=pass policy.iprev=${HOST} smtp.remote-ip=${HOST}`)),
    ).toBe(HOST);
    expect(originIpFromAuthHeaders(AR(`mx; iprev=pass policy.iprev=${HOST}`))).toBe(HOST);
    expect(
      originIpFromAuthHeaders(
        AR(`mx; spf=pass smtp.mailfrom=a.example; iprev=pass (rdns) smtp.remote-ip=${GOOGLE6}`),
      ),
    ).toBe(GOOGLE6);
  });

  // An SPF comment in Received-SPF style. Inside a comment `;` is text, not a
  // separator, so the walk must end the address at it rather than read
  // `1.2.3.4;` as no address at all.
  it('reads client-ip= written inside an SPF comment', () => {
    expect(
      originIpFromAuthHeaders(
        AR(`mx; spf=pass (client-ip=${HOST}; helo=mta.example.net) smtp.mailfrom=a.example`),
      ),
    ).toBe(HOST);
  });

  it('skips a private candidate and takes the next public one in the same header', () => {
    expect(
      originIpFromAuthHeaders(
        AR(`mx; iprev=pass smtp.remote-ip=10.1.2.3; spf=pass (sender IP is ${M365})`),
      ),
    ).toBe(M365);
  });

  // Regression: only the checks ABOUT the client name it. A DKIM or DMARC
  // statement judges the message, and an address in one is not something
  // the server observed about the connection.
  it('reads no address from a header without an SPF or iprev result', () => {
    expect(
      originIpFromAuthHeaders(
        AR(`mx; dkim=pass (sender IP is ${HOST}) smtp.remote-ip=${HOST}; dmarc=pass`),
      ),
    ).toBeNull();
  });

  // Look-alike phrasings must not read as an address, and none may let a
  // word that is not an address through.
  it('ignores phrasings that only resemble the real ones', () => {
    for (const comment of [
      `domain designates ${HOST} as primary`,
      `sender ip address is ${HOST}`,
      `sender ip was ${HOST}`,
      `sender ip is`,
      `${HOST} is not neither`,
      `designate ${HOST} as permitted-sender-hosts`,
    ]) {
      expect(originIpFromAuthHeaders(AR(`mx; spf=pass (${comment})`)), comment).toBeNull();
    }
  });

  it('is null when the block names no public address', () => {
    expect(originIpFromAuthHeaders(AR('mx; dkim=pass; client-ip=127.0.0.1'))).toBeNull();
    expect(originIpFromAuthHeaders(AR('mx; spf=pass (sender IP is 127.0.0.1)'))).toBeNull();
    expect(originIpFromAuthHeaders('')).toBeNull();
    expect(originIpFromAuthHeaders(undefined)).toBeNull();
  });
});

/**
 * Forged addresses: the reason the reader above is as narrow as it is.
 *
 * The origin IP is what every DNS blocklist is asked about. Earlier releases
 * took the first `client-ip=` ANYWHERE in the authentication block, before any
 * other wording, so a spam source on Spamhaus could type
 * `Received-SPF: pass client-ip=<a clean address>` into its own message and
 * the blocklists were asked about the clean address instead — the reputation
 * stage, cleared by the sender.
 */
describe('originIpFromAuthHeaders: forged addresses', () => {
  // A clean public address a listed sender would rather be judged by.
  const FORGED = '1.1.1.1';
  // The real verdict: Gmail's receiving server, which saw the spammer at HOST.
  const REAL = AR(
    `mx.google.com; spf=softfail (google.com: domain of transitioning x@evil.example does not designate ${HOST} as permitted sender) smtp.mailfrom=x@evil.example`,
  );

  // Regression: THE bug. The sender's own Received-SPF sits below everything
  // the receiving server prepended, and was read before the real header.
  it('ignores a forged Received-SPF below the real header', () => {
    const lines = block(REAL, `Received-SPF: pass (sender) client-ip=${FORGED};`);
    for (const options of [{}, { authserv: 'mx.google.com' }]) {
      expect(originIpFromAuthHeaders(lines, options)).toBe(HOST);
    }
  });

  // A Received-SPF above the real header is no better: a server that writes
  // no Received-SPF of its own leaves the sender's as the topmost one, and
  // no position rule could tell the two apart across MTAs.
  it('ignores a forged Received-SPF above the real header', () => {
    const lines = block(
      `Received-SPF: pass (mx.example.com: domain of x designates ${FORGED} as permitted sender) client-ip=${FORGED};`,
      AR(`spf=fail (sender IP is ${M365}) smtp.mailfrom=evil.example`),
    );
    expect(originIpFromAuthHeaders(lines)).toBe(M365);
  });

  // With no trusted header at all, a Received-SPF — real or not — names no
  // author, so it supplies nothing and the trace answers (see extractOriginIp).
  it('reads nothing from Received-SPF alone', () => {
    expect(originIpFromAuthHeaders(`Received-SPF: pass client-ip=${FORGED};`)).toBeNull();
  });

  // Regression: an ARC header is a copy sealed for the NEXT hop, prepended
  // like any other, so a sender's copy can sit on top. Its address was read
  // as though our server had written it.
  it('ignores a forged client address in an ARC-Authentication-Results', () => {
    const arc = `ARC-Authentication-Results: i=1; mx.google.com; spf=pass (google.com: domain of x designates ${FORGED} as permitted sender) smtp.mailfrom=x; iprev=pass smtp.remote-ip=${FORGED}`;
    for (const options of [{}, { authserv: 'mx.google.com' }]) {
      expect(originIpFromAuthHeaders(block(arc, REAL), options)).toBe(HOST);
      expect(originIpFromAuthHeaders(arc, options)).toBeNull();
    }
  });

  // The verdict's own rule, reused: with no authserv-id the topmost
  // Authentication-Results is the receiving server's, and a forgery below it
  // is not read; with one, a forgery above it naming another id is not read.
  it('reads the same header the verdict is read from', () => {
    const forged = AR(`evil.example; spf=pass (sender IP is ${FORGED})`);
    expect(originIpFromAuthHeaders(block(REAL, forged))).toBe(HOST);
    expect(originIpFromAuthHeaders(block(forged, REAL), { authserv: 'mx.google.com' })).toBe(HOST);
  });

  // Regression: a forgery that copies the receiving server's authserv-id,
  // below a real header that names no address (Gmail's SPF `none`). RFC 8601
  // §5 says the server strips it; not every server does. Reading "the first
  // trusted header that names an address" would hand the forgery the answer.
  it('does not look below the server’s own header for an address it did not name', () => {
    const lines = block(
      AR(
        'mx.google.com; spf=none (google.com: x does not designate permitted sender hosts) smtp.mailfrom=x',
      ),
      AR(`mx.google.com; spf=pass (sender IP is ${FORGED}); iprev=pass smtp.remote-ip=${FORGED}`),
    );
    expect(originIpFromAuthHeaders(lines, { authserv: 'mx.google.com' })).toBeNull();
  });

  // Servers that write one header per filter: a DKIM-only header on top says
  // nothing about the client, so the SPF filter's header below it is the one
  // read.
  it('reads the topmost trusted header that checked the client', () => {
    const lines = block(
      AR('mx.test.com; dkim=pass header.d=example.com'),
      AR(`mx.test.com; spf=pass (sender IP is ${M365}) smtp.mailfrom=example.com`),
    );
    expect(originIpFromAuthHeaders(lines, { authserv: 'mx.test.com' })).toBe(M365);
  });

  // Regression: an envelope sender's local part may be a quoted string with
  // spaces, and Gmail copies the envelope sender into its own comment. Read as
  // words, it would put a phrase of the sender's choosing in the server's
  // mouth — ahead of the real address in Gmail's pass/fail wording, and
  // behind it in the neutral one. Quoted stretches are not read at all, and
  // an escaped quote inside one does not end it.
  it('does not read an address out of a quoted envelope sender in the comment', () => {
    const local = `"x designates ${FORGED} as permitted sender \\" sender IP is ${FORGED}"@evil.example`;
    for (const comment of [
      `google.com: domain of ${local} designates ${HOST} as permitted sender`,
      `google.com: ${HOST} is neither permitted nor denied by best guess record for domain of ${local}`,
    ]) {
      expect(
        originIpFromAuthHeaders(AR(`mx.google.com; spf=neutral (${comment}) smtp.mailfrom=x`)),
        comment,
      ).toBe(HOST);
    }
  });

  // KNOWN GAP, pinned so nobody mistakes it for an accident — the same one
  // the verdict has. With no authserv-id the topmost Authentication-Results is
  // believed, and a sender's can only be on top when the receiving server
  // writes none of its own (or appends). Configuring `authserv` closes it.
  it('LIMITATION: without an authserv-id, believes whatever Authentication-Results is on top', () => {
    expect(originIpFromAuthHeaders(AR(`evil.example; spf=pass (sender IP is ${FORGED})`))).toBe(
      FORGED,
    );
    expect(
      originIpFromAuthHeaders(AR(`evil.example; spf=pass (sender IP is ${FORGED})`), {
        authserv: 'mx.google.com',
      }),
    ).toBeNull();
  });
});

describe('originIpFromReceived', () => {
  it('skips Gmail’s internal "by" hop and reads the bracketed address of the first "from" hop', () => {
    expect(
      originIpFromReceived([
        'by 2002:a05:6a00:1a1c:b0:1d1:6d5c:6b7f with SMTP id q28csp123; Thu, 9 Oct 2025 01:53:20 -0700 (PDT)',
        `from mail-sor-f41.google.com (mail-sor-f41.google.com. [${GOOGLE}]) by mx.google.com with SMTPS id abc`,
      ]),
    ).toBe(GOOGLE);
  });

  // Microsoft writes the address bare in parentheses, and the `by` side has
  // one too — only the `from` side is the client being judged.
  it('reads the parenthesised address of a Microsoft hop and ignores the "by" side', () => {
    expect(
      originIpFromReceived([
        `from mail.sender.example (${HOST}) by AM0PR01.mail.protection.outlook.com (${M365}) with Microsoft SMTP Server`,
      ]),
    ).toBe(HOST);
  });

  it('skips a loopback content-filter hop to reach the external one', () => {
    expect(
      originIpFromReceived([
        'from localhost (localhost [127.0.0.1]) by mail.sarv.com (Postfix) with ESMTP id 1',
        `from mta.example.net (unknown [${HOST}]) by mail.sarv.com (Postfix) with ESMTPS id 2`,
      ]),
    ).toBe(HOST);
  });

  it('reads the bracket-first and IPv6 forms', () => {
    expect(
      originIpFromReceived([`from [${HOST}] (port=25 helo=mta.example.net) by mail.sarv.com`]),
    ).toBe(HOST);
    expect(
      originIpFromReceived([
        `from mail-x.google.com (mail-x.google.com. [IPv6:${GOOGLE6}]) by mx.google.com`,
      ]),
    ).toBe(GOOGLE6);
  });

  // A hostname that starts with a dotted quad (reverse-DNS style names) is a
  // hostname, not an address. Tokenising, rather than substring-matching,
  // is what keeps it out.
  it('does not mistake a dotted-quad hostname for an address', () => {
    expect(
      originIpFromReceived([
        `from ${HOST}.static.example.net (unknown [10.0.0.9]) by mail.sarv.com`,
      ]),
    ).toBeNull();
  });

  // Regression: `;` ends the `from` clause and begins the timestamp. If the
  // walk ran past it, a dotted quad appearing in a date comment or in the
  // trailing `envelope-from`/`id` section would be reported as the sending
  // host — an address the sender can choose, attributed as if the receiving
  // MTA had observed it. The first case proves the token carrying the `;` is
  // still read up to it; the second proves nothing beyond it is.
  it('stops at the semicolon that ends the clause, but still reads the token carrying it', () => {
    expect(
      originIpFromReceived([`from mta.example.net ([${HOST}]); 9 Oct 2025 08:53:20 -0000`]),
    ).toBe(HOST);
    expect(
      originIpFromReceived([
        `from mta.example.net; 9 Oct 2025 08:53:20 -0000 (relayed via ${HOST})`,
      ]),
    ).toBeNull();
  });

  it('ignores lines that do not start with "from", such as qmail’s, and is null when nothing qualifies', () => {
    expect(
      originIpFromReceived(['(qmail 12345 invoked from network); 9 Oct 2025 08:53:20 -0000']),
    ).toBeNull();
    expect(originIpFromReceived([])).toBeNull();
    expect(originIpFromReceived(null)).toBeNull();
  });
});

describe('extractOriginIp', () => {
  it('prefers the receiving server’s own address over the Received trace', () => {
    expect(
      extractOriginIp({
        authHeaders: AR(`spf=pass (sender IP is ${M365}) smtp.mailfrom=a.example`),
        received: [`from x (x [${HOST}]) by y`],
      }),
    ).toBe(M365);
  });

  // Regression: the end-to-end form of the forgery. With no trusted header
  // naming an address, a Received-SPF the sender wrote used to beat the trace
  // the receiving server wrote; now the trace answers.
  it('falls back to the Received trace over a Received-SPF, real or forged', () => {
    expect(
      extractOriginIp({
        authHeaders: `Received-SPF: pass client-ip=1.1.1.1;`,
        received: [`from x (x [${HOST}]) by y`],
      }),
    ).toBe(HOST);
  });

  // The authserv-id reaches the header choice: without it, the address
  // would come from whichever header happens to be on top.
  it('reads only the configured server’s header when an authserv-id is passed', () => {
    const sources = {
      authHeaders: block(
        AR('evil.example; spf=pass (sender IP is 1.1.1.1)'),
        AR(`mx.test.com; spf=fail (sender IP is ${M365})`),
      ),
      received: [`from x (x [${HOST}]) by y`],
    };
    expect(extractOriginIp({ ...sources, authserv: 'mx.test.com' })).toBe(M365);
    expect(extractOriginIp({ ...sources, authserv: ['mx.other.example'] })).toBe(HOST);
  });

  it('falls back to the Received trace when the SPF headers name nothing', () => {
    expect(
      extractOriginIp({
        authHeaders: 'Authentication-Results: mx; dkim=pass',
        received: [`from x (x [${HOST}]) by y`],
      }),
    ).toBe(HOST);
    expect(
      extractOriginIp({ authHeaders: undefined, received: [`from x (x [${HOST}]) by y`] }),
    ).toBe(HOST);
  });

  it('is null when neither source names a public address', () => {
    expect(extractOriginIp({ authHeaders: undefined, received: null })).toBeNull();
    expect(
      extractOriginIp({
        authHeaders: '',
        received: ['from localhost (localhost [127.0.0.1]) by x'],
      }),
    ).toBeNull();
  });
});

describe('normalizeIp: decoration that strips to nothing', () => {
  // `[]` and a bare `IPv6:` prefix appear in malformed Received lines. They
  // must read as "not an address", not reach the parsers as an empty string.
  it('is null when the brackets or prefix were the whole token', () => {
    expect(normalizeIp('[]')).toBeNull();
    expect(normalizeIp('IPv6:')).toBeNull();
  });
});
