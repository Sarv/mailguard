import { describe, expect, it } from 'vitest';

import {
  assessLinks,
  assessPhishing,
  linkDomains,
  linkDomainsAllMatch,
  linkMismatches,
  summarizeLinkDomains,
  LINK_DOMAINS_MAX,
  LINK_WRAPPER_DOMAINS,
} from '../src/links.js';

const anchor = (text: string, href: string): string => `<a href="${href}">${text}</a>`;

describe('linkMismatches', () => {
  // Regression: the whole point of the rule. Text names one registrable
  // domain, href goes to another.
  it('finds an anchor whose text names a different domain than its href', () => {
    const found = linkMismatches(anchor('paypal.com', 'https://paypal.secure-login.ru/pay'));
    expect(found).toEqual([{ shown: 'paypal.com', actual: 'secure-login.ru' }]);
  });

  // Regression: subdomains of the SAME registrable domain are not deceptive.
  // Flagging them put warnings on ordinary corporate mail.
  it('does not flag a subdomain of the same registrable domain', () => {
    expect(linkMismatches(anchor('paypal.com', 'https://mail.paypal.com/x'))).toEqual([]);
    expect(linkMismatches(anchor('www.paypal.com', 'https://paypal.com/x'))).toEqual([]);
  });

  // Regression: legitimate marketing wraps every link through an ESP. If
  // those count, the warning fires on most newsletters and stops meaning
  // anything.
  // Regression: an invoice whose amounts link to the biller was scored as three
  // deceptive links ("appears to go to ₹3.2 actually points to cii.in").
  it('does not read a number in the link text as a domain', () => {
    expect(linkMismatches(anchor('₹3.2', 'https://cii.in/invoice/1'))).toEqual([]);
    expect(linkMismatches(anchor('2.58', 'https://cii.in/invoice/1'))).toEqual([]);
    expect(linkMismatches(anchor('136.25', 'https://cii.in/invoice/1'))).toEqual([]);
  });

  // Regression: a sarv.com signature whose "www.sarv.com" link is click-tracked
  // through track.sendclean.net was charged 4 as "a link dressed as your own
  // domain" — on the org's own authenticated mail.
  it('treats the SendClean click tracker as a wrapper', () => {
    expect(
      linkMismatches(
        anchor('www.sarv.com', 'https://track.sendclean.net/c/?u=iuuqt%3B00tbsw%2Fdpn0'),
      ),
    ).toEqual([]);
  });

  it('skips wrapper and tracker domains on either side', () => {
    expect(linkMismatches(anchor('paypal.com', 'https://sendgrid.net/ls/click?u=1'))).toEqual([]);
    expect(linkMismatches(anchor('bit.ly/xyz', 'https://example-shop.com/x'))).toEqual([]);
  });

  it('ignores non-web schemes and unparseable hrefs', () => {
    expect(linkMismatches(anchor('paypal.com', 'mailto:a@evil.ru'))).toEqual([]);
    expect(linkMismatches(anchor('paypal.com', 'javascript:alert(1)'))).toEqual([]);
    expect(linkMismatches(anchor('paypal.com', 'https://'))).toEqual([]);
    expect(linkMismatches('<a>no href</a>')).toEqual([]);
  });

  it('ignores text that names no domain at all', () => {
    expect(linkMismatches(anchor('Click here', 'https://evil.ru/x'))).toEqual([]);
  });

  it('de-duplicates identical pairs and caps the list at three', () => {
    const same = anchor('paypal.com', 'https://evil.ru/a').repeat(4);
    expect(linkMismatches(same)).toHaveLength(1);
    const many = ['a.com', 'b.com', 'c.com', 'd.com', 'e.com']
      .map((d) => anchor(d, 'https://evil.ru/x'))
      .join('');
    expect(linkMismatches(many)).toHaveLength(3);
  });

  it('is empty for absent or empty html', () => {
    expect(linkMismatches(null)).toEqual([]);
    expect(linkMismatches(undefined)).toEqual([]);
    expect(linkMismatches('')).toEqual([]);
  });

  it('takes only the first mismatching domain named in one anchor', () => {
    const found = linkMismatches(anchor('paypal.com and stripe.com', 'https://evil.ru/x'));
    expect(found).toHaveLength(1);
  });
});

describe('assessLinks', () => {
  it('phrases each mismatch as a caution', () => {
    const reasons = assessLinks(anchor('paypal.com', 'https://evil.ru/x'));
    expect(reasons).toHaveLength(1);
    expect(reasons[0]!.kind).toBe('link');
    expect(reasons[0]!.severity).toBe('caution');
    expect(reasons[0]!.text).toContain('paypal.com');
    expect(reasons[0]!.text).toContain('evil.ru');
  });
});

describe('linkMismatches — quoted history', () => {
  // Regression: `linkDomainsAllMatch` stopped counting quoted links, and this
  // check must NOT follow it. A forged quoted chain is a real phishing
  // technique, so a link whose text names one domain and whose href goes to
  // another is worth pointing at wherever in the thread it sits.
  it('still finds a deceptive link inside the quoted thread', () => {
    const html = `<blockquote>${anchor('paypal.com', 'https://paypal.secure-login.ru/pay')}</blockquote>`;
    expect(linkMismatches(html)).toEqual([{ shown: 'paypal.com', actual: 'secure-login.ru' }]);
  });
});

describe('linkDomainsAllMatch', () => {
  it('is true when every link stays on the sender’s own domain', () => {
    const html =
      anchor('Account', 'https://mail.example.net/a') + anchor('Help', 'https://example.net/h');
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(true);
  });

  it('is false when any link points away', () => {
    const html =
      anchor('Account', 'https://example.net/a') + anchor('Track', 'https://tracker.io/t');
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(false);
  });

  // Regression: a reply carries the mail it answers, and that mail's links
  // belong to the other party. Counting them cost `verified` to every message
  // after the first in a thread — a green shield on the opener and a hollow
  // one on every reply, for links their sender neither wrote nor is shown.
  it('ignores links inside quoted history', () => {
    const html = `${anchor('Our docs', 'https://example.net/docs')}<blockquote>${anchor('Their portal', 'https://other.example/login')}</blockquote>`;
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(true);
  });

  // Regression: clients that wrap the history in a plain div rather than a
  // blockquote must be read the same way, or whether a reply can be verified
  // depends on which client the OTHER party happened to use.
  it('ignores them in a client quote container too, not only a blockquote', () => {
    const quoted = anchor('Their portal', 'https://other.example/login');
    expect(linkDomainsAllMatch(`<div class="gmail_quote">${quoted}</div>`, 'example.net')).toBe(
      true,
    );
  });

  // Regression: the exemption is for the QUOTE, not for the message. A blanket
  // ignore would hand `verified` to a body whose own links point anywhere at
  // all, as long as it also quoted something.
  it('still fails on an off-domain link in the sender’s own words', () => {
    const html = `${anchor('Click', 'https://tracker.io/t')}<blockquote>${anchor('Home', 'https://example.net/h')}</blockquote>`;
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(false);
  });

  it('treats a body with no links, and no body at all, as staying home', () => {
    expect(linkDomainsAllMatch('<p>Just text</p>', 'example.net')).toBe(true);
    expect(linkDomainsAllMatch(null, 'example.net')).toBe(true);
    expect(linkDomainsAllMatch('', 'example.net')).toBe(true);
  });

  it('ignores non-web schemes', () => {
    expect(linkDomainsAllMatch(anchor('Mail us', 'mailto:a@example.net'), 'example.net')).toBe(
      true,
    );
  });

  // Regression: the claim being made is "everything here stays home". With no
  // sender domain there is nothing to compare against, so it must not be
  // asserted — this feeds the top `verified` level.
  it('is false when the sender domain is unknown', () => {
    expect(linkDomainsAllMatch(anchor('x', 'https://example.net/a'), null)).toBe(false);
  });
});

describe('summarizeLinkDomains', () => {
  // Regression: the boolean above can decide a level but cannot explain it.
  // Two messages with an identical row of green ticks showed different
  // badges, and nothing a reader could see said why. This is the why.
  it('counts the sender’s links and names the ones that leave', () => {
    const html =
      anchor('Home', 'https://example.net/h') +
      anchor('The doc', 'https://docs.google.com/d/1') +
      anchor('Status', 'https://status.io/s');
    expect(summarizeLinkDomains(html, 'example.net')).toEqual({
      linkCount: 3,
      offDomain: [
        { actual: 'google.com', shown: [] },
        { actual: 'status.io', shown: [] },
      ],
    });
  });

  // Regression: zero links and "every link stayed home" both permit the top
  // level, and reporting them with one sentence told a reader a check had
  // passed that never ran.
  it('separates a message with no links from one whose links all stay home', () => {
    expect(summarizeLinkDomains('<p>Just text</p>', 'example.net')).toEqual({
      linkCount: 0,
      offDomain: [],
    });
    expect(summarizeLinkDomains(anchor('Home', 'https://example.net/h'), 'example.net')).toEqual({
      linkCount: 1,
      offDomain: [],
    });
  });

  // Regression: a trust rule is keyed by the pair the reader SAW, so the
  // shown domains have to travel with the link or the rule cannot be found.
  it('carries the domains the text named, for the trust-rule key', () => {
    const html = anchor('paypal.com', 'https://evil.ru/x');
    expect(summarizeLinkDomains(html, 'example.net').offDomain).toEqual([
      { actual: 'evil.ru', shown: ['paypal.com'] },
    ]);
  });

  // Regression: same exemption as the boolean it backs — a reply's quoted
  // history is the other party's mail, and counting it made every reply in a
  // thread look like it linked away.
  it('ignores quoted history and non-web schemes', () => {
    const html = `${anchor('Mail us', 'mailto:a@example.net')}<blockquote>${anchor('Portal', 'https://other.example/x')}</blockquote>`;
    expect(summarizeLinkDomains(html, 'example.net')).toEqual({ linkCount: 0, offDomain: [] });
  });

  // Regression: an href with no registrable domain (a bare IP) has nowhere to
  // put its name, and dropping it would let the one link most worth reporting
  // report nothing.
  it('falls back to the host for a link with no registrable domain', () => {
    expect(
      summarizeLinkDomains(anchor('Pay', 'https://203.0.113.9/p'), 'example.net').offDomain,
    ).toEqual([{ actual: '203.0.113.9', shown: [] }]);
  });
});

describe('linkDomainsAllMatch — vetted pairs', () => {
  const html = anchor('paypal.com', 'https://evil.ru/x');

  // Regression: the doc comment promised vetted pairs were forgiven here and
  // the code had no way to ask. A reader who trusted the pair watched the
  // message climb out of caution and stop one rung short for the very link
  // they had just forgiven.
  it('forgives a link the caller vouches for', () => {
    expect(linkDomainsAllMatch(html, 'example.net', (link) => link.actual === 'evil.ru')).toBe(
      true,
    );
  });

  it('still fails when the predicate declines, or when there is none', () => {
    expect(linkDomainsAllMatch(html, 'example.net', () => false)).toBe(false);
    expect(linkDomainsAllMatch(html, 'example.net')).toBe(false);
  });
});

describe('assessPhishing', () => {
  it('is none for an ordinary message', () => {
    const result = assessPhishing({
      fromName: 'Alice',
      fromAddress: 'alice@example.net',
      html: anchor('example.net', 'https://example.net/x'),
    });
    expect(result).toEqual({ level: 'none', reasons: [] });
  });

  it('is caution for a deceptive link alone', () => {
    const result = assessPhishing({
      fromName: 'Alice',
      fromAddress: 'alice@example.net',
      html: anchor('paypal.com', 'https://evil.ru/x'),
    });
    expect(result.level).toBe('caution');
  });

  // Regression: danger must win over caution when both are present, or a
  // spoofed sender is reported with the softer of the two colours.
  it('is danger when the sender name impersonates, even alongside a caution', () => {
    const result = assessPhishing({
      fromName: 'PayPal <service@paypal.com>',
      fromAddress: 'billing@evil.ru',
      html: anchor('stripe.com', 'https://elsewhere.io/x'),
    });
    expect(result.level).toBe('danger');
    expect(result.reasons.length).toBeGreaterThan(1);
  });
});

describe('assessPhishing — a borrowed brand name', () => {
  // Regression: the renderer's banner reads this, and it must go red on a
  // name with no domain in it — the case the domain rule cannot see.
  it('is danger when the sender name borrows a protected brand, with no domain in it', () => {
    const result = assessPhishing({
      fromName: 'DocuSign',
      fromAddress: 'docs@evil.ru',
      html: null,
    });
    expect(result.level).toBe('danger');
    expect(result.reasons[0]?.kind).toBe('brand');
  });
});

describe('LINK_WRAPPER_DOMAINS', () => {
  // Regression: entries must be registrable domains. A full URL or a
  // subdomain never matches what `registrableDomain` returns, so it would be
  // a silently dead entry.
  it('holds bare registrable domains only', () => {
    for (const domain of LINK_WRAPPER_DOMAINS) {
      expect(domain, domain).not.toMatch(/^https?:|\/|\s/);
      expect(domain, domain).toBe(domain.toLowerCase());
      expect(domain, domain).toContain('.');
    }
  });
});

describe('linkDomains', () => {
  it('has nothing to say about an empty body', () => {
    expect(linkDomains(null)).toEqual([]);
    expect(linkDomains(undefined)).toEqual([]);
    expect(linkDomains('   \n  ')).toEqual([]);
  });

  it('reduces every destination to its registrable domain', () => {
    expect(linkDomains('<a href="https://mail.evil.ru/go?x=1">click</a>')).toEqual(['evil.ru']);
  });

  // Regression: a phish is rarely SENT from a listed domain; it links to one.
  // `<area>` and `<form action>` are the two destinations that are never
  // anchors, and the deceptive-link check does not read either.
  it('reads image maps and form actions, not just anchors', () => {
    const body =
      '<a href="https://one.example">one</a>' +
      '<area href="https://two.example">' +
      '<form action="https://three.example"></form>';
    expect(linkDomains(body)).toEqual(['one.example', 'two.example', 'three.example']);
  });

  // Regression: a reply carries the mail it answers. Charging the forwarder
  // for the phish they forwarded is the mistake this exists to avoid.
  it('leaves quoted history out, unless asked for it', () => {
    const body =
      '<p><a href="https://mine.example">mine</a></p>' +
      '<blockquote><a href="https://theirs.example">theirs</a></blockquote>';
    expect(linkDomains(body)).toEqual(['mine.example']);
    expect(linkDomains(body, { includeQuoted: true })).toEqual(['mine.example', 'theirs.example']);
  });

  // Regression: marketing mail routes every link through an ESP or a
  // shortener. Without this the cap fills with sendgrid.net and t.co before a
  // real destination is reached — and the day one of those lands on a
  // blocklist, every newsletter that month is charged for it.
  it('skips the carriers and keeps the destinations', () => {
    const body =
      '<a href="https://u123.ct.sendgrid.net/ls/click?u=x">offer</a>' +
      '<a href="https://t.co/abc">more</a>' +
      '<a href="https://shop.example/sale">shop</a>';
    expect(linkDomains(body)).toEqual(['shop.example']);
    expect(linkDomains(body, { includeWrappers: true })).toEqual([
      'sendgrid.net',
      't.co',
      'shop.example',
    ]);
  });

  it('skips the domains it was told to skip, whatever their case', () => {
    const body = '<a href="https://sender.example/a">a</a><a href="https://other.example">b</a>';
    expect(linkDomains(body, { exclude: ['Sender.Example', null, undefined, ' '] })).toEqual([
      'other.example',
    ]);
  });

  it('reports each domain once, in the order the reader would meet it', () => {
    const body =
      '<a href="https://a.example/1">1</a>' +
      '<a href="https://b.example/1">2</a>' +
      '<a href="https://a.example/2">3</a>';
    expect(linkDomains(body)).toEqual(['a.example', 'b.example']);
  });

  // Regression: a spam blast links to a thousand things. An unbounded list
  // would turn one message into a thousand network lookups.
  it('stops at the cap', () => {
    const many = Array.from(
      { length: LINK_DOMAINS_MAX + 5 },
      (_unused, index) => `<a href="https://d${index}.example">x</a>`,
    ).join('');
    expect(linkDomains(many)).toHaveLength(LINK_DOMAINS_MAX);
    expect(linkDomains(many, { max: 3 })).toEqual(['d0.example', 'd1.example', 'd2.example']);
    expect(linkDomains(many, { max: 0 })).toEqual([]);
    expect(linkDomains(many, { max: -1 })).toEqual([]);
  });

  // Regression: `mailto:`, `tel:` and `#anchor` are not places to be sent, and
  // a bare IP has no registrable domain to ask a blocklist about.
  it('ignores what cannot be looked up', () => {
    const body =
      '<a href="mailto:x@evil.ru">mail</a>' +
      '<a href="tel:+15550100">call</a>' +
      '<a href="#top">top</a>' +
      '<a href="http://203.0.113.9/login">ip</a>' +
      '<a href="not a url">junk</a>';
    expect(linkDomains(body)).toEqual([]);
  });

  // Regression: an href split by entities or quoted oddly is exactly the shape
  // a spammer reaches for. This is why the body is parsed rather than
  // pattern-matched.
  it('reads an href the way a mail client would, not the way a regex would', () => {
    expect(linkDomains('<a href="https://evil.example/a&amp;b">paypal.com</a>')).toEqual([
      'evil.example',
    ]);
    expect(linkDomains('<a href=https://bare.example/path>x</a>')).toEqual(['bare.example']);
  });

  // Regression: a bare hostname with no public suffix has no registrable
  // domain to ask a blocklist about, and asking one about `localhost` would
  // leak the fact that the mail was opened.
  it('ignores a host that is not a public domain', () => {
    expect(linkDomains('<a href="https://localhost/x">l</a>')).toEqual([]);
  });

  it('reads a plain-text body with the same rules', () => {
    expect(linkDomains('see https://shop.example/sale. and https://t.co/x')).toEqual([
      'shop.example',
    ]);
  });

  // Regression: a URL typed into an HTML body and never wrapped in an anchor
  // is still a link — every mail client autolinks it. Reading only the markup
  // would let the same address count in a plain-text message and vanish in an
  // HTML one, which is a one-line evasion.
  it('reads a bare URL written into an HTML body', () => {
    expect(linkDomains('<p>go to https://evil.ru/login now</p>')).toEqual(['evil.ru']);
  });

  // Regression: the visible text of an HTML body already has quoted history
  // and invisible text removed, so the bare-URL path inherits both exclusions
  // rather than reopening them.
  it('does not let a bare URL in quoted history back in', () => {
    const body = '<p>hi</p><blockquote>see https://theirs.example/x</blockquote>';
    expect(linkDomains(body)).toEqual([]);
    expect(linkDomains(body, { includeQuoted: true })).toEqual(['theirs.example']);
  });
});

describe('assessPhishing — a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };
  it('is danger for a brand only the caller protects', () => {
    const input = { fromName: 'Acme Corp', fromAddress: 'x@evil.example', html: null };
    expect(assessPhishing(input).level).toBe('none');
    expect(assessPhishing({ ...input, brands: [ACME] }).level).toBe('danger');
  });
});
