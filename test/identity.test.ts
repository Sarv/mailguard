import { describe, expect, it } from 'vitest';

import {
  assessSender,
  brandOwningDomain,
  brandsNamedIn,
  domainCarriesBrandName,
  domainOfAddress,
  domainsInText,
  impersonatedBrand,
  registrableDomain,
  PROTECTED_BRANDS,
} from '../src/identity.js';

/**
 * Display-name impersonation — one rule for the shield and the spam filter.
 *
 * What this protects: `support@paypal.com <attacker@evil.ru>` is the classic
 * phish. These cases moved here from the renderer's phishing tests when the
 * logic moved into core; they pin BOTH sides — the spoof is caught, and an
 * ordinary human name, a brand word without a domain, or the sender's own
 * subdomain is not. A false positive here puts a red shield on a colleague.
 */
describe('registrableDomain', () => {
  it('collapses subdomains to eTLD+1, including multi-part TLDs', () => {
    expect(registrableDomain('mail.paypal.com')).toBe('paypal.com');
    expect(registrableDomain('a.b.company.co.uk')).toBe('company.co.uk');
    expect(registrableDomain(' MAIL.PayPal.com ')).toBe('paypal.com');
  });

  it('returns null for non-domains', () => {
    expect(registrableDomain('Advik')).toBeNull();
    expect(registrableDomain('')).toBeNull();
    expect(registrableDomain('   ')).toBeNull();
    expect(registrableDomain(null)).toBeNull();
    expect(registrableDomain(undefined)).toBeNull();
  });
});

describe('domainOfAddress', () => {
  it('takes the part after the LAST @ and collapses it', () => {
    expect(domainOfAddress('rc@mail.sarv.com')).toBe('sarv.com');
    expect(domainOfAddress('"odd@local"@sarv.com')).toBe('sarv.com');
  });
  it('is null without an @ or a resolvable host', () => {
    expect(domainOfAddress('not-an-email')).toBeNull();
    expect(domainOfAddress('x@localhost')).toBeNull();
    expect(domainOfAddress(null)).toBeNull();
  });
});

describe('domainsInText', () => {
  it('finds domains and the host side of embedded addresses, deduplicated', () => {
    expect(domainsInText('security@paypal.com via PayPal.com (paypal.com)')).toEqual([
      'paypal.com',
    ]);
  });
  it('ignores bare words — a name is not a domain', () => {
    expect(domainsInText('Advik Dutta')).toEqual([]);
    expect(domainsInText('')).toEqual([]);
    expect(domainsInText(null)).toEqual([]);
  });
  // Regression: an invoice whose amounts are links to the biller was flagged as
  // "a link that appears to go to ₹3.2 actually points to cii.in" — tldts reads
  // an unknown last label as a suffix, so every decimal number was a "domain".
  it('ignores numbers — a price, a version or an amount is not a domain', () => {
    expect(domainsInText('₹3.2')).toEqual([]);
    expect(domainsInText('2.58')).toEqual([]);
    expect(domainsInText('Total 136.25 (incl. 18.00 GST) v1.2.3')).toEqual([]);
    expect(domainsInText('1.2.3.4')).toEqual([]);
  });
  // A made-up suffix is not a domain either, but a real one next to a number is.
  it('keeps only names under a real public suffix', () => {
    expect(domainsInText('foo.notatld')).toEqual([]);
    expect(domainsInText('Pay ₹3.2 at cii.in')).toEqual(['cii.in']);
    expect(domainsInText('user.github.io')).toEqual(['github.io']);
    expect(domainsInText('Dear Mr.Smith')).toEqual([]);
  });
  // A written-out URL is a claim about its host whatever the suffix — the
  // lure "https://bank.example/login" must still be read as naming bank.example.
  it('takes the host of a written-out URL even under an unlisted suffix', () => {
    expect(domainsInText('https://bank.example/login')).toEqual(['bank.example']);
    expect(domainsInText('see http://Portal.Acme.example.')).toEqual(['acme.example']);
    expect(domainsInText('https:// nothing')).toEqual([]);
    expect(domainsInText('https://[bad')).toEqual([]);
  });
});

describe('assessSender', () => {
  it('flags DANGER when the display name references a different registrable domain', () => {
    const r = assessSender('support@paypal.com', 'attacker@evil.ru');
    expect(r).toHaveLength(1);
    expect(r[0]!.kind).toBe('domain');
    expect(r[0]!.severity).toBe('danger');
    expect(r[0]!.text).toContain('paypal.com');
    expect(r[0]!.text).toContain('evil.ru');
  });

  it('does NOT flag a subdomain of the sender domain in the name', () => {
    expect(assessSender('Amazon.com', 'ship@mail.amazon.com')).toEqual([]);
  });

  it('does NOT flag ordinary human display names', () => {
    expect(assessSender('Advik Dutta', 'advik.d@sarv.com')).toEqual([]);
    expect(assessSender('Meghna Kotak', 'meghna.k@sarv.com')).toEqual([]);
  });

  // Regression: the case the domain rule could never see. No dot in the name,
  // so nothing for tldts to resolve — and the attacker's own domain passed
  // every authentication check. The brand list is the only offline evidence,
  // and the shield must read it as the same lie as the embedded domain.
  it('flags DANGER when the name borrows a protected brand on a stranger’s address', () => {
    const r = assessSender('Adobe Acrobat Sign', 'Adobesign@powersublinks.com');
    expect(r).toHaveLength(1);
    expect(r[0]!.kind).toBe('brand');
    expect(r[0]!.severity).toBe('danger');
    expect(r[0]!.text).toContain('Adobe');
    expect(r[0]!.text).toContain('powersublinks.com');
  });

  it('does NOT flag the brand itself, from any of its own domains or their subdomains', () => {
    expect(assessSender('PayPal Service', 'no-reply@paypal.com')).toEqual([]);
    expect(assessSender('Adobe Acrobat Sign', 'adobesign@adobesign.com')).toEqual([]);
    expect(assessSender('Adobe Sign', 'noreply@documents.adobe.com')).toEqual([]);
  });

  // The matcher is the vocabulary stage's: whole words, case folded, lookalike
  // codepoints and zero-width separators collapsed. A brand name is not a
  // substring — "Paypalooza" is not PayPal — and the words the list refuses
  // to hold (a fruit, a verb) stay unmatched.
  it('matches the brand name whole-word, case-folded and through lookalike codepoints', () => {
    expect(assessSender('ＰａｙＰａｌ Support', 'x@evil.ru')[0]?.kind).toBe('brand');
    const zeroWidthSpace = String.fromCharCode(0x200b);
    expect(assessSender(`Pay${zeroWidthSpace}Pal Support`, 'x@evil.ru')[0]?.kind).toBe('brand');
    expect(assessSender('Paypalooza Festival', 'x@evil.ru')).toEqual([]);
    expect(assessSender('Apple Tree Nursery', 'x@evil.ru')).toEqual([]);
  });

  // Regression, from the first consumer's live mailbox: Axis Bank writes from
  // `alerts.axisbankmail.bank.in`, a domain no list had. A brand's real sending
  // domains outnumber any list, so a domain that carries the brand's own name
  // is never judged by this rule — red on a bank statement teaches the reader
  // to ignore red.
  it('does NOT flag a brand writing from an unlisted domain that carries its name', () => {
    expect(assessSender('Axis Bank', 'info@alerts.axisbankmail.bank.in')).toEqual([]);
    expect(assessSender('Wells Fargo Online', 'alerts@wellsfargoemail.com')).toEqual([]);
  });

  // Regression, from a live mailbox 2026-09-27: Indian banks moved to the
  // RBI-mandated `.bank.in` namespace, and `bank.in` is a public suffix, so
  // `axis.bank.in` has the label `axis` — which carries no `axisbank`. The
  // genuine AutoPay notice from it was painted red and filed as spam. Every
  // listed Indian bank's live `.bank.in` sending domain is its own.
  it('does NOT flag Indian banks writing from their .bank.in domains', () => {
    expect(assessSender('Axis Bank Alerts', 'alerts@axis.bank.in')).toEqual([]);
    expect(assessSender('HDFC Bank', 'alerts@hdfc.bank.in')).toEqual([]);
    expect(assessSender('HDFC Bank InstaAlerts', 'alerts@hdfcbank.bank.in')).toEqual([]);
    expect(assessSender('ICICI Bank', 'alerts@icici.bank.in')).toEqual([]);
    expect(assessSender('Kotak Mahindra Bank', 'alerts@kotak.bank.in')).toEqual([]);
    expect(assessSender('State Bank of India', 'donotreply@sbi.bank.in')).toEqual([]);
    expect(assessSender('HSBC India', 'alerts@hsbc.bank.in')).toEqual([]);
  });

  // Regression: a `.bank.in` entry must not hand its short label to the
  // name-carrying exemption. `axis` is Axis Bank's only inside the verified
  // registry; outside it, `axis-login.example` writing as Axis Bank is
  // precisely the stranger this rule exists to catch.
  it('does not let a .bank.in label forgive a lookalike outside that registry', () => {
    const axis = PROTECTED_BRANDS.find((brand) => brand.id === 'axis-bank')!;
    expect(domainCarriesBrandName(axis, 'axis-login.example')).toBe(false);
    expect(assessSender('Axis Bank', 'kyc@axis-login.example')[0]?.kind).toBe('brand');
    expect(assessSender('HDFC Bank', 'kyc@hdfc-verify.example')[0]?.kind).toBe('brand');
    // A brand whose only entry sits under the `.bank` TLD is held the same way.
    const onlyDotBank = {
      id: 'x',
      name: 'Example Bank',
      phrases: ['example bank'],
      domains: ['examplebank.bank'],
    };
    expect(domainCarriesBrandName(onlyDotBank, 'examplebank-login.example')).toBe(false);
    // ...while the long, name-carrying label from its ordinary domain still counts.
    expect(domainCarriesBrandName(axis, 'axisbankmail.bank.in')).toBe(true);
  });

  // KNOWN LIMITATION, stated so nobody mistakes it for an accident: the
  // lookalike domain carries the brand's name too, so this rule leaves it
  // alone. Catching `paypal-secure.example` is a different tell — a domain
  // built around a name its registrant does not own — and needs its own rule.
  it('LIMITATION: a lookalike domain built around the brand name is not matched', () => {
    expect(assessSender('PayPal', 'service@paypal-secure.example')).toEqual([]);
  });

  // Regression: a Google Group rewrites From to "Author via Group" on its own
  // address, and the author may well be a brand. That is the list working,
  // not a spoof — flagging it would paint every brand that posts to a list.
  it('does NOT flag a list’s " via " rewrite of a brand author', () => {
    expect(assessSender('DocuSign via Vendors', 'vendors@googlegroups.com')).toEqual([]);
  });

  // One name, one lie: a name that embeds the brand's domain is the domain
  // rule's business, and the brand rule must not charge it a second time.
  it('prefers the domain rule when the name embeds a domain', () => {
    const r = assessSender('PayPal <service@paypal.com>', 'attacker@evil.ru');
    expect(r.map((reason) => reason.kind)).toEqual(['domain']);
  });

  it('returns nothing for a sender with no display name at all', () => {
    expect(assessSender(null, 'billing@evil.ru')).toEqual([]);
    expect(assessSender(undefined, 'billing@evil.ru')).toEqual([]);
  });

  it('flags CAUTION for a punycode/IDN sender domain', () => {
    const r = assessSender('', 'billing@xn--paypa-9qa.com');
    expect(r).toHaveLength(1);
    expect(r[0]!.kind).toBe('punycode');
    expect(r[0]!.severity).toBe('caution');
  });

  it('returns nothing when the address has no parseable domain', () => {
    expect(assessSender('Somebody', 'not-an-email')).toEqual([]);
    expect(assessSender('security@paypal.com', null)).toEqual([]);
  });
});

describe('brandsNamedIn / brandOwningDomain / impersonatedBrand', () => {
  it('names every brand a text borrows, in list order, and nothing for a bare word', () => {
    expect(brandsNamedIn('Your DocuSign and PayPal accounts').map((brand) => brand.id)).toEqual([
      'docusign',
      'paypal',
    ]);
    expect(brandsNamedIn('Advik Dutta')).toEqual([]);
    expect(brandsNamedIn('')).toEqual([]);
    expect(brandsNamedIn(null)).toEqual([]);
  });

  // Compared at eTLD+1: a brand's subdomain is the brand, and the brand's
  // name in front of somebody else's domain is somebody else.
  it('resolves a host to the brand that owns its registrable domain', () => {
    expect(brandOwningDomain('documents.adobe.com')?.id).toBe('adobe');
    expect(brandOwningDomain('ADOBE.COM')?.id).toBe('adobe');
    expect(brandOwningDomain('adobe.com.evil.example')).toBeNull();
    expect(brandOwningDomain('not a host')).toBeNull();
    expect(brandOwningDomain(null)).toBeNull();
  });

  // The exemption's edges: labels shorter than three characters (`me.com`,
  // `fb.com`) do not count, or `theme.example` would be Apple's; a host with no
  // registrable label is nobody's.
  it('recognises the brand’s name inside a sender label, but not a two-letter one', () => {
    const apple = PROTECTED_BRANDS.find((brand) => brand.id === 'apple')!;
    expect(domainCarriesBrandName(apple, 'applesupport.example')).toBe(true);
    expect(domainCarriesBrandName(apple, 'theme.example')).toBe(false);
    expect(domainCarriesBrandName(apple, 'localhost')).toBe(false);
    expect(domainCarriesBrandName(apple, null)).toBe(false);
  });

  it('is null for an empty name, the brand’s own domain, or a list rewrite', () => {
    expect(impersonatedBrand('', 'evil.ru')).toBeNull();
    expect(impersonatedBrand(null, 'evil.ru')).toBeNull();
    expect(impersonatedBrand('PayPal', 'paypal.com')).toBeNull();
    expect(impersonatedBrand('PayPal via Vendors', 'groups.example')).toBeNull();
    expect(impersonatedBrand('PayPal', 'evil.ru')?.id).toBe('paypal');
  });
});

/**
 * A caller's own brand list. The first consumer is a mail client that wants
 * the mailbox owner's organisation protected too — "Acme Corp Billing" from a
 * stranger's domain — without a pull request to this package.
 */
describe('a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };

  it('judges the name against the list it is given, and against the built-in list by default', () => {
    expect(assessSender('Acme Corp Billing', 'x@evil.example')).toEqual([]);
    const reasons = assessSender('Acme Corp Billing', 'x@evil.example', [
      ...PROTECTED_BRANDS,
      ACME,
    ]);
    expect(reasons.map((reason) => reason.kind)).toEqual(['brand']);
    expect(reasons[0]?.text).toContain('Acme Corp');
    // A list that replaces the default protects only what it names.
    expect(assessSender('PayPal Service', 'x@evil.example', [ACME])).toEqual([]);
    expect(assessSender('Acme Corp', 'billing@mail.acme.example', [ACME])).toEqual([]);
  });

  it('threads the list through every helper', () => {
    expect(brandsNamedIn('Acme Corp', [ACME]).map((brand) => brand.id)).toEqual(['acme']);
    expect(brandOwningDomain('mail.acme.example', [ACME])?.id).toBe('acme');
    expect(impersonatedBrand('Acme Corp', 'evil.example', [ACME])?.id).toBe('acme');
  });

  // A caller's list is not held to the built-in hygiene test, so a domain it
  // lists is reduced the way a sender's is — and one that is not a domain at
  // all is ignored rather than trusted.
  it('reduces a caller’s domains to registrable form and ignores ones that are not domains', () => {
    const messy = { ...ACME, domains: ['not a domain', 'MAIL.Acme.Example'] };
    const list = [messy];
    expect(brandOwningDomain('acme.example', list)?.id).toBe('acme');
    // The index is built once per list and reused.
    expect(brandOwningDomain('www.acme.example', list)?.id).toBe('acme');
    expect(brandOwningDomain('not a domain', list)).toBeNull();
  });

  it('lets the first brand win a domain two brands both list', () => {
    const other = { id: 'other', name: 'Other', phrases: ['other co'], domains: ['acme.example'] };
    expect(brandOwningDomain('acme.example', [ACME, other])?.id).toBe('acme');
    expect(brandOwningDomain('acme.example', [other, ACME])?.id).toBe('other');
  });
});

describe('free mailbox hosts are never a brand’s own domain', () => {
  // Regression, found by the 2026-09-24 audit: with gmail.com, outlook.com
  // and icloud.com listed as the brands' own, these three — the commonest
  // free-account lures — were exempt from the very rule written for them.
  it('flags a brand name on a free mailbox address', () => {
    expect(assessSender('Microsoft account team', 'security.alerts@outlook.com')[0]?.kind).toBe(
      'brand',
    );
    expect(assessSender('Google Security', 'noreply.google.alerts@gmail.com')[0]?.kind).toBe(
      'brand',
    );
    expect(assessSender('Apple Support', 'apple.id.help@icloud.com')[0]?.kind).toBe('brand');
    expect(assessSender('Microsoft 365', 'billing@hotmail.com')[0]?.kind).toBe('brand');
  });

  it('still exempts the brands writing from their own domains', () => {
    expect(
      assessSender(
        'Microsoft account team',
        'account-security-noreply@accountprotection.microsoft.com',
      ),
    ).toEqual([]);
    expect(assessSender('Google Security', 'no-reply@accounts.google.com')).toEqual([]);
    expect(assessSender('Apple Support', 'noreply@email.apple.com')).toEqual([]);
  });
});
