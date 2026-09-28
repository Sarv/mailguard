import { describe, expect, it } from 'vitest';

import {
  assessEmailSecurity,
  linkRuleKey,
  parseAuthStatus,
  worstLevel,
  EMPTY_RULES,
  LEVEL_RANK,
  type BrandIdentity,
  type LinkRuleSets,
  type SecurityCheck,
  type SecurityLevel,
} from '../src/security.js';
import type { AuthStatus, SpamReason } from '../src/verdict.js';

const auth = (over: Partial<AuthStatus> = {}): AuthStatus => ({
  spf: 'pass',
  dkim: 'pass',
  dmarc: 'pass',
  overall: 'pass',
  ...over,
});

const anchor = (text: string, href: string): string => `<a href="${href}">${text}</a>`;
const SENDER = { fromName: 'Alice Example', fromAddress: 'alice@example.net' };

const levelOf = (over: Parameters<typeof assessEmailSecurity>[0] = {}): SecurityLevel =>
  assessEmailSecurity({ ...SENDER, ...over }).level;

const rules = (trusted: string[] = [], blocked: string[] = []): LinkRuleSets => ({
  trusted: new Set(trusted),
  blocked: new Set(blocked),
});

describe('parseAuthStatus', () => {
  it('reads a stored verdict', () => {
    expect(
      parseAuthStatus('{"spf":"pass","dkim":"fail","dmarc":"pass","overall":"partial"}'),
    ).toEqual({
      spf: 'pass',
      dkim: 'fail',
      dmarc: 'pass',
      overall: 'partial',
    });
  });

  // Regression: an unreadable stored value must mean "no verdict", never a
  // throw — a corrupt column would otherwise take the whole message view down.
  it('is null for anything unreadable, and defaults missing fields', () => {
    expect(parseAuthStatus('not json')).toBeNull();
    expect(parseAuthStatus('null')).toBeNull();
    expect(parseAuthStatus('"a string"')).toBeNull();
    expect(parseAuthStatus('')).toBeNull();
    expect(parseAuthStatus(null)).toBeNull();
    expect(parseAuthStatus(undefined)).toBeNull();
    expect(parseAuthStatus('{}')).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
  });
});

describe('assessEmailSecurity — the level', () => {
  it('is verified when DMARC passes and every link stays on the sender’s domain', () => {
    expect(levelOf({ auth: auth(), html: anchor('Account', 'https://example.net/a') })).toBe(
      'verified',
    );
    expect(levelOf({ auth: auth(), html: '<p>no links</p>' })).toBe('verified');
  });

  // Regression: the shield went green on the first message of a thread and
  // hollow on every reply, because a reply quotes the mail it answers and
  // that mail's links are the other party's. The replier wrote none of them,
  // and a client collapses the quote so the reader is not even shown them.
  it('is verified when the only off-domain links sit in the quoted history', () => {
    const html = `${anchor('Our docs', 'https://example.net/docs')}<blockquote>${anchor('Their portal', 'https://other.example/login')}</blockquote>`;
    expect(levelOf({ auth: auth(), html })).toBe('verified');
  });

  // Regression: the exemption above is for the quote alone. The same link in
  // the sender's own words still costs the top level, or "verified" would
  // mean nothing more than "quoted something".
  it('is authenticated when that same link is in the sender’s own words', () => {
    const html = `${anchor('Their portal', 'https://other.example/login')}<blockquote>${anchor('Our docs', 'https://example.net/docs')}</blockquote>`;
    expect(levelOf({ auth: auth(), html })).toBe('authenticated');
  });

  // Regression: exempting the quote from the VERIFIED test must not exempt it
  // from the danger tests. A forged quoted chain is how a phish arrives
  // looking like a conversation already in progress.
  it('still escalates to caution for a deceptive link in the quoted history', () => {
    const html = `<blockquote>${anchor('paypal.com', 'https://paypal.secure-login.ru/pay')}</blockquote>`;
    expect(levelOf({ auth: auth(), html })).toBe('caution');
  });

  // Regression: a newsletter that passes DMARC but links to its CDN is real,
  // not "everything in this mail is the sender". Calling that verified
  // devalues the top level on exactly the mail people get most of.
  it('is authenticated, not verified, when links point off-domain', () => {
    expect(levelOf({ auth: auth(), html: anchor('Track', 'https://cdn-tracker.io/t') })).toBe(
      'authenticated',
    );
  });

  it('is unverified when no authentication verdict was recorded', () => {
    expect(levelOf({})).toBe('unverified');
    expect(
      levelOf({ auth: auth({ spf: 'none', dkim: 'none', dmarc: 'none', overall: 'none' }) }),
    ).toBe('unverified');
  });

  it('accepts SPF+DKIM both passing as authentication when DMARC is silent', () => {
    expect(levelOf({ auth: auth({ dmarc: 'none' }), html: '<p>x</p>' })).toBe('verified');
  });

  it('is danger on a DMARC failure', () => {
    expect(levelOf({ auth: auth({ dmarc: 'fail' }) })).toBe('danger');
  });

  // Regression: THE false positive this model exists to avoid. A forwarder or
  // list breaks one input while DMARC still passes; treating that as failure
  // put red shields on legitimate bank and travel mail, which teaches people
  // to ignore red.
  it('is NOT danger when a single input failed but DMARC passed', () => {
    expect(levelOf({ auth: auth({ dkim: 'fail' }), html: '<p>x</p>' })).toBe('verified');
    expect(levelOf({ auth: auth({ spf: 'fail' }), html: '<p>x</p>' })).toBe('verified');
  });

  it('falls back to both-inputs-failed only with no DMARC verdict', () => {
    expect(levelOf({ auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'none' }) })).toBe('danger');
  });

  it('is danger when the display name impersonates another domain', () => {
    expect(
      assessEmailSecurity({
        fromName: 'PayPal <service@paypal.com>',
        fromAddress: 'billing@evil.ru',
        auth: auth(),
      }).level,
    ).toBe('danger');
  });

  // Regression: the lure that passed every authentication check. The shield
  // must go red on the borrowed brand name — the ONLY offline tell in the
  // headers — and not be talked out of it by three green authentication rows.
  it('is danger when the display name borrows a protected brand on a stranger’s address', () => {
    const lure = assessEmailSecurity({
      fromName: 'Adobe Acrobat Sign',
      fromAddress: 'Adobesign@powersublinks.com',
      auth: auth(),
    });
    expect(lure.level).toBe('danger');
    expect(lure.checks.find((c) => c.id === 'sender')?.status).toBe('fail');
    expect(lure.checks.find((c) => c.id === 'sender')?.detail).toContain('Adobe');
    // The brand itself, from its own domain, is the arrangement working: with
    // DMARC passing and no links to judge, that is the top level.
    expect(
      levelOf({
        fromName: 'Adobe Acrobat Sign',
        fromAddress: 'adobesign@adobesign.com',
        auth: auth(),
      }),
    ).toBe('verified');
  });

  it('is caution for a soft SPF result', () => {
    expect(levelOf({ auth: auth({ spf: 'softfail' }) })).toBe('caution');
    expect(levelOf({ auth: auth({ spf: 'neutral' }) })).toBe('caution');
  });

  it('is caution for one failed input with no DMARC verdict to settle it', () => {
    expect(levelOf({ auth: auth({ spf: 'fail', dmarc: 'none' }) })).toBe('caution');
    expect(levelOf({ auth: auth({ dkim: 'fail', dmarc: 'none' }) })).toBe('caution');
  });

  it('is caution for an unvetted deceptive link', () => {
    expect(levelOf({ auth: auth(), html: anchor('paypal.com', 'https://evil.ru/x') })).toBe(
      'caution',
    );
  });

  // Regression: spam is unwanted, not impersonation. The reasons that make
  // spam DANGEROUS already score danger above on their own; promoting every
  // spam verdict to danger would flatten the distinction the levels exist for.
  it('is caution — not danger — when the filter scored it spam', () => {
    expect(levelOf({ auth: auth(), spamScore: 7 })).toBe('caution');
  });

  it('does not escalate for a merely suspicious score', () => {
    expect(levelOf({ auth: auth(), spamScore: 3, html: '<p>x</p>' })).toBe('verified');
  });
});

describe('assessEmailSecurity — the Links row explains the badge', () => {
  const detailOf = (over: Parameters<typeof assessEmailSecurity>[0] = {}): string =>
    assessEmailSecurity({ ...SENDER, auth: auth(), ...over }).checks.find((c) => c.id === 'links')
      ?.detail ?? '';

  // THE regression this row exists for. Two messages, seven identical green
  // ticks, two different badges: one `verified`, one `authenticated`, and
  // nothing on screen said which fact had decided it. The level's question
  // (does every link stay home?) is not the Links check's question (does any
  // link lie about where it goes?), so the deciding fact has to be stated.
  it('says which links left the domain, so two identical tick lists read differently', () => {
    const home = { html: anchor('Our docs', 'https://example.net/docs') };
    const away = { html: anchor('The doc', 'https://docs.google.com/d/1') };

    expect(levelOf({ auth: auth(), ...home })).toBe('verified');
    expect(levelOf({ auth: auth(), ...away })).toBe('authenticated');

    // Both still pass the deception check — that is the whole trap.
    expect(
      assessEmailSecurity({ ...SENDER, auth: auth(), ...away }).checks.find((c) => c.id === 'links')
        ?.status,
    ).toBe('pass');

    expect(detailOf(home)).toBe(
      'Link domains match what they show, and every link stays on example.net',
    );
    expect(detailOf(away)).toBe(
      'Link domains match what they show; 1 link leaves example.net (google.com)',
    );
  });

  // Regression: a body with nothing to check was reported as a body that had
  // been checked and found clean — the flattering reading of an absence, on
  // the one row a reader consults to find out what was actually examined.
  it('does not claim a link check it never ran on a message with no links', () => {
    expect(detailOf({ html: '<p>Just a note.</p>' })).toBe(
      'The sender wrote no links in this message',
    );
    expect(levelOf({ auth: auth(), html: '<p>Just a note.</p>' })).toBe('verified');
  });

  // With no parsable From address there is no "home" to say the links stayed
  // on, so the row stops at the question it CAN answer. Naming a domain here
  // would mean inventing one.
  it('claims nothing about staying home when the sender domain is unknown', () => {
    expect(
      detailOf({ fromAddress: null, html: anchor('Our docs', 'https://docs.example.org/x') }),
    ).toBe('Link domains match what they show');
  });

  it('counts and names several destinations, and caps the naming', () => {
    const html =
      anchor('a', 'https://one.example/a') +
      anchor('b', 'https://two.example/b') +
      anchor('c', 'https://three.example/c');
    expect(detailOf({ html })).toBe(
      'Link domains match what they show; 3 links leave example.net (one.example, two.example, +1 more)',
    );
  });

  // Regression: the body is not here yet, and the row must say so rather than
  // borrow either of the sentences above.
  it('reports the links as unchecked while the body is still being fetched', () => {
    expect(detailOf({ html: null, bodyLoaded: false })).toContain('has not been downloaded yet');
  });
});

describe('assessEmailSecurity — trust and block rules', () => {
  const html = anchor('paypal.com', 'https://evil.ru/x');
  const key = linkRuleKey('example.net', 'paypal.com', 'evil.ru');

  // CHANGED in 0.4: this used to stop at `authenticated`. Trusting the pair
  // lifted the message out of `caution` and then withheld the top level for
  // the very link that had just been forgiven — the setting appeared to work
  // and then visibly did not. Regression: the vetted pair is honoured in the
  // level as well as in the checks.
  it('a trusted pair stops being a caution, and is forgiven by the level too', () => {
    const result = assessEmailSecurity({ ...SENDER, auth: auth(), html, rules: rules([key]) });
    expect(result.untrustedLinks).toEqual([]);
    expect(result.level).toBe('verified');
    expect(result.checks.find((c) => c.id === 'links')?.detail).toContain('1 pair you trust');
  });

  // Regression: the detail claimed "every link stays on example.net" for a
  // link that plainly went to evil.ru and had merely been forgiven. The whole
  // point of these lines is that a reader can check them.
  it('says the trusted link LEFT the domain rather than that it stayed', () => {
    const result = assessEmailSecurity({ ...SENDER, auth: auth(), html, rules: rules([key]) });
    const detail = result.checks.find((c) => c.id === 'links')?.detail ?? '';
    expect(detail).toContain('1 link leaves example.net');
    expect(detail).toContain('you have trusted it');
    expect(detail).not.toContain('every link stays');
  });

  it('a blocked pair forces danger', () => {
    const result = assessEmailSecurity({ ...SENDER, auth: auth(), html, rules: rules([], [key]) });
    expect(result.level).toBe('danger');
    expect(result.blockedLinks).toHaveLength(1);
    expect(result.checks.find((c) => c.id === 'links')?.status).toBe('fail');
  });

  // Regression: a rule trusted for one sender must not license the same
  // redirect for every other sender — a compromised known account is the
  // usual way phishing arrives from a familiar name.
  it('a rule is scoped to the sender domain', () => {
    const result = assessEmailSecurity({
      fromName: 'Mallory',
      fromAddress: 'm@other.com',
      auth: auth(),
      html,
      rules: rules([key]),
    });
    expect(result.level).toBe('caution');
    expect(result.untrustedLinks).toHaveLength(1);
  });

  it('defaults to no rules', () => {
    expect(assessEmailSecurity({ ...SENDER, auth: auth(), html }).untrustedLinks).toHaveLength(1);
    expect(EMPTY_RULES.trusted.size + EMPTY_RULES.blocked.size).toBe(0);
  });

  it('counts additional untrusted links in the summary', () => {
    const two =
      anchor('paypal.com', 'https://evil.ru/x') + anchor('stripe.com', 'https://bad.io/y');
    const detail = assessEmailSecurity({ ...SENDER, auth: auth(), html: two }).checks.find(
      (c) => c.id === 'links',
    )?.detail;
    expect(detail).toContain('+1 more');
  });

  it('pluralises the trusted-pair count', () => {
    const two =
      anchor('paypal.com', 'https://evil.ru/x') + anchor('stripe.com', 'https://bad.io/y');
    const keys = [
      linkRuleKey('example.net', 'paypal.com', 'evil.ru'),
      linkRuleKey('example.net', 'stripe.com', 'bad.io'),
    ];
    const detail = assessEmailSecurity({
      ...SENDER,
      auth: auth(),
      html: two,
      rules: rules(keys),
    }).checks.find((c) => c.id === 'links')?.detail;
    expect(detail).toContain('2 pairs you trust');
  });

  it('lower-cases the rule key so a stored rule matches regardless of case', () => {
    expect(linkRuleKey('Example.NET', 'PayPal.com', 'Evil.RU')).toBe(
      'example.net|paypal.com|evil.ru',
    );
  });
});

describe('assessEmailSecurity — the checks it explains itself with', () => {
  it('reports each authentication result, including the absent one', () => {
    const checks = assessEmailSecurity({
      ...SENDER,
      auth: auth({ spf: 'fail', dmarc: 'none' }),
    }).checks;
    expect(checks.find((c) => c.id === 'spf')?.status).toBe('fail');
    expect(checks.find((c) => c.id === 'dkim')?.status).toBe('pass');
    expect(checks.find((c) => c.id === 'dmarc')?.status).toBe('unknown');
  });

  it('reports a soft SPF as a warning', () => {
    const spf = assessEmailSecurity({ ...SENDER, auth: auth({ spf: 'softfail' }) }).checks.find(
      (c) => c.id === 'spf',
    );
    expect(spf?.status).toBe('warn');
    expect(spf?.detail).toContain('softfail');
  });

  // Regression: the broken-signature-under-passing-DMARC case must stay
  // VISIBLE as a warning rather than vanish, so a reader can still see that
  // something was rewritten in transit.
  it('downgrades a broken DKIM under a passing DMARC to a warning, and says why', () => {
    const dkim = assessEmailSecurity({ ...SENDER, auth: auth({ dkim: 'fail' }) }).checks.find(
      (c) => c.id === 'dkim',
    );
    expect(dkim?.status).toBe('warn');
    expect(dkim?.detail).toContain('DMARC still passed');
  });

  it('reports the sender-name check both ways', () => {
    expect(assessEmailSecurity({ ...SENDER }).checks.find((c) => c.id === 'sender')?.status).toBe(
      'pass',
    );
    const spoofed = assessEmailSecurity({
      fromName: 'PayPal <service@paypal.com>',
      fromAddress: 'billing@evil.ru',
    }).checks.find((c) => c.id === 'sender');
    expect(spoofed?.status).toBe('fail');
    expect(spoofed?.detail).toContain('paypal.com');
  });

  it('reports each spam verdict, with the reasons behind it', () => {
    const reasons = '[{"id":"auth-failed","points":3,"detail":"DMARC failed"}]';
    const spam = assessEmailSecurity({ ...SENDER, spamScore: 7, spamReasons: reasons }).checks.find(
      (c) => c.id === 'spam',
    );
    expect(spam?.status).toBe('fail');
    expect(spam?.detail).toContain('DMARC failed');

    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 3 }).checks.find((c) => c.id === 'spam')?.status,
    ).toBe('warn');
    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 0 }).checks.find((c) => c.id === 'spam')?.status,
    ).toBe('pass');
  });

  it('reports a clean score that still carried reasons', () => {
    const reasons = '[{"id":"missing-date","points":1,"detail":"No Date header"}]';
    const detail = assessEmailSecurity({
      ...SENDER,
      spamScore: 1,
      spamReasons: reasons,
    }).checks.find((c) => c.id === 'spam')?.detail;
    expect(detail).toContain('No Date header');
  });

  // Regression: never scored and scored zero are different facts. Collapsing
  // them shows a green tick on mail nothing ever looked at.
  it('distinguishes "never scored" from "scored clean"', () => {
    const never = assessEmailSecurity({ ...SENDER }).checks.find((c) => c.id === 'spam');
    expect(never?.status).toBe('unknown');
    expect(assessEmailSecurity({ ...SENDER }).spam.verdict).toBeNull();
    const nan = assessEmailSecurity({ ...SENDER, spamScore: Number.NaN }).spam;
    expect(nan.score).toBeNull();
    expect(nan.verdict).toBeNull();
  });
});

describe('assessEmailSecurity — input shapes', () => {
  it('accepts the auth verdict as an object or as stored JSON', () => {
    const asJson = assessEmailSecurity({
      ...SENDER,
      auth: JSON.stringify(auth()),
      html: '<p>x</p>',
    });
    const asObject = assessEmailSecurity({ ...SENDER, auth: auth(), html: '<p>x</p>' });
    expect(asJson.level).toBe(asObject.level);
    expect(asJson.level).toBe('verified');
  });

  it('accepts spam reasons as an array or as stored JSON', () => {
    const array = assessEmailSecurity({
      ...SENDER,
      spamScore: 7,
      spamReasons: [{ id: 'auth-failed', points: 3, detail: 'DMARC failed' }],
    });
    expect(array.spam.reasons).toHaveLength(1);
    expect(
      assessEmailSecurity({ ...SENDER, spamScore: 7, spamReasons: 'corrupt' }).spam.reasons,
    ).toEqual([]);
  });

  // Regression: with an unusable From address there is no sender domain to
  // scope a trust rule to. The key must still be built (against an empty
  // domain) rather than crashing, and the link must stay untrusted — a rule
  // saved for a real sender must not accidentally match one with no domain.
  it('still evaluates links when the sender address yields no domain', () => {
    const result = assessEmailSecurity({
      fromAddress: 'nonsense',
      auth: auth(),
      html: anchor('paypal.com', 'https://evil.ru/x'),
      rules: rules([linkRuleKey('example.net', 'paypal.com', 'evil.ru')]),
    });
    expect(result.senderDomain).toBeNull();
    expect(result.untrustedLinks).toHaveLength(1);
    expect(result.level).toBe('caution');
  });

  it('reports the sender domain, or null when the address is unusable', () => {
    expect(assessEmailSecurity({ ...SENDER }).senderDomain).toBe('example.net');
    expect(assessEmailSecurity({ fromAddress: 'nonsense' }).senderDomain).toBeNull();
    expect(assessEmailSecurity({}).senderDomain).toBeNull();
  });
});

/**
 * The sender's mark. `/brand` resolves what a domain publishes about its own
 * logo; this is the one line the shield says about it.
 *
 * What this protects: a reader who has seen a tick on this sender before and
 * does not see one today is owed a reason. Every branch below is a different
 * reason, and a wrong one is worse than none — telling somebody a brand
 * "proved ownership" of a message that failed DMARC is exactly the sentence
 * a spoofer needs.
 */
describe('assessEmailSecurity — the sender brand mark', () => {
  const brandOf = (
    bimi: BrandIdentity | null,
    over: Parameters<typeof assessEmailSecurity>[0] = {},
  ): SecurityCheck | undefined =>
    assessEmailSecurity({ ...SENDER, auth: auth(), bimi, ...over }).checks.find(
      (check) => check.id === 'brand',
    );

  // Three states, not two. A caller that never looks BIMI up must not get a
  // row claiming the domain publishes nothing.
  it('says nothing at all when the caller did not ask', () => {
    expect(assessEmailSecurity({ ...SENDER }).checks.some((check) => check.id === 'brand')).toBe(
      false,
    );
    expect(brandOf(null)?.status).toBe('unknown');
    expect(brandOf(null)?.detail).toBe('Not looked up yet');
  });

  it('names the organisation, the domain and the authority behind a verified mark', () => {
    const check = brandOf({
      status: 'verified',
      organization: 'Example Inc',
      issuer: 'Test Verified Mark Root',
    });

    expect(check?.status).toBe('pass');
    expect(check?.detail).toBe(
      'Example Inc proved ownership of example.net with a Verified Mark Certificate from Test Verified Mark Root',
    );
  });

  // A cached row need not carry every field, and a sentence with an "undefined"
  // in it is worse than a vaguer one.
  it('falls back to plain words for a mark whose row names nobody', () => {
    const check = brandOf({ status: 'verified' }, { fromAddress: null });

    expect(check?.detail).toBe(
      'The brand proved ownership of this domain with a Verified Mark Certificate from a Mark Verifying Authority',
    );
  });

  // THE regression in this block. The certificate says who owns the brand;
  // DMARC says this message came from them. Without the second, the first
  // sentence is what a spoofer would like the reader to see.
  it('withholds the tick when the message did not pass DMARC', () => {
    const check = brandOf(
      { status: 'verified', organization: 'Example Inc' },
      {
        auth: auth({ dmarc: 'none' }),
      },
    );

    expect(check?.status).toBe('warn');
    expect(check?.detail).toBe(
      'The domain publishes a verified logo, but this message did not pass DMARC — logo and tick withheld',
    );
  });

  it('distinguishes a logo with no certificate from a verified mark', () => {
    expect(brandOf({ status: 'logo' })).toEqual({
      id: 'brand',
      label: 'Brand identity',
      status: 'pass',
      detail: 'The domain publishes a BIMI logo, without a Verified Mark Certificate',
    });
    expect(brandOf({ status: 'logo' }, { auth: auth({ dmarc: 'fail' }) })?.detail).toBe(
      'The domain publishes a logo, but this message did not pass DMARC — logo withheld',
    );
  });

  // A domain that declines and a domain that publishes nothing are different
  // facts, and neither is a complaint about the message.
  it('reports the quiet outcomes as unknown, each in its own words', () => {
    expect(brandOf({ status: 'declined' })?.detail).toBe('The domain declines to show a logo');
    expect(brandOf({ status: 'none' })?.detail).toBe('The domain publishes no BIMI record');
    expect(brandOf({ status: 'declined' })?.status).toBe('unknown');
  });

  it('passes on why a record was unusable, and says so plainly when it cannot', () => {
    expect(brandOf({ status: 'invalid', detail: 'l= is not an https URL' })?.detail).toBe(
      'BIMI record unusable: l= is not an https URL',
    );
    expect(brandOf({ status: 'invalid' })?.detail).toBe(
      'BIMI record unusable: the record could not be read',
    );
  });

  // Regression: a resolver timeout is a fact about the network, never about
  // the sender. It must never read as a warning about the mail.
  it('reports a failed lookup as unknown rather than as a warning', () => {
    expect(brandOf({ status: 'error', detail: 'ESERVFAIL' })).toEqual({
      id: 'brand',
      label: 'Brand identity',
      status: 'unknown',
      detail: 'The brand lookup failed: ESERVFAIL',
    });
    expect(brandOf({ status: 'error' })?.detail).toBe('The brand lookup failed');
  });

  // THE other regression: the mark explains, it does not score. Most
  // legitimate senders publish no BIMI record at all, so letting its absence
  // (or a failed lookup) touch the level would warn about most of the world's
  // mail — and a verified mark must not lift a message DMARC already doubted.
  it('never moves the level, in either direction', () => {
    const verified: BrandIdentity = { status: 'verified', organization: 'Example Inc' };

    expect(levelOf({ auth: auth(), bimi: { status: 'none' } })).toBe('verified');
    expect(levelOf({ auth: auth(), bimi: { status: 'error' } })).toBe('verified');
    expect(levelOf({ auth: auth({ dmarc: 'fail' }), bimi: verified })).toBe('danger');
    expect(levelOf({ auth: auth(), bimi: verified, spamScore: 7 })).toBe('caution');
    expect(levelOf({ bimi: verified })).toBe('unverified');
  });
});

describe('assessEmailSecurity — a body that has not arrived yet', () => {
  const spoofedLink = anchor('example.net', 'https://evil.example/login');

  // Regression: a client that lazy-loads bodies asked for a verdict with no
  // body at all, and got `verified` — the TOP level, its badge earned by a
  // links check that read an empty string and reported "nothing deceptive".
  // Every unread message in the list wore a green shield the filter had no
  // grounds to give it.
  it('never awards verified for a body it has not read', () => {
    expect(levelOf({ auth: auth() })).toBe('verified');
    expect(levelOf({ auth: auth(), bodyLoaded: false })).toBe('authenticated');
  });

  it('reports the links check as unknown, not as a pass', () => {
    const pending = assessEmailSecurity({ ...SENDER, auth: auth(), bodyLoaded: false });
    const links = pending.checks.find((c) => c.id === 'links');
    expect(links?.status).toBe('unknown');
    expect(links?.detail).toContain('not been downloaded');
    expect(pending.pending).toBe(true);
    expect(pending.untrustedLinks).toEqual([]);
  });

  // The flag is what a caller renders "still checking" from, so a loaded body
  // must never set it — a permanent spinner is the same bug in reverse.
  it('is not pending once the body is there', () => {
    expect(assessEmailSecurity({ ...SENDER, auth: auth() }).pending).toBe(false);
    expect(assessEmailSecurity({ ...SENDER, auth: auth(), bodyLoaded: true }).pending).toBe(false);
  });

  // THE thing a pending state must not do: withhold a warning. Authentication
  // and the spam verdict come from the headers, which arrived with the
  // message — a DMARC failure is final before the first byte of the body.
  it('still condemns a message the headers already condemn', () => {
    const danger = assessEmailSecurity({
      fromName: 'example.net',
      fromAddress: 'alice@evil.example',
      auth: auth({ spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' }),
      bodyLoaded: false,
    });
    expect(danger.level).toBe('danger');
    expect(danger.pending).toBe(true);
  });

  // And the level it holds back is provisional in BOTH directions: the same
  // message that reads `authenticated` while pending becomes `caution` when
  // the body turns out to carry a deceptive link.
  it('moves once the body arrives', () => {
    expect(levelOf({ auth: auth(), html: spoofedLink, bodyLoaded: false })).toBe('authenticated');
    expect(levelOf({ auth: auth(), html: spoofedLink })).toBe('caution');
  });
});

describe('assessEmailSecurity — a sender the reader trusts', () => {
  // The Axis Bank alert that started this: a bank's name on an address the
  // brand list did not know, plus a spam score. Trusted and authenticated, it
  // must not arrive under a red shield again.
  const BANK = { fromName: 'Axis Bank Alerts', fromAddress: 'alerts@unlisted-bank.example' };
  const SPAM: SpamReason[] = [
    { id: 'brand-impersonation', points: 3, detail: 'borrows the Axis Bank name' },
    { id: 'in-reply-to-self', points: 2, detail: 'reply to itself' },
  ];

  // Regression: if trust stops lifting the name and score checks, the
  // reader's "Trust this sender" visibly does nothing.
  it('sets the name check and the spam score aside when the message authenticated', () => {
    const untrusted = assessEmailSecurity({
      ...BANK,
      auth: auth(),
      spamScore: 5,
      spamReasons: SPAM,
    });
    expect(untrusted.level).toBe('danger');
    const trusted = assessEmailSecurity({
      ...BANK,
      auth: auth(),
      spamScore: 5,
      spamReasons: SPAM,
      trustedSender: true,
    });
    expect(trusted.trusted).toBe(true);
    expect(trusted.level).toBe('verified');
    expect(trusted.checks.find((c) => c.id === 'sender')?.status).toBe('pass');
    const spam = trusted.checks.find((c) => c.id === 'spam');
    expect(spam?.status).toBe('pass');
    // Still shown, so the reader can see what the filter found.
    expect(spam?.detail).toContain('set aside because you trust this sender');
    expect(spam?.detail).toContain('borrows the Axis Bank name');
  });

  // Regression, the security edge: the From address is what a forger copies.
  // A trusted address on a message that FAILED authentication must stay
  // danger and say why — otherwise trust is a bypass for anyone who can type
  // the address.
  it('sets trust aside, and says so, when the message failed authentication', () => {
    const forged = assessEmailSecurity({
      ...BANK,
      auth: auth({ dmarc: 'fail', overall: 'fail' }),
      spamScore: 8,
      spamReasons: SPAM,
      trustedSender: true,
    });
    expect(forged.trusted).toBe(false);
    expect(forged.level).toBe('danger');
    const sender = forged.checks.find((c) => c.id === 'sender');
    expect(sender?.status).toBe('fail');
    expect(sender?.detail).toContain('may be a forgery');
    expect(forged.checks.find((c) => c.id === 'spam')?.status).toBe('fail');
  });

  // Trust is in the SENDER, not in every URL their mail carries: a link that
  // lies about where it goes, or one the reader blocked, still counts.
  it('still judges links', () => {
    const html = anchor('https://unlisted-bank.example', 'https://evil.example/x');
    expect(assessEmailSecurity({ ...BANK, auth: auth(), html, trustedSender: true }).level).toBe(
      'caution',
    );
    const blocked = rules(
      [],
      [linkRuleKey('unlisted-bank.example', 'unlisted-bank.example', 'evil.example')],
    );
    expect(
      assessEmailSecurity({ ...BANK, auth: auth(), html, rules: blocked, trustedSender: true })
        .level,
    ).toBe('danger');
  });

  it('changes nothing when the reader has not trusted the sender', () => {
    const plain = assessEmailSecurity({ ...SENDER, auth: auth() });
    expect(plain.trusted).toBe(false);
    expect(assessEmailSecurity({ ...SENDER, auth: auth(), trustedSender: false })).toEqual(plain);
  });

  // With no authentication verdict at all there is nothing to contradict the
  // address, so trust applies — the same "unknown is not a failure" rule the
  // scorer uses.
  it('applies trust when the server recorded no authentication verdict', () => {
    const noAuth = assessEmailSecurity({
      ...BANK,
      spamScore: 5,
      spamReasons: SPAM,
      trustedSender: true,
    });
    expect(noAuth.trusted).toBe(true);
    expect(LEVEL_RANK[noAuth.level]).toBeLessThan(LEVEL_RANK.caution);
  });
});

describe('worstLevel', () => {
  // Regression: a thread banner must escalate to its worst message. Returning
  // the first or the last mislabels a clean opener when message 14 is a spoof.
  it('returns the most dangerous level present', () => {
    expect(worstLevel(['verified', 'danger', 'authenticated'])).toBe('danger');
    expect(worstLevel(['verified', 'unverified'])).toBe('unverified');
    expect(worstLevel(['verified'])).toBe('verified');
    expect(worstLevel([])).toBe('verified');
  });

  it('ranks the levels from safest to most dangerous', () => {
    expect(LEVEL_RANK.verified).toBeLessThan(LEVEL_RANK.authenticated);
    expect(LEVEL_RANK.authenticated).toBeLessThan(LEVEL_RANK.unverified);
    expect(LEVEL_RANK.unverified).toBeLessThan(LEVEL_RANK.caution);
    expect(LEVEL_RANK.caution).toBeLessThan(LEVEL_RANK.danger);
  });
});

describe('assessEmailSecurity — a caller-supplied brand list', () => {
  const ACME = { id: 'acme', name: 'Acme Corp', phrases: ['acme corp'], domains: ['acme.example'] };
  it('goes red on a brand only the caller protects, and not without it', () => {
    const lure = { fromName: 'Acme Corp Billing', fromAddress: 'x@evil.example', auth: auth() };
    expect(levelOf(lure)).not.toBe('danger');
    expect(levelOf({ ...lure, brands: [ACME] })).toBe('danger');
  });
});
