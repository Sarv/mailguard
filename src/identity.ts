/**
 * Who the message claims to be from, judged from the From header alone.
 *
 * `support@paypal.com` as the friendly name on a message that actually came
 * from attacker@evil.ru is the oldest phishing tell there is, and it needs
 * nothing but the envelope — no body, no network, no DNS. That makes it the
 * one high-signal check available at the moment a message arrives, before a
 * body has been downloaded, which is why it lives in its own entry point
 * rather than inside the scanner.
 *
 * Two very different callers want the same answer and must never disagree
 * about it: the ingest-time scorer, and the UI drawing a shield on a message
 * someone is reading months later. Two copies of a security rule drift, in
 * exactly the direction nobody notices — the one where the warning quietly
 * stops firing.
 *
 * Browser-safe by construction: the only import is `tldts`, which is pure.
 * Available as `@sarv-in/mailguard/identity` so a renderer can take this
 * rule without the scanner behind it.
 *
 * Domain comparison is done on the registrable domain (eTLD+1), so
 * `mail.paypal.com` vs `paypal.com` is NOT flagged, while `paypal.com` vs
 * `paypal.secure-login.ru` is.
 *
 * TWO WAYS TO WEAR A NAME. The first version of this rule caught a display
 * name that contained a DOMAIN — `"PayPal <service@paypal.com>"` — because
 * `tldts` can adjudicate a domain and no list is needed. It could not catch
 * `"Adobe Acrobat Sign" <Adobesign@powersublinks.com>`: no dot in the name,
 * so nothing to resolve, and the message passed SPF, DKIM and DMARC for the
 * attacker's own domain. Authentication says who sent a message; it cannot
 * say whether that sender is who the name claims. The second check closes
 * that: a curated list of protected brands and the domains each actually
 * sends from (`./data/brands/`, one file per brand), so a name borrowed from the list on an
 * address outside its domains is the same lie as the embedded domain — and
 * is reported with the same severity.
 */
import { getDomain, parse as parseHost } from 'tldts';

import { PROTECTED_BRANDS, type ProtectedBrand } from './data/brands/index.js';
import { containsPhrase, normalizeForMatching } from './text.js';

export type { ProtectedBrand };
export { PROTECTED_BRANDS };

export interface PhishingReason {
  /**
   * Which check spoke. `domain`: the display name names another registrable
   * domain. `brand`: it borrows a protected brand's name on an address that is
   * not the brand's. `punycode`: the sender domain is IDN-encoded. `link`: an
   * anchor's text and href disagree (from `/links`). A scorer maps each to
   * its own reason id; a shield needs only `severity`.
   */
  kind: 'domain' | 'brand' | 'punycode' | 'link';
  /** 'danger' is a categorical tell; 'caution' is suggestive on its own. */
  severity: 'danger' | 'caution';
  text: string;
}

/**
 * Registrable domain (eTLD+1), lowercased — e.g. `a.b.paypal.co.uk` →
 * `paypal.co.uk`. Null for anything that is not a resolvable public domain
 * (bare words, IPs, empty). `allowPrivateDomains: false` keeps a host like
 * `someone.github.io` collapsing to its true registrable owner.
 */
export function registrableDomain(input: string | null | undefined): string | null {
  if (!input) return null;
  const host = input.trim().toLowerCase();
  if (!host) return null;
  return getDomain(host, { allowPrivateDomains: false }) || null;
}

/** Registrable domain of an email address (the part after the last `@`). */
export function domainOfAddress(address: string | null | undefined): string | null {
  if (!address) return null;
  const at = address.lastIndexOf('@');
  if (at < 0) return null;
  return registrableDomain(address.slice(at + 1));
}

/**
 * Registrable domains referenced inside a free-text display name.
 *
 * Tokenised on separators and handed to `tldts` to adjudicate — no pattern
 * tries to recognise a domain itself. A token like `Advik` yields null and is
 * ignored; `paypal.com` or `security@paypal.com` yields `paypal.com`. The
 * dot requirement stops `tldts` resolving a bare word against its no-dot
 * fallbacks and inventing a brand out of somebody's surname.
 */
export function domainsInText(text: string | null | undefined): string[] {
  if (!text) return [];
  const found = new Set<string>();
  for (const rawToken of text.split(/[\s<>(),;:"'|]+/)) {
    const token = rawToken.trim();
    if (!token) continue;
    // If the token is (or contains) an email address, keep the host side.
    const candidate = token.includes('@') ? token.slice(token.lastIndexOf('@') + 1) : token;
    if (!candidate.includes('.')) continue;
    const domain = registrableDomain(candidate);
    if (domain) found.add(domain);
  }
  return [...found];
}

/**
 * One domain → brand map per brand list, built on first use and kept for as
 * long as the list is. A `WeakMap` keyed by the array itself, so a caller's
 * own list gets its own index and is not held alive by it — which is also
 * why a list should be treated as immutable once it has been used: a later
 * edit to the same array is not seen. Where two brands list one domain, the
 * first wins, as a linear scan would have.
 */
const DOMAIN_INDEXES = new WeakMap<
  readonly ProtectedBrand[],
  ReadonlyMap<string, ProtectedBrand>
>();

function domainIndex(brands: readonly ProtectedBrand[]): ReadonlyMap<string, ProtectedBrand> {
  const known = DOMAIN_INDEXES.get(brands);
  if (known) return known;
  const index = new Map<string, ProtectedBrand>();
  for (const brand of brands) {
    for (const domain of brand.domains) {
      // A caller's list is not held to the built-in list's hygiene test, so
      // its entries are reduced the same way a sender's domain is.
      const key = registrableDomain(domain);
      if (key !== null && !index.has(key)) index.set(key, brand);
    }
  }
  DOMAIN_INDEXES.set(brands, index);
  return index;
}

/**
 * The protected brand whose own domains include this host, or null.
 *
 * Compared at eTLD+1, so `documents.adobe.com` is Adobe's and
 * `adobe.com.evil.example` is not — the registrable domain of the latter is
 * `evil.example`, whatever the labels in front of it say.
 *
 * @param brands the list to consult. Defaults to {@link PROTECTED_BRANDS}; pass `[...PROTECTED_BRANDS, yours]` to add to it, or your own list to replace it.
 */
export function brandOwningDomain(
  host: string | null | undefined,
  brands: readonly ProtectedBrand[] = PROTECTED_BRANDS,
): ProtectedBrand | null {
  const domain = registrableDomain(host);
  if (!domain) return null;
  return domainIndex(brands).get(domain) ?? null;
}

/**
 * Every protected brand whose name appears in some text, as whole words, in
 * the order the list holds them.
 *
 * Matching is the same fold the vocabulary stage uses (`./text.ts`): case,
 * NFKC lookalikes and zero-width separators are all collapsed first, so
 * `ＰａｙＰａｌ` and `Pay<U+200B>Pal` both match and `paypalooza` does not.
 */
export function brandsNamedIn(
  text: string | null | undefined,
  brands: readonly ProtectedBrand[] = PROTECTED_BRANDS,
): ProtectedBrand[] {
  const haystack = normalizeForMatching(text);
  if (!haystack) return [];
  return brands.filter((brand) => brand.phrases.some((phrase) => containsPhrase(haystack, phrase)));
}

/**
 * The shortest label that still names a brand. `fb.com` and `me.com` give
 * two-letter labels that appear inside ordinary words, and an exemption keyed
 * on those would forgive `theme.example` for Apple.
 */
const BRAND_LABEL_MIN_CHARS = 3;

/**
 * Public suffixes whose registry admits only verified institutions: `bank.in`
 * is issued by IDRBT to RBI-licensed banks alone, and the `.bank` TLD by fTLD
 * to verified banks alone. A brand's domain under one of these proves the
 * list entry, but its short label (`axis`, `sbi`) is not the brand's name
 * anywhere else — see {@link domainCarriesBrandName}.
 */
const REGISTRANT_VERIFIED_SUFFIXES: readonly string[] = ['bank', 'bank.in'];

/**
 * True when the sender's registrable domain carries the brand's own name —
 * `axisbankmail.bank.in` for Axis Bank, `wellsfargoemail.com` for Wells Fargo.
 *
 * WHY THIS EXEMPTION EXISTS. A brand's real sending domains are more numerous
 * than any list: Axis Bank writes from `alerts.axisbankmail.bank.in`, and the
 * first consumer of this package had a live-mailbox test proving it. A rule
 * that painted that statement red would be the false positive this package is
 * built to avoid — red on a bank statement teaches the reader to ignore red.
 * So a domain that visibly names the brand is left alone here, whatever the
 * list says.
 *
 * WHAT IT COSTS, stated plainly: the LOOKALIKE domain — `paypal-secure.example`
 * writing as "PayPal" — carries the brand's name too, and is therefore NOT this
 * rule's business. That is a different tell (a registrable domain built around
 * a brand's name that the brand does not own) and needs a rule of its own;
 * what this rule catches is the name on a stranger's domain — the freemail
 * address, the throwaway `powersublinks.com` — which is where the campaign
 * that motivated it came from.
 *
 * The labels are taken from the brand's own domains (`axisbank` from
 * `axisbank.com`), not from its phrases, so a brand named by a phrase like
 * "state bank of india" is matched on the label it actually registers.
 *
 * Except the domains under a {@link REGISTRANT_VERIFIED_SUFFIXES} namespace.
 * `axis.bank.in` is Axis Bank's because only a licensed bank can hold a name
 * under `bank.in` — the label `axis` says so only INSIDE that registry. Keyed
 * on here it would forgive `axis-login.example` for Axis Bank, which is the
 * lookalike this exemption must not widen to. Such a domain is matched by the
 * list itself ({@link brandOwningDomain}), never by its label.
 */
export function domainCarriesBrandName(
  brand: ProtectedBrand,
  senderDomain: string | null | undefined,
): boolean {
  const label = parseHost((senderDomain ?? '').toLowerCase()).domainWithoutSuffix;
  if (!label) return false;
  return brand.domains.some((domain) => {
    const parsed = parseHost(domain);
    if (parsed.publicSuffix && REGISTRANT_VERIFIED_SUFFIXES.includes(parsed.publicSuffix)) {
      return false;
    }
    const own = parsed.domainWithoutSuffix;
    return !!own && own.length >= BRAND_LABEL_MIN_CHARS && label.includes(own);
  });
}

/**
 * A mailing list or a group that rewrites From for DMARC's sake writes the
 * original author's name followed by ` via ` and its own — `"Alex Carter via
 * Sales Team" <sales@groups.example>`. The name in front of ` via ` is a
 * claim about the AUTHOR, made by the list, and the address is the list's;
 * judging that pair as impersonation would flag every brand that posts to a
 * Google Group. The header scorer additionally exempts anything carrying a
 * `List-Id`, which this entry, having no headers, cannot see.
 */
const LIST_REWRITE_MARKER = ' via ';

/**
 * The protected brand a display name borrows on an address that is not the
 * brand's own, or null when the name borrows nothing — or when it is the
 * brand itself writing.
 *
 * @param brands the list to consult. Defaults to {@link PROTECTED_BRANDS}; pass `[...PROTECTED_BRANDS, yours]` to add to it, or your own list to replace it.
 */
export function impersonatedBrand(
  fromName: string | null | undefined,
  senderDomain: string | null | undefined,
  brands: readonly ProtectedBrand[] = PROTECTED_BRANDS,
): ProtectedBrand | null {
  const name = normalizeForMatching(fromName);
  if (!name || name.includes(LIST_REWRITE_MARKER)) return null;
  // The brand writing under its own name is the arrangement working.
  if (brandOwningDomain(senderDomain, brands)) return null;
  const brand = brandsNamedIn(name, brands)[0];
  if (!brand) return null;
  // ...and so is the brand writing from a domain the list has not heard of
  // but that carries its name. See {@link domainCarriesBrandName}.
  return domainCarriesBrandName(brand, senderDomain) ? null : brand;
}

/**
 * Assess the sender identity from the always-available From name + address.
 *
 * DANGER when the display name references a different registrable domain than
 * the one the mail was sent from (the classic display-name spoof), or borrows
 * a protected brand's name on an address outside that brand's domains;
 * CAUTION when the sender domain is punycode/IDN, which can be a homograph of
 * a real brand and can equally be somebody's perfectly ordinary non-Latin
 * domain — which is why it is a caution and not a verdict.
 *
 * The two DANGER checks are exclusive: a name like `"PayPal <service@paypal.com>"`
 * on evil.ru names PayPal's domain AND PayPal's brand, and it is one lie. The
 * domain check speaks, because it is the more specific claim, and the brand
 * check is only consulted when no domain was named.
 *
 * @param brands the protected brands to judge the name against. Defaults to {@link PROTECTED_BRANDS}; pass `[...PROTECTED_BRANDS, yours]` to add to it, or your own list to replace it —
 *   a mail client adds the mailbox owner's own organisation this way.
 */
export function assessSender(
  fromName: string | null | undefined,
  fromAddress: string | null | undefined,
  brands: readonly ProtectedBrand[] = PROTECTED_BRANDS,
): PhishingReason[] {
  const reasons: PhishingReason[] = [];
  const senderDomain = domainOfAddress(fromAddress);
  if (!senderDomain) return reasons;

  const nameDomains = domainsInText(fromName).filter((domain) => domain !== senderDomain);
  if (nameDomains.length > 0) {
    reasons.push({
      kind: 'domain',
      severity: 'danger',
      text: `The sender name mentions ${nameDomains.join(', ')}, but this email was actually sent from ${senderDomain}.`,
    });
  } else {
    const shown = fromName?.trim();
    const brand = shown ? impersonatedBrand(shown, senderDomain, brands) : null;
    if (brand) {
      reasons.push({
        kind: 'brand',
        severity: 'danger',
        text: `The sender name "${shown}" borrows the ${brand.name} name, but this email was actually sent from ${senderDomain}, which does not belong to ${brand.name}.`,
      });
    }
  }

  if (senderDomain.includes('xn--')) {
    reasons.push({
      kind: 'punycode',
      severity: 'caution',
      text: `The sender domain "${senderDomain}" uses punycode, which can be used to imitate a well-known brand.`,
    });
  }

  return reasons;
}
