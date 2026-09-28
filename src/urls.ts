/**
 * What a link in a message actually points at.
 *
 * Shared by the deceptive-link check a mail client renders (`links.ts`) and the
 * body-content rules that score one at ingest (`content/`). One implementation
 * on purpose: the pair of them exist to agree, and a UI that draws a warning
 * the scanner did not charge points for — or the reverse — is the same message
 * telling the user two different stories.
 *
 * Everything here is structural. It reads the URL the way a browser will and
 * reports what it finds; it never asks whether a domain is reputable, which
 * needs the network and belongs in a later stage.
 */
import { parse as parseHost } from 'tldts';

import { domainsInText } from './identity.js';

/**
 * Common ESP / link-tracker / URL-shortener registrable domains. Legitimate
 * marketing mail routinely wraps links through these, so a "text says
 * brand.com, href is <esp>" mismatch there is expected, not deceptive — skip
 * them to keep the signal meaningful, because a warning that fires on ordinary
 * newsletters is a warning people learn to click past.
 *
 * Contributions: add a host that exists to COUNT a click and redirect. Do not
 * add a host merely because one sender abused it — these carry ordinary mail
 * too, and blocking the carrier punishes everyone who uses it.
 */
export const LINK_WRAPPER_DOMAINS: ReadonlySet<string> = new Set<string>([
  'amazonses.com',
  'bit.ly',
  'cmail19.com',
  'cmail20.com',
  'createsend.com',
  'doubleclick.net',
  'exct.net',
  'goo.gl',
  'google.com',
  'hs-sending.com',
  'hubs.ly',
  'hubspot.com',
  'hubspotlinks.com',
  'list-manage.com',
  'lnkd.in',
  'mailchimp.com',
  'mailgun.org',
  'mandrillapp.com',
  'marketo.com',
  'ow.ly',
  'pardot.com',
  'rs6.net',
  'safelinks.protection.outlook.com',
  'salesforce.com',
  'sendclean.net',
  'sendgrid.net',
  'sendible.com',
  'sparkpostmail.com',
  't.co',
  'tinyurl.com',
]);

/** One http(s) link, read structurally. */
export interface LinkTarget {
  /** The href as written. */
  href: string;
  /** Lowercased hostname, with no userinfo and no port. */
  host: string;
  /** Registrable domain (eTLD+1), or null for an IP literal or a non-public host. */
  domain: string | null;
  /** The host is a bare IP address rather than a name. */
  isIp: boolean;
  /**
   * The URL carries credentials before the host — `https://paypal.com@evil.ru/`.
   * Everything left of the `@` is userinfo and is NOT where the link goes, but
   * it is the part a reader's eye stops at, which is the entire point of
   * writing one.
   */
  hasUserinfo: boolean;
  /** The host is IDN-encoded, so it may be a homograph of a familiar name. */
  isPunycode: boolean;
}

/**
 * Read one href, or null when there is nothing to read.
 *
 * Null for anything that is not http(s): `mailto:`, `tel:`, `#anchor` and
 * `cid:` are not places to be sent, and a rule that treated them as such would
 * charge points for the unsubscribe link at the bottom of a legitimate mail.
 */
export function linkTarget(href: string | null | undefined): LinkTarget | null {
  if (!href) return null;
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const host = url.hostname.toLowerCase();
  const parsed = parseHost(host, { allowPrivateDomains: false });
  return {
    href,
    host,
    domain: parsed.domain,
    isIp: parsed.isIp === true,
    hasUserinfo: url.username !== '' || url.password !== '',
    isPunycode: host.includes('xn--'),
  };
}

/**
 * http(s) URLs written out in plain text.
 *
 * Tokenised on whitespace and the characters that bracket a URL in prose, then
 * handed to {@link linkTarget} to adjudicate — no pattern here tries to
 * recognise a URL itself. Trailing sentence punctuation is trimmed, because
 * "see https://example.com." ends with a full stop that is not part of the
 * address.
 */
export function urlsInText(text: string | null | undefined): string[] {
  if (!text) return [];
  const found: string[] = [];
  for (const rawToken of text.split(/[\s<>"'`(),;[\]{}]+/)) {
    const token = rawToken.replace(/[.,;:!?]+$/, '');
    if (/^https?:\/\//i.test(token)) found.push(token);
  }
  return found;
}

/** One deceptive link: the domain the text shows vs the domain the href goes to. */
export interface LinkMismatch {
  shown: string;
  actual: string;
}

/** An anchor as the reader meets it, for {@link anchorMismatches}. */
export interface AnchorLike {
  href: string;
  text: string;
}

/**
 * The domains an anchor's visible text names that are NOT where it goes.
 *
 * Shared by the two questions that both need it and must agree: which anchors
 * are deceptive ({@link anchorMismatches}), and — for an anchor that leaves the
 * sender's domain — which trust rule the user would have written about it. A
 * rule is keyed by the pair the reader saw, so a second copy of this selection
 * that chose a different name would look up a key nobody ever stored.
 *
 * A link wrapper is neither end of a lie: mail that goes out through one shows
 * its own brand and arrives via the wrapper's domain, which is the arrangement
 * working, not a trick.
 */
export function shownDomains(anchor: AnchorLike, actual: string): string[] {
  return domainsInText(anchor.text).filter(
    (shown) => shown !== actual && !LINK_WRAPPER_DOMAINS.has(shown),
  );
}

/**
 * Anchors whose visible text names one registrable domain while the href goes
 * to another.
 *
 * De-duplicated, and capped at three: the fourth example of the same trick
 * persuades nobody who was not already persuaded by the first.
 */
export function anchorMismatches(anchors: readonly AnchorLike[]): LinkMismatch[] {
  const seen = new Set<string>();
  const out: LinkMismatch[] = [];
  for (const anchor of anchors) {
    if (out.length >= 3) break;
    const target = linkTarget(anchor.href);
    const actual = target?.domain;
    if (!actual || LINK_WRAPPER_DOMAINS.has(actual)) continue;
    for (const shown of shownDomains(anchor, actual)) {
      const key = `${shown}->${actual}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ shown, actual });
      break;
    }
  }
  return out;
}
