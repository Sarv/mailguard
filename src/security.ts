/**
 * The ONE place an email's security level is decided.
 *
 * Three very different kinds of evidence feed it, and the level is honest
 * about which it has:
 *
 *   AUTHENTICATION — SPF / DKIM / DMARC as the receiving server recorded them
 *   in Authentication-Results. The only AUTHORITATIVE signal: it says whether
 *   the sending domain really sent the mail. Absent for many small senders,
 *   which is "unverifiable", not "suspicious".
 *
 *   HEURISTICS — display-name impersonation and links whose text names one
 *   domain while the href goes to another. High-signal tells, but tells, not
 *   proof; a caller's trust list can retire a pair the user has vetted.
 *
 *   SPAM SCORE — the header-stage score, as computed when the message arrived.
 *   Passed in rather than recomputed: the verdict shown to a reader must be
 *   the verdict that actually filed the message, not a fresh one from a newer
 *   rule set that would explain a decision nobody made.
 *
 *   BRAND IDENTITY — what the sender's domain publishes about its own logo,
 *   as `/brand` resolved it. Reported, never scored: a domain with no BIMI
 *   record is not suspicious, and a Verified Mark Certificate proves who owns
 *   a brand, not that this message deserves the reader's trust.
 *
 * What is deliberately NOT here: the human copy for each level. A library
 * cannot know the product's voice, its language, or its reading age. Callers
 * map the level to their own strings.
 */
import type { BimiStatus } from './brand/bimi.js';
import { assessSender, registrableDomain, type ProtectedBrand } from './identity.js';
import {
  linkDomainsAllMatch,
  linkMismatches,
  summarizeLinkDomains,
  type LinkDomainSummary,
  type LinkMismatch,
  type OffDomainLink,
} from './links.js';
import {
  authenticationFailed,
  parseSpamReasons,
  spamVerdict,
  type AuthStatus,
  type SpamReason,
  type SpamVerdict,
} from './verdict.js';

/**
 * From safest to most dangerous. Ordered so callers can compare with `>`
 * via {@link LEVEL_RANK} — "escalate the thread banner to the worst message".
 */
export type SecurityLevel = 'verified' | 'authenticated' | 'unverified' | 'caution' | 'danger';

export const LEVEL_RANK: Record<SecurityLevel, number> = {
  verified: 0,
  authenticated: 1,
  unverified: 2,
  caution: 3,
  danger: 4,
};

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'unknown';

/** One line of the explanation: what was checked and how it came out. */
export interface SecurityCheck {
  id: 'spf' | 'dkim' | 'dmarc' | 'sender' | 'links' | 'spam' | 'brand';
  label: string;
  status: CheckStatus;
  /** Plain-language detail, e.g. "Text says x.com, link goes to y.com". */
  detail: string;
}

export interface LinkRuleSets {
  /** Keys from {@link linkRuleKey} the user has chosen to trust. */
  trusted: ReadonlySet<string>;
  /** Keys from {@link linkRuleKey} the user has chosen to block. */
  blocked: ReadonlySet<string>;
}

export const EMPTY_RULES: LinkRuleSets = { trusted: new Set(), blocked: new Set() };

/**
 * What the shield needs of a BIMI lookup: the standing, who proved it, and
 * why. A whole `BimiLookup` from `/brand` satisfies it, and so does the
 * handful of columns a caller cached from one — the status is the only part
 * that must be there. Typed against `/brand`'s own union so the two cannot
 * drift apart, and imported as a TYPE, so nothing about this entry's
 * dependency cost changes.
 */
export interface BrandIdentity {
  status: BimiStatus;
  organization?: string | null;
  issuer?: string | null;
  detail?: string | null;
}

export interface SecurityAssessment {
  level: SecurityLevel;
  checks: SecurityCheck[];
  /**
   * A check that needs the message body has not run, because the caller said
   * the body is not loaded yet ({@link SecurityInput.bodyLoaded}).
   *
   * The level is then PROVISIONAL and can move either way once the body
   * arrives: up to `verified` if every link the sender wrote stays on their
   * own domain,
   * down to `caution` or `danger` if one does not. A UI that lazy-loads
   * bodies should say "still checking" rather than render a provisional
   * clean level as a finding — but it must still render `caution` and
   * `danger`, which come from the headers and are already final.
   */
  pending: boolean;
  /** Deceptive links found and NOT covered by a trust rule — what "I trust this" acts on. */
  untrustedLinks: LinkMismatch[];
  /** Deceptive links the user has explicitly blocked — forces `danger`. */
  blockedLinks: LinkMismatch[];
  /** Registrable domain of the sender, or null when the address is unusable. */
  senderDomain: string | null;
  /** The spam verdict; `verdict` is null when the message was never scored. */
  spam: { verdict: SpamVerdict | null; score: number | null; reasons: SpamReason[] };
  /**
   * The reader's trust in this sender was APPLIED: they vouched for the
   * address ({@link SecurityInput.trustedSender}) and the message
   * authenticated. False when they did not, and false when they did but the
   * message failed authentication — trust is then set aside, not honoured.
   */
  trusted: boolean;
}

/**
 * The identity of a trust/block rule. Scoped to the SENDER domain on purpose:
 * trusting "x.com -> y.com" for everyone would let ANY sender use that
 * redirect unflagged, and a compromised known account is the usual way
 * phishing arrives from a familiar name.
 */
export function linkRuleKey(senderDomain: string, shown: string, actual: string): string {
  return `${senderDomain}|${shown}|${actual}`.toLowerCase();
}

/** Parse a stored auth_status JSON blob; anything unreadable is "no verdict", never a throw. */
export function parseAuthStatus(raw: string | null | undefined): AuthStatus | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<AuthStatus> | null;
    if (!value || typeof value !== 'object') return null;
    return {
      spf: value.spf ?? 'unknown',
      dkim: value.dkim ?? 'unknown',
      dmarc: value.dmarc ?? 'unknown',
      overall: value.overall ?? 'none',
    };
  } catch {
    return null;
  }
}

const authCheck = (
  id: 'spf' | 'dkim' | 'dmarc',
  label: string,
  value: string | undefined,
  passText: string,
  failText: string,
): SecurityCheck => {
  if (value === 'pass') return { id, label, status: 'pass', detail: passText };
  if (value === 'fail') return { id, label, status: 'fail', detail: failText };
  if (value === 'softfail' || value === 'neutral') {
    return {
      id,
      label,
      status: 'warn',
      detail: `${label} returned ${value} — the sender's policy did not vouch for this server`,
    };
  }
  return {
    id,
    label,
    status: 'unknown',
    detail: `The receiving server recorded no ${label} verdict`,
  };
};

/**
 * What the Links row says when nothing in the body was deceptive.
 *
 * Three different facts hide behind that one tick, and until they were spelt
 * out here two of them produced the same sentence under two different badges:
 * a message whose links all stay home is `verified`, one that links out to a
 * document or a tracker is `authenticated`, and the reader saw "Link domains
 * match what they show" in both places with no way to tell which fact had
 * decided it. Naming the destinations turns the badge into something a person
 * can check.
 *
 * The no-links case gets its own sentence rather than the reassuring one.
 * Nothing was examined, and a check that says it passed when it never ran is
 * the reason the other lines are worth reading.
 */
function linkPassDetail(
  summary: LinkDomainSummary,
  stray: readonly OffDomainLink[],
  trustedCount: number,
  senderDomain: string | null,
): string {
  if (summary.linkCount === 0) return 'The sender wrote no links in this message';
  const vetted = trustedCount
    ? ` (${trustedCount} pair${trustedCount > 1 ? 's' : ''} you trust)`
    : '';
  const honest = `Link domains match what they show${vetted}`;
  if (!senderDomain) return honest;
  if (summary.offDomain.length === 0) return `${honest}, and every link stays on ${senderDomain}`;
  // Links DID leave, and the level is the top one anyway, because the reader
  // forgave each of them. Saying "every link stays on the domain" here would
  // be the flattering lie this function exists to stop telling.
  if (stray.length === 0) {
    const forgiven = summary.offDomain.length;
    const many = forgiven > 1;
    return `${honest}; ${forgiven} link${many ? 's' : ''} leave${many ? '' : 's'} ${senderDomain}, and you have trusted ${many ? 'them' : 'it'}`;
  }
  const destinations = [...new Set(stray.map((link) => link.actual))];
  const named = destinations.slice(0, 2).join(', ');
  const more = destinations.length > 2 ? `, +${destinations.length - 2} more` : '';
  const plural = stray.length > 1;
  return `${honest}; ${stray.length} link${plural ? 's' : ''} leave${plural ? '' : 's'} ${senderDomain} (${named}${more})`;
}

export interface SecurityInput {
  fromName?: string | null;
  fromAddress?: string | null;
  /** The message body as HTML, for the link checks. */
  html?: string | null;
  /**
   * Whether `html` is the message's real body. Default true.
   *
   * Pass `false` while the body is still being fetched. An absent body is not
   * a body with no links in it, and the difference is the whole verdict: read
   * as "checked, nothing found" it makes every unfetched message `verified`
   * — the top level, awarded for a body nobody has looked at. With `false`
   * the links check reports `unknown`, the level stops at `authenticated`,
   * and {@link SecurityAssessment.pending} says so.
   */
  bodyLoaded?: boolean;
  /** A stored `AuthStatus` — either the object, or the JSON string it was stored as. */
  auth?: AuthStatus | string | null;
  /** The header-stage score, as computed when the message arrived. */
  spamScore?: number | null;
  /** The stored reasons — either the array, or the JSON string they were stored as. */
  spamReasons?: readonly SpamReason[] | string | null;
  /** The user's trust/block rules. Defaults to none. */
  rules?: LinkRuleSets;
  /**
   * The sender domain's BIMI standing, if the caller has looked it up — a
   * `BimiLookup` from `/brand`, or the columns it cached from one.
   *
   * Three states, not two: leave it `undefined` and the shield says nothing
   * about the brand at all, pass `null` and it says "not looked up yet".
   * A reader who has been shown a tick on this sender before is owed the
   * difference between "no mark" and "we have not asked yet".
   */
  bimi?: BrandIdentity | null;
  /**
   * The protected brands the sender name is judged against. Defaults to
   * `PROTECTED_BRANDS`. Pass the same list the scorer was given, or the
   * shield and the score will disagree about the same name.
   */
  brands?: readonly ProtectedBrand[];
  /**
   * The reader has vouched for this exact sender address ("Trust this
   * sender"). When the message authenticated, the sender-name check and the
   * spam score stop counting against it: the reader knows who this is, and a
   * bank alert they trust must not keep arriving under a red shield. Links,
   * blocked links and authentication are still judged — trust in a sender is
   * not trust in every URL their mail carries.
   *
   * Set aside when authentication FAILED ({@link authenticationFailed}): the
   * From address is exactly what a forger copies, so a trusted address that
   * did not authenticate is the likeliest forgery of all, and the sender check
   * says so.
   */
  trustedSender?: boolean;
}

/** Decide the level for one message. */
export function assessEmailSecurity(input: SecurityInput): SecurityAssessment {
  const rules = input.rules ?? EMPTY_RULES;
  const senderDomain = registrableDomain(input.fromAddress?.split('@')[1] ?? null);
  const auth = typeof input.auth === 'string' ? parseAuthStatus(input.auth) : (input.auth ?? null);
  const authFailed = authenticationFailed(auth);
  const trusted = input.trustedSender === true && !authFailed;

  const dkimCheck = authCheck(
    'dkim',
    'DKIM',
    auth?.dkim,
    'The message signature is valid — it was not altered in transit',
    'The message signature is INVALID — it was altered or forged',
  );
  if (auth?.dkim === 'fail' && auth?.dmarc === 'pass') {
    // A broken DKIM signature under a PASSING DMARC is routine: a mailing list
    // or forwarder re-wrote the message and invalidated one signature, while
    // SPF (or another signature) still aligned with the From domain. Reporting
    // it as a failure put a red shield on bank statements — a false alarm that
    // teaches the reader to ignore red. Keep it visible, as a warning.
    dkimCheck.status = 'warn';
    dkimCheck.detail =
      'A signature was broken in transit, but DMARC still passed — the sender’s domain is confirmed';
  }
  const checks: SecurityCheck[] = [
    authCheck(
      'spf',
      'SPF',
      auth?.spf,
      'The sending server is authorised for this domain',
      'The sending server is NOT authorised for this domain',
    ),
    dkimCheck,
    authCheck(
      'dmarc',
      'DMARC',
      auth?.dmarc,
      'The domain owner’s policy accepts this message',
      'The domain owner’s policy REJECTS this message',
    ),
  ];

  // Display-name impersonation.
  const spoof = assessSender(input.fromName, input.fromAddress, input.brands);
  checks.push(
    input.trustedSender === true && authFailed
      ? {
          id: 'sender',
          label: 'Sender name',
          status: 'fail',
          detail:
            'You trust this address, but this message failed authentication — it may be a forgery of it',
        }
      : trusted
        ? {
            id: 'sender',
            label: 'Sender name',
            status: 'pass',
            detail: 'You trust this sender, and this message authenticated',
          }
        : spoof.length
          ? {
              id: 'sender',
              label: 'Sender name',
              status: 'fail',
              detail: (spoof[0] as { text: string }).text,
            }
          : {
              id: 'sender',
              label: 'Sender name',
              status: 'pass',
              detail: 'The display name does not impersonate another domain',
            },
  );

  // Deceptive links, minus the pairs the user has vetted. A body the caller
  // has not fetched yet yields no links to read — and, crucially, is not
  // reported as a body with none.
  const bodyLoaded = input.bodyLoaded !== false;
  const all = bodyLoaded ? linkMismatches(input.html) : [];
  const key = (m: LinkMismatch): string => linkRuleKey(senderDomain ?? '', m.shown, m.actual);
  const blockedLinks = all.filter((m) => rules.blocked.has(key(m)));
  const untrustedLinks = all.filter(
    (m) => !rules.trusted.has(key(m)) && !rules.blocked.has(key(m)),
  );
  const trustedCount = all.length - blockedLinks.length - untrustedLinks.length;

  // Where the sender's own links GO — a different question from whether any of
  // them lies about where it goes, and the one that separates `verified` from
  // `authenticated` below. Both answers have to reach the reader: a checklist
  // that reports only the deception test shows an identical row of ticks under
  // two different badges, and the difference then looks like a bug in the
  // shield rather than a fact about the mail.
  // An unloaded body summarises to nothing, which never reaches a reader: the
  // branch below reports "not downloaded yet" on its own.
  const linkDomains = summarizeLinkDomains(bodyLoaded ? input.html : null, senderDomain);
  const isVetted = (link: OffDomainLink): boolean =>
    link.shown.some((shown) => rules.trusted.has(key({ shown, actual: link.actual })));
  const strayLinks = linkDomains.offDomain.filter((link) => !isVetted(link));

  if (!bodyLoaded) {
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'unknown',
      detail: 'The message body has not been downloaded yet, so its links are unchecked',
    });
  } else if (blockedLinks.length) {
    const first = blockedLinks[0] as LinkMismatch;
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'fail',
      detail: `A link you have blocked: text says ${first.shown}, goes to ${first.actual}`,
    });
  } else if (untrustedLinks.length) {
    const first = untrustedLinks[0] as LinkMismatch;
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'warn',
      detail: `Text says ${first.shown}, link goes to ${first.actual}${
        untrustedLinks.length > 1 ? ` (+${untrustedLinks.length - 1} more)` : ''
      }`,
    });
  } else {
    checks.push({
      id: 'links',
      label: 'Links',
      status: 'pass',
      detail: linkPassDetail(linkDomains, strayLinks, trustedCount, senderDomain),
    });
  }

  // The spam verdict, as computed when the message arrived. Shown with its
  // reasons so "filed as spam" is never a bare adjective either.
  const spamScore =
    typeof input.spamScore === 'number' && Number.isFinite(input.spamScore)
      ? input.spamScore
      : null;
  const verdict = spamVerdict(spamScore);
  const spamReasons =
    typeof input.spamReasons === 'string'
      ? parseSpamReasons(input.spamReasons)
      : [...(input.spamReasons ?? [])];
  const spam = { verdict, score: spamScore, reasons: spamReasons };
  const spamSummary = spamReasons.map((r) => r.detail).join('; ');
  if (trusted && (verdict === 'spam' || verdict === 'suspicious')) {
    // Shown, not hidden: the reader should still be able to see what the
    // filter found, only not have it held against a sender they vouched for.
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'pass',
      detail: `Scored ${spamScore}, set aside because you trust this sender — ${spamSummary}`,
    });
  } else if (verdict === 'spam') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'fail',
      detail: `Scored ${spamScore} — ${spamSummary}`,
    });
  } else if (verdict === 'suspicious') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'warn',
      detail: `Scored ${spamScore} — ${spamSummary}`,
    });
  } else if (verdict === 'clean') {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'pass',
      detail: spamReasons.length
        ? `Scored ${spamScore} — ${spamSummary}`
        : 'No spam signals in the headers',
    });
  } else {
    checks.push({
      id: 'spam',
      label: 'Spam filter',
      status: 'unknown',
      detail: 'Not scored — this message was never put through the filter',
    });
  }

  // Brand identity (BIMI), when the caller has looked it up. The logo and the
  // tick belong to a message only on a DMARC pass: the certificate says who
  // owns the brand, DMARC says this message came from them. It is reported so
  // the shield can explain a tick's ABSENCE — a reader who saw a logo on the
  // last message from this sender will otherwise read its disappearance as
  // nothing at all.
  if (input.bimi !== undefined) {
    checks.push(brandCheck(input.bimi, auth?.dmarc === 'pass', senderDomain));
  }

  const result = (level: SecurityLevel): SecurityAssessment => ({
    level,
    checks,
    pending: !bodyLoaded,
    untrustedLinks,
    blockedLinks,
    senderDomain,
    spam,
    trusted,
  });

  // ---- the level ---------------------------------------------------------
  // Hard failures first: an authoritative FAIL, an impersonating display name,
  // or a link the user explicitly blocked. Nothing below can soften these.
  //
  // "Authoritative" means DMARC. It is the check that asks whether the domain
  // in From: is the domain that actually authenticated — the question a reader
  // cares about. SPF and DKIM are its inputs: either one can fail for benign
  // reasons (a forwarder, a list, a second signature) while DMARC still
  // passes, and treating ANY component failure as failure turned those into
  // red shields on legitimate bank and travel mail. Only when the server
  // recorded no DMARC verdict at all do we fall back to "both inputs failed".
  //
  // A sender the reader trusts is not impersonating anybody to them: the name
  // check stops counting once the message authenticated (see `trusted`).
  const dmarcKnown = auth?.dmarc === 'pass' || auth?.dmarc === 'fail';
  if (authFailed || (spoof.length > 0 && !trusted) || blockedLinks.length > 0) {
    return result('danger');
  }

  // Soft signals: an unvetted deceptive link, a policy that declined to vouch,
  // a single failed input with no DMARC verdict to settle the question — or
  // the filter having scored it spam. Spam is caution, not danger: the reasons
  // that make spam DANGEROUS (a failed DMARC, a spoofed name) already score
  // danger on their own above; the rest is unwanted, not impersonation.
  const softAuth =
    auth?.spf === 'softfail' ||
    auth?.spf === 'neutral' ||
    (!dmarcKnown && (auth?.spf === 'fail' || auth?.dkim === 'fail'));
  if (untrustedLinks.length > 0 || softAuth || (verdict === 'spam' && !trusted)) {
    return result('caution');
  }

  // Clean. Now: how STRONGLY do we know who sent it? DMARC pass settles it;
  // without a DMARC verdict, SPF and DKIM both passing is the next best thing.
  const authPassed =
    auth?.dmarc === 'pass' || (!dmarcKnown && auth?.spf === 'pass' && auth?.dkim === 'pass');
  if (authPassed) {
    // Fully authenticated AND every link the sender wrote stays on their own
    // domain, or is a pair the user vetted: the top level. A newsletter that
    // passes DMARC but links out to its CDN and tracker is authenticated, not
    // verified — real, but not "everything in this mail is the sender".
    // `verified` is the claim that EVERYTHING in this mail is the sender's
    // own — it cannot be made about a body that has not been read. Quoted
    // history is exempt: it is the mail being ANSWERED, not this one, and
    // holding its links against the replier denied `verified` to every
    // message after the first in a thread.
    //
    // The vetted pairs are honoured HERE and not only in the checks above.
    // Trusting a pair used to lift the message out of `caution` and then leave
    // it one rung short of the top for the very link that had just been
    // forgiven — the rule appeared to work and then visibly did not, which
    // reads as the setting being ignored.
    return result(
      bodyLoaded && linkDomainsAllMatch(input.html, senderDomain, isVetted)
        ? 'verified'
        : 'authenticated',
    );
  }
  return result('unverified');
}

/**
 * One line about the sender's mark.
 *
 * It never moves the level, in either direction. A verified mark proves who
 * owns the domain — which DMARC already settled for this message — and the
 * overwhelming majority of legitimate senders publish no mark at all, so
 * scoring its absence would put a warning on most of the world's mail.
 */
function brandCheck(
  bimi: BrandIdentity | null,
  dmarcPass: boolean,
  senderDomain: string | null,
): SecurityCheck {
  const check = (status: CheckStatus, detail: string): SecurityCheck => ({
    id: 'brand',
    label: 'Brand identity',
    status,
    detail,
  });
  if (!bimi) return check('unknown', 'Not looked up yet');
  switch (bimi.status) {
    case 'verified':
      return dmarcPass
        ? check(
            'pass',
            `${bimi.organization ?? 'The brand'} proved ownership of ${senderDomain ?? 'this domain'} with a Verified Mark Certificate from ${bimi.issuer ?? 'a Mark Verifying Authority'}`,
          )
        : check(
            'warn',
            'The domain publishes a verified logo, but this message did not pass DMARC — logo and tick withheld',
          );
    case 'logo':
      return dmarcPass
        ? check('pass', 'The domain publishes a BIMI logo, without a Verified Mark Certificate')
        : check(
            'warn',
            'The domain publishes a logo, but this message did not pass DMARC — logo withheld',
          );
    case 'declined':
      return check('unknown', 'The domain declines to show a logo');
    case 'none':
      return check('unknown', 'The domain publishes no BIMI record');
    case 'invalid':
      return check(
        'unknown',
        `BIMI record unusable: ${bimi.detail ?? 'the record could not be read'}`,
      );
  }
  // 'error' — the lookup itself did not finish. Deliberately not a warning
  // about the SENDER: a resolver timeout is a fact about the network here.
  return check(
    'unknown',
    bimi.detail ? `The brand lookup failed: ${bimi.detail}` : 'The brand lookup failed',
  );
}

/** The worst level among several messages — what a thread-level banner shows. */
export function worstLevel(levels: readonly SecurityLevel[]): SecurityLevel {
  return levels.reduce<SecurityLevel>(
    (worst, level) => (LEVEL_RANK[level] > LEVEL_RANK[worst] ? level : worst),
    'verified',
  );
}
