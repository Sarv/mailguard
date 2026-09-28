import { describe, expect, it } from 'vitest';

import {
  assessmentOf,
  authenticationFailed,
  canonicalReasonId,
  isSpamScore,
  mergeAssessments,
  parseSpamReasons,
  rollUpAuthStatus,
  spamVerdict,
  stageOfReason,
  SPAM_REASON_STAGES,
  SPAM_THRESHOLD,
  SUSPICIOUS_THRESHOLD,
  unknownAuthStatus,
  type AuthStatus,
  type SpamReason,
  type SpamStage,
} from '../src/verdict.js';

/**
 * The stored verdict: where the line is, and reading reasons back.
 *
 * What this protects: this module is the ONLY thing a reader (a shield, a
 * report, another service) needs in order to agree with the scanner about
 * what a number means. If the reader and the scanner ever disagree about the
 * threshold, a message is filed as spam and displayed as clean, which is the
 * one outcome worse than either verdict on its own — the user is told the
 * mail is fine and never sees it again.
 */
// The one rule the scorer, the shield and sender trust share. If it drifts,
// a trusted address that failed DMARC — a forgery of it — sails through, or a
// forwarded message with a broken DKIM under a passing DMARC turns red.
describe('authenticationFailed', () => {
  const status = (over: Partial<AuthStatus>): AuthStatus => ({
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    overall: 'pass',
    ...over,
  });

  it('is DMARC failing, whatever SPF and DKIM said', () => {
    expect(authenticationFailed(status({ dmarc: 'fail' }))).toBe(true);
    expect(authenticationFailed(status({ dmarc: 'pass', spf: 'fail', dkim: 'fail' }))).toBe(false);
  });

  it('falls back to SPF and DKIM both failing only when DMARC gave no verdict', () => {
    expect(authenticationFailed(status({ dmarc: 'none', spf: 'fail', dkim: 'fail' }))).toBe(true);
    expect(authenticationFailed(status({ dmarc: 'unknown', spf: 'fail', dkim: 'pass' }))).toBe(
      false,
    );
  });

  it('is not a failure when nothing was asserted', () => {
    expect(authenticationFailed(null)).toBe(false);
    expect(authenticationFailed(undefined)).toBe(false);
    expect(authenticationFailed(unknownAuthStatus())).toBe(false);
  });
});

describe('spamVerdict', () => {
  // Boundaries are inclusive on purpose. A message scoring exactly the
  // threshold IS spam; an off-by-one here silently widens the inbox by one
  // whole rule's worth of mail.
  it('is inclusive at both thresholds', () => {
    expect(spamVerdict(SPAM_THRESHOLD)).toBe('spam');
    expect(spamVerdict(SPAM_THRESHOLD - 0.01)).toBe('suspicious');
    expect(spamVerdict(SUSPICIOUS_THRESHOLD)).toBe('suspicious');
    expect(spamVerdict(SUSPICIOUS_THRESHOLD - 0.01)).toBe('clean');
  });

  it('reads clean for zero and for a negative score', () => {
    expect(spamVerdict(0)).toBe('clean');
    expect(spamVerdict(-3)).toBe('clean');
  });

  // Regression: "never scored" must not read as "scored clean". A message
  // synced before the scanner existed has no verdict, and showing it a green
  // shield claims a check that never ran.
  it('is null — not "clean" — when the message was never scored', () => {
    expect(spamVerdict(null)).toBeNull();
    expect(spamVerdict(undefined)).toBeNull();
    expect(spamVerdict(Number.NaN)).toBeNull();
    expect(spamVerdict(Number.POSITIVE_INFINITY)).toBeNull();
    expect(spamVerdict('5' as unknown as number)).toBeNull();
  });
});

describe('isSpamScore', () => {
  it('is true only at or above the spam threshold', () => {
    expect(isSpamScore(SPAM_THRESHOLD)).toBe(true);
    expect(isSpamScore(SPAM_THRESHOLD + 10)).toBe(true);
    expect(isSpamScore(SUSPICIOUS_THRESHOLD)).toBe(false);
    expect(isSpamScore(null)).toBe(false);
  });
});

describe('parseSpamReasons', () => {
  const reason: SpamReason = { id: 'auth-failed', points: 3, detail: 'DMARC failed' };

  it('round-trips what the scanner wrote', () => {
    expect(parseSpamReasons(JSON.stringify([reason]))).toEqual([reason]);
  });

  // Every one of these is a real stored value: a NULL column, a column written
  // before the feature existed, a truncated write. None may throw — the row
  // that fails to parse is the message the user is trying to open.
  it('reads anything unusable as "no reasons", never a throw', () => {
    expect(parseSpamReasons(null)).toEqual([]);
    expect(parseSpamReasons(undefined)).toEqual([]);
    expect(parseSpamReasons('')).toEqual([]);
    expect(parseSpamReasons('not json')).toEqual([]);
    expect(parseSpamReasons('{"id":"auth-failed"}')).toEqual([]);
    expect(parseSpamReasons('null')).toEqual([]);
    expect(parseSpamReasons('42')).toEqual([]);
  });

  // Regression: Sarv Inbox shipped these four ids before this package
  // existed and they are sitting in stored verdicts on users' disks. A
  // reader that switches on today's union must not fall through to a blank
  // row for mail that was scored last year.
  it('reads a verdict stored under the old ids under the current ones', () => {
    const stored = JSON.stringify([
      { id: 'ip-blocklisted', points: 4, detail: 'listed' },
      { id: 'domain-blocklisted', points: 2, detail: 'listed' },
      { id: 'link-blocklisted', points: 5, detail: 'links to a listed domain' },
      { id: 'user-reported', points: 3, detail: 'reported' },
    ]);

    expect(parseSpamReasons(stored).map((parsed) => parsed.id)).toEqual([
      'reputation-ip-listed',
      'reputation-domain-listed',
      'reputation-link-listed',
      'reputation-user-reported',
    ]);
  });

  // Partial survival, deliberately: one bad element in an array of five should
  // cost the reader that one line, not the whole explanation.
  it('keeps the good elements of a partly-bad array', () => {
    const json = JSON.stringify([
      reason,
      null,
      'nonsense',
      { id: 'missing-date' },
      { id: 'date-skew', points: '2', detail: 'x' },
      { id: 'fake-reply', points: 2, detail: 42 },
    ]);
    expect(parseSpamReasons(json)).toEqual([reason]);
  });
});

describe('canonicalReasonId', () => {
  it('translates every id this package has renamed', () => {
    expect(canonicalReasonId('ip-blocklisted')).toBe('reputation-ip-listed');
    expect(canonicalReasonId('domain-blocklisted')).toBe('reputation-domain-listed');
    expect(canonicalReasonId('link-blocklisted')).toBe('reputation-link-listed');
    expect(canonicalReasonId('user-reported')).toBe('reputation-user-reported');
  });

  // Regression: the table is a translation, not a filter. An id it has never
  // heard of — one this package still uses, or one a newer version wrote —
  // comes back unchanged rather than as undefined.
  it('hands back anything it has no other name for', () => {
    expect(canonicalReasonId('auth-failed')).toBe('auth-failed');
    expect(canonicalReasonId('a-rule-from-a-later-release')).toBe('a-rule-from-a-later-release');
  });
});

/**
 * Which stage owns which reason. The consumer this exists for scores a message
 * in pieces — headers at sync, body on demand — and has to be able to strip
 * its own previous body reasons before writing a re-scored verdict. Get the
 * partition wrong and one rule is charged twice, which looks like nothing at
 * all in a total.
 */
describe('SPAM_REASON_STAGES', () => {
  // Regression: the partition itself, pinned id by id. The Record's type makes
  // a NEW id fail to compile until it is classified; nothing but this list
  // makes a WRONG classification fail, and a body rule filed under 'header'
  // survives every re-score as a second copy of itself.
  it('files every reason under the stage that emits it', () => {
    const byStage = (stage: SpamStage): string[] =>
      Object.entries(SPAM_REASON_STAGES)
        .filter(([, value]) => value === stage)
        .map(([id]) => id)
        .sort();

    expect(byStage('header')).toEqual([
      'auth-failed',
      'brand-impersonation',
      'bulk-no-unsubscribe',
      'date-skew',
      'display-name-spoof',
      'fake-reply',
      'in-reply-to-self',
      'known-spammer',
      'malformed-message-id',
      'missing-date',
      'missing-message-id',
      'no-recipient',
      'precedence-junk',
      'reply-to-freemail',
      'reply-to-mismatch',
      'sender-invalid',
      'sender-punycode',
      'upstream-spam',
    ]);
    expect(byStage('content')).toEqual([
      'content-hidden-text',
      'content-shouting',
      'content-spam-vocabulary',
      'link-bare-ip',
      'link-display-mismatch',
      'link-punycode',
      'link-userinfo',
    ]);
    expect(byStage('attachment')).toEqual([
      'attachment-archive-executable',
      'attachment-double-extension',
      'attachment-encrypted-archive',
      'attachment-executable',
      'attachment-macro',
      'attachment-name-spoof',
      'attachment-type-mismatch',
    ]);
    expect(byStage('reputation')).toEqual([
      'reputation-domain-listed',
      'reputation-domain-new',
      'reputation-ip-listed',
      'reputation-link-listed',
      'reputation-link-new',
      'reputation-user-reported',
    ]);
  });
});

describe('stageOfReason', () => {
  it('names the stage for a current id', () => {
    expect(stageOfReason('auth-failed')).toBe('header');
    expect(stageOfReason('content-shouting')).toBe('content');
    expect(stageOfReason('attachment-macro')).toBe('attachment');
    expect(stageOfReason('reputation-ip-listed')).toBe('reputation');
  });

  // Regression: a verdict stored before the rename carries the OLD id. Read
  // as unclassified, it would be treated as somebody else's reason forever —
  // and the reputation sweep's own reasons would survive its next re-score.
  it('resolves a renamed id to its stage', () => {
    expect(stageOfReason('ip-blocklisted')).toBe('reputation');
    expect(stageOfReason('link-blocklisted')).toBe('reputation');
    expect(stageOfReason('user-reported')).toBe('reputation');
  });

  // Regression: an id from a NEWER release must read as null, not as a guess.
  // Callers treat null as "leave it alone", so a reason this version cannot
  // place survives the re-score instead of quietly lowering the score.
  it('returns null for an id it has never heard of', () => {
    expect(stageOfReason('a-rule-from-a-later-release')).toBeNull();
    expect(stageOfReason('')).toBeNull();
  });
});

/**
 * The two helpers every stage returns through. They exist so that a caller
 * combining the header stage with the body stage never adds numbers by hand —
 * the moment two call sites each compute `isSpam` for themselves, they start
 * disagreeing about the same message.
 */
describe('assessmentOf', () => {
  const reasonWorth = (points: number): SpamReason => ({ id: 'date-skew', points, detail: 'x' });

  it('sums the reasons and answers both thresholds', () => {
    const assessment = assessmentOf([reasonWorth(2), reasonWorth(1)]);
    expect(assessment.score).toBe(3);
    expect(assessment.reasons).toHaveLength(2);
    expect(assessment.suspicious).toBe(true);
    expect(assessment.isSpam).toBe(false);
  });

  it('is clean and not suspicious with no reasons at all', () => {
    expect(assessmentOf([])).toEqual({ score: 0, reasons: [], isSpam: false, suspicious: false });
  });

  // Regression: the thresholds are inclusive. An off-by-one here is a message
  // scoring exactly 5 that never gets filed, which looks like the rule that
  // scored it simply not working.
  it('treats each threshold as a floor, not a bound to exceed', () => {
    expect(assessmentOf([reasonWorth(SUSPICIOUS_THRESHOLD)]).suspicious).toBe(true);
    expect(assessmentOf([reasonWorth(SUSPICIOUS_THRESHOLD - 1)]).suspicious).toBe(false);
    expect(assessmentOf([reasonWorth(SPAM_THRESHOLD)]).isSpam).toBe(true);
    expect(assessmentOf([reasonWorth(SPAM_THRESHOLD - 1)]).isSpam).toBe(false);
  });

  // Regression: spam is a superset of suspicious. A message reported as spam
  // but not suspicious would render as two contradictory badges at once.
  it('never reports spam without also reporting suspicious', () => {
    expect(assessmentOf([reasonWorth(SPAM_THRESHOLD)]).suspicious).toBe(true);
  });
});

describe('mergeAssessments', () => {
  const stage = (points: number): SpamReason => ({ id: 'auth-failed', points, detail: 'x' });

  // Regression: this is the whole point of the seam. Two stages that each fall
  // short of the threshold can only file a message together if their reasons
  // are concatenated and re-totalled, not if their booleans are OR-ed.
  it('adds the stages up, so two partial cases can make a whole one', () => {
    const headers = assessmentOf([stage(3)]);
    const content = assessmentOf([stage(2)]);
    expect(headers.isSpam).toBe(false);
    expect(content.isSpam).toBe(false);
    const merged = mergeAssessments(headers, content);
    expect(merged.score).toBe(5);
    expect(merged.reasons).toHaveLength(2);
    expect(merged.isSpam).toBe(true);
  });

  // Regression: `null` is what a stage returns when it did not judge the
  // message at all — own mail is never spam-scored. Skipping a stage must not
  // throw, and must not be confused with that stage finding nothing.
  it('skips stages that did not run, and merges nothing into a clean verdict', () => {
    expect(mergeAssessments(null, undefined, assessmentOf([stage(2)])).score).toBe(2);
    expect(mergeAssessments()).toEqual({ score: 0, reasons: [], isSpam: false, suspicious: false });
    expect(mergeAssessments(null, undefined)).toEqual({
      score: 0,
      reasons: [],
      isSpam: false,
      suspicious: false,
    });
  });

  it('keeps the reasons in stage order, so the explanation reads top-down', () => {
    const merged = mergeAssessments(
      assessmentOf([{ id: 'auth-failed', points: 1, detail: 'first' }]),
      assessmentOf([{ id: 'content-shouting', points: 1, detail: 'second' }]),
    );
    expect(merged.reasons.map((reason) => reason.detail)).toEqual(['first', 'second']);
  });
});

describe('unknownAuthStatus', () => {
  it('asserts nothing about any of the three', () => {
    expect(unknownAuthStatus()).toEqual({
      spf: 'unknown',
      dkim: 'unknown',
      dmarc: 'unknown',
      overall: 'none',
    });
  });

  // Regression: both producers of an `AuthStatus` fill one in field by field.
  // A shared frozen constant would have them writing into each other's
  // results, so one message's verdict would depend on the one scanned before
  // it — the worst kind of bug to reproduce.
  it('returns a fresh object every time', () => {
    const first = unknownAuthStatus();
    first.spf = 'pass';
    expect(unknownAuthStatus().spf).toBe('unknown');
  });
});

describe('rollUpAuthStatus', () => {
  const components = (
    spf: AuthStatus['spf'],
    dkim: AuthStatus['dkim'],
    dmarc: AuthStatus['dmarc'],
  ): Omit<AuthStatus, 'overall'> => ({ spf, dkim, dmarc });

  // Regression: one failure outranks any number of passes. A sender who
  // controls their own domain can always arrange SPF and DKIM to pass, so two
  // passes next to a DMARC failure is the SHAPE OF A SPOOF, not a near miss —
  // rolling it up as `partial` would show the reader a half-green shield on
  // exactly the message the rules exist to catch.
  it('reports fail when any one component failed, however many passed', () => {
    expect(rollUpAuthStatus(components('pass', 'pass', 'fail'))).toBe('fail');
    expect(rollUpAuthStatus(components('fail', 'unknown', 'unknown'))).toBe('fail');
    expect(rollUpAuthStatus(components('unknown', 'fail', 'none'))).toBe('fail');
  });

  it('reports pass only when at least two of the three passed', () => {
    expect(rollUpAuthStatus(components('pass', 'pass', 'none'))).toBe('pass');
    expect(rollUpAuthStatus(components('pass', 'pass', 'pass'))).toBe('pass');
  });

  it('reports partial for a single pass', () => {
    expect(rollUpAuthStatus(components('pass', 'unknown', 'unknown'))).toBe('partial');
    expect(rollUpAuthStatus(components('none', 'none', 'pass'))).toBe('partial');
  });

  // Regression: `none` is the answer for a message nobody asserted anything
  // about, and `softfail`/`neutral` are assertions that decline to assert.
  // Neither is a failure, and a UI that painted them red would flag most mail
  // from small senders.
  it('reports none when nothing passed and nothing failed', () => {
    expect(rollUpAuthStatus(components('unknown', 'unknown', 'unknown'))).toBe('none');
    expect(rollUpAuthStatus(components('softfail', 'none', 'none'))).toBe('none');
    expect(rollUpAuthStatus(components('neutral', 'unknown', 'none'))).toBe('none');
  });
});
