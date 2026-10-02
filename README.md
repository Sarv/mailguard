# mailguard

[![npm version](https://img.shields.io/npm/v/@sarv-in/mailguard.svg)](https://www.npmjs.com/package/@sarv-in/mailguard)
[![npm downloads](https://img.shields.io/npm/dm/@sarv-in/mailguard.svg)](https://www.npmjs.com/package/@sarv-in/mailguard)
[![CI](https://github.com/Sarv/mailguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Sarv/mailguard/actions/workflows/ci.yml)
[![coverage 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/Sarv/mailguard/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@sarv-in/mailguard.svg)](./LICENSE)

Decide whether an email is spam, from the email itself.

**npm:** [`@sarv-in/mailguard`](https://www.npmjs.com/package/@sarv-in/mailguard) ·
**source:** [Sarv/mailguard](https://github.com/Sarv/mailguard) ·
**issues:** [report one](https://github.com/Sarv/mailguard/issues) ·
**contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)

You supply the headers — eventually the whole message — and it gives back a
score, a verdict, and a list of named reasons a human can read. No service to
call, no API key, no model to download. Every rule is a small pure function over
data you already have.

**Status: the header stage, the body-content stage, the attachment stage,
`scan(rawMessage)`, authentication verified against DNS, and blocklist
lookups.** Sixteen header rules, the sender-identity check, deceptive-link
detection, the security-level decision, seven body-content rules, seven
attachment rules and a scanner that takes raw RFC 5322 bytes are all here,
extracted from a mail client that runs them on real mail at ingest. The two
things that touch the network — [live SPF/DKIM/DMARC
verification](#verifying-authentication-yourself) and [blocklist
lookups](#reputation-asking-somebody-else) — are here too, each in its own
entry point you have to ask for by name. What
ships today is listed under [What it does today](#what-it-does-today), and
nothing else is implied. This package will not tell you it checked something it
did not check.

## Contents

- [Install](#install)
- [Entry points](#entry-points)
- [Quick start](#quick-start)
- [Scanning a whole message](#scanning-a-whole-message)
- [What it does today](#what-it-does-today)
- [Scoring model](#scoring-model)
- [The header rules](#the-header-rules)
- [The content rules](#the-content-rules)
- [The attachment rules](#the-attachment-rules)
- [Security levels](#security-levels)
- [Reading a stored verdict back](#reading-a-stored-verdict-back)
- [Origin IP: which address actually sent this](#origin-ip-which-address-actually-sent-this)
- [Authentication results: read, not verified](#authentication-results-read-not-verified)
- [Verifying authentication yourself](#verifying-authentication-yourself)
- [Reputation: asking somebody else](#reputation-asking-somebody-else)
- [Brand marks: BIMI, VMC and favicons](#brand-marks-bimi-vmc-and-favicons)
- [API](#api)
- [Contributing](#contributing)
- [Licence](#licence)

## Install

```bash
npm install @sarv-in/mailguard
# or
pnpm add @sarv-in/mailguard
# or
yarn add @sarv-in/mailguard
```

Node 20 or newer. TypeScript types ship with the package; ESM and CJS both work.
The optional `verify` entry needs `mailauth`, which itself requires Node 22.19
or newer; every other entry runs on 20.

## Entry points

Thirteen, so a browser bundle never has to carry what only a server needs.

| Import | Dependencies | Use it for |
| --- | --- | --- |
| `@sarv-in/mailguard` | `tldts`, `ipaddr.js`, `email-addresses`, `htmlparser2`, `postal-mime` | Everything. The Node entry — the scanner, all three stages, the header primitives. |
| `@sarv-in/mailguard/verdict` | **none** | Reading a stored score/reason back — in a renderer, a worker, anywhere. |
| `@sarv-in/mailguard/headers` | **none** | Reading raw header text: the lookup, and whether the sender declared itself bulk. |
| `@sarv-in/mailguard/attachments` | **none** | The attachment stage: filenames, magic bytes, zip directories. Nothing is unpacked, so nothing is needed to unpack it. |
| `@sarv-in/mailguard/identity` | `tldts` | The sender-spoof rule on its own. |
| `@sarv-in/mailguard/links` | `tldts`, `htmlparser2` | Deceptive-link detection. |
| `@sarv-in/mailguard/security` | `tldts`, `htmlparser2` | The five-level decision, for the UI that renders it. |
| `@sarv-in/mailguard/content` | `tldts`, `htmlparser2` | The body-content stage: vocabulary, quote stripping, link structure. |
| `@sarv-in/mailguard/quote` | **none** | Where somebody else's email begins: the reply/forward cut on its own, for a scorer or a contact miner. |
| `@sarv-in/mailguard/scan` | all of the above + `postal-mime` | `scan(rawMessage)` and the bulk stream. The only entry that costs a MIME parser. |
| `@sarv-in/mailguard/verify` | **none statically** — `mailauth`, an optional peer, is `import`ed on first use | Real SPF/DKIM/DMARC verification against DNS. One of the two entries that can make a network call. |
| `@sarv-in/mailguard/reputation` | `ipaddr.js` — `node:dns` is `import`ed on first use | Blocklist lookups for a sending address or a domain. Node only, and it queries nothing you did not name. |
| `@sarv-in/mailguard/brand` | `tldts`, `htmlparser2` — `@peculiar/x509` and `asn1js`, both optional peers, are `import`ed on first use | The sender's mark: the BIMI logo a domain publishes, the certificate that verifies it, and the favicon that stands in. Runs in a browser; DNS and HTTPS are injected. |
| `@sarv-in/mailguard/age` | `tldts` | When a domain was registered, from the registry's own RDAP record, and what that is worth. Runs in a browser; HTTPS is injected. |

The split exists because the common case in a mail client is displaying a
verdict that was computed at ingest, hours ago, on a server. That side needs
thresholds and a JSON parse, not a scanner.

**Every entry answers the same question the same way in every environment.**
Until v0.2 the `links` and `security` entries parsed HTML with the ambient
`DOMParser`, which meant they found no links at all in Node — the ingest-time
scorer silently reported "no deceptive links" on every message it ever scored,
while the renderer running the identical code on the identical message found
them. HTML is now parsed with `htmlparser2`, so there is one implementation and
one answer. The entry-point dependency table above is pinned by a test that
walks the source import graph, so an accidental import cannot quietly add weight
to a browser bundle.

## Quick start

Hand it a message and it answers:

```ts
import { scan } from '@sarv-in/mailguard/scan';

const result = await scan(await readFile('message.eml'), { authserv: 'mx.example.com' });

// {
//   assessed: true,
//   score: 10,
//   verdict: 'spam',
//   isSpam: true,
//   suspicious: true,
//   reasons: [ { id: 'auth-failed', points: 3, detail: 'DMARC failed — …' }, … ],
//   auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
//   originIp: '185.199.108.1',
//   message: { messageId: null, subject: 'Re: your account', fromName: 'PayPal Support', … },
// }
```

Or use the pieces directly, when you already have them — which is the normal
case inside a mail client, where the IMAP fetch has handed you an envelope and a
header block and parsing the message again would be waste:

```ts
import {
  extractAuthHeaderBlock,
  parseAuthenticationHeaders,
  extractOriginIp,
  assessSender,
  spamVerdict,
} from '@sarv-in/mailguard';

const block = extractAuthHeaderBlock(rawHeaderText);
// Your receiving server's authserv-id, when you know it — see below.
const auth = parseAuthenticationHeaders(block, { authserv: 'mx.example.com' });
// { spf: 'pass', dkim: 'pass', dmarc: 'pass', overall: 'pass' }

const ip = extractOriginIp({ authHeaders: block, received: receivedLines, authserv: 'mx.example.com' });
// '185.199.108.1' — public unicast only, never a private or CGNAT hop

const reasons = assessSender('PayPal Support', 'billing@paypal.secure-login.ru');
// [{ severity: 'danger', text: 'The sender name mentions paypal.com …' }]

spamVerdict(6); // 'spam'
```

Or score the whole thing at once:

```ts
import { assessSpamSignals, headerLookupFromText } from '@sarv-in/mailguard';

const { score, reasons, isSpam } = assessSpamSignals({
  fromName: 'PayPal Support',
  fromAddress: 'billing@paypal.secure-login.ru',
  subject: 'Re: your account',
  messageId: null,
  auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', overall: 'fail' },
  headers: headerLookupFromText(rawHeaderText),
});

// score: 10, isSpam: true
// reasons: [
//   { id: 'auth-failed',        points: 3, detail: 'DMARC failed — …' },
//   { id: 'display-name-spoof', points: 3, detail: 'The sender name mentions paypal.com …' },
//   { id: 'missing-message-id', points: 2, detail: 'No Message-ID header — …' },
//   { id: 'fake-reply',         points: 2, detail: 'Looks like a reply, but …' },
// ]
```

## Scanning a whole message

`scan(raw, options)` parses the message with
[`postal-mime`](https://www.npmjs.com/package/postal-mime), runs the header
stage, the content stage and the attachment stage over it, and returns one JSON
verdict — numbers,
strings and named reason ids, no classes and no functions, so you can store it
and read it back later with `spamVerdict` and `parseSpamReasons` alone. It takes
anything `postal-mime` takes: a string, a `Buffer`, a `Uint8Array`, a `Blob` or
a `ReadableStream`.

**Tell it your authserv-id.** This is the one security decision `scan` makes for
you, and it is worth understanding. `Authentication-Results` is plain text, and
every hop that handles a message can write one — including the sender, who can
simply type `Authentication-Results: dmarc=pass` into their own message before
sending it. RFC 8601 exists for this: your own boundary MTA stamps its
authserv-id (usually its hostname) at the start of the header it writes.

```ts
await scan(raw, { authserv: 'mx.example.com' }); // only that server is believed
```

Without one, `scan` believes only the **topmost** `Authentication-Results`, on
the conventional assumption that your own MTA was the most recent hop — headers
are prepended, so a forged verdict the sender wrote sits below it. That
assumption is usually right and occasionally not: a server that appends its
header, or writes none, leaves a forgery on top. `ARC-Authentication-Results` and
`Received-SPF` never supply the verdict or the origin IP. Neither names its
author, and both are as easy to type as a forged `Authentication-Results`.
`trustedAuthHeaders(headerLines, authserv?)` is exported so you can see exactly
which lines survived.

**Other options.** `receivedAt` (unix seconds) is the delivery time the
date-skew rule compares the sender's `Date:` against; it defaults to the
timestamp on the topmost `Received:` header, and you should pass your IMAP
INTERNALDATE instead when you have one, because you trust your own server's
clock more than a header. `auth` replaces the verdict read from the headers with one you verified
yourself — see
[Verifying authentication yourself](#verifying-authentication-yourself).
`reputation` folds in an assessment from a blocklist lookup you ran yourself —
see [Reputation: asking somebody else](#reputation-asking-somebody-else).
`knownSpammer: true` applies the categorical
5-point rule for a sender the recipient has reported. `ownMail: true` returns
`assessed: false` with a `null` verdict — not judged, which a UI must not render
as a green tick.

**Attachments are scored; their bytes are not handed back.**
`result.message.attachments` gives you each filename and MIME type, and the
`attachment-*` reasons say what the stage made of them — see
[The attachment rules](#the-attachment-rules). The content itself is left out
deliberately: it is the largest thing in a message, and a verdict you store
should stay small enough to store.

### The bulk stream

`scanMany` takes any iterable or async iterable and yields one result per
message:

```ts
import { scanMany } from '@sarv-in/mailguard/scan';

for await (const { id, result, error } of scanMany(messages, { concurrency: 8 })) {
  if (error) log.warn(`${id} could not be read: ${error.message}`);
  else if (result.isSpam) await file(id, result);
}
```

Exactly one of `result` and `error` is set. A message that cannot be read is
**reported, never thrown**: in a run over a real mailbox, one bad message must
not end the run and lose the fifty thousand behind it.

Results come back **in input order** even though the scans overlap, because a
bulk API whose output order depends on how long each message happened to take is
one nobody can write a stable test — or a resumable job — against. The source is
consumed lazily and at most `concurrency` messages are held at once, so this
works on a mailbox larger than memory. Per-message `options` override the shared
ones.

## What it does today

**Sender identity** (`assessSender`) — the friendly name claims one brand while
the address belongs to another registrable domain. Compared at eTLD+1 via
`tldts`, so `mail.paypal.com` vs `paypal.com` does **not** fire, while
`paypal.com` vs `paypal.secure-login.ru` does. A name with no domain in it is
checked against the protected brands in `src/data/brands/`: `"Adobe Acrobat
Sign" <Adobesign@powersublinks.com>` borrows a name whose owner never writes
from that domain, and is reported with the same severity — whatever SPF, DKIM
and DMARC said about powersublinks.com, which the attacker owns and was free
to authenticate. Every entry point that judges a sender takes an optional
`brands` list (default `PROTECTED_BRANDS`), so a client can protect the
mailbox owner's own organisation with `[...PROTECTED_BRANDS, own]`; pass the
same list to the scorer and the shield, or they will disagree about a name.
`pnpm verify:brands` audits the list against the registries and the DNS.

**Authentication results** (`extractAuthHeaderBlock`, `parseAuthenticationHeaders`,
`parseAuthResultsHeader`) — reads the SPF/DKIM/DMARC verdicts your own MTA
already wrote into `Authentication-Results`, with an RFC 8601 parser that knows
which server wrote each one.

**Origin IP** (`extractOriginIp`) — the public address the message actually came
from, taken from your receiving server's own `Authentication-Results` where it
names one and the `Received:` trace otherwise. Private, loopback, link-local, CGNAT and reserved
ranges are rejected, so you get an address worth reputation-checking or nothing.

**Real authentication** (`verifyAuthentication`) — SPF, DKIM and DMARC checked
against live DNS over the original message, rather than read out of a header
somebody else wrote. Its own entry point, its own optional dependency, and
never reached by accident. See
[Verifying authentication yourself](#verifying-authentication-yourself).

**Reputation** (`checkReputation`, `assessReputation`) — what other operators
have already published about the machine that delivered a message and the
domain it claims, asked over DNS. Its own entry point, no default list of zones,
and never reached by accident. See
[Reputation: asking somebody else](#reputation-asking-somebody-else).

**Domain age** (`lookupDomainAge`, `assessDomainAge`) — how long ago the
sender's domain, and the domains a message links to, were registered,
read from the registry's own RDAP record. The one fact about a campaign
domain that is true before anybody has reported it, which is the window a
blocklist is blind in; never enough to file a message on its own. Its own
entry point, its own fetch, and never reached by `scan`. See
[Domain age: how new is the domain](#domain-age-how-new-is-the-domain).

**The header scorer** (`assessSpamSignals`) — eighteen rules over the envelope,
the threading headers, the authentication verdict and the bulk-mail headers.
Listed in full under [The header rules](#the-header-rules).

**Deceptive links** (`linkMismatches`, `assessLinks`) — an anchor whose visible
text names one registrable domain while its `href` goes to another. Thirty ESP
and URL-shortener domains are skipped, because legitimate marketing mail wraps
its links through them and a banner that fires on every newsletter is a banner
nobody reads.

**The security level** (`assessEmailSecurity`) — combines all of the above into
one of five levels with a per-check breakdown, for the shield or banner a mail
client shows. The copy is deliberately yours: the library returns levels and
check ids, never English sentences for the user.

**The body-content stage** (`assessContentSignals`) — seven rules over what the
message actually says, scored on the sender's **own** words: quoted history,
signature and the mail client's footer are removed first, so forwarding a phish
to your IT desk does not score you as the phisher and a long thread does not get
worse every time somebody hits reply. Listed in full under
[The content rules](#the-content-rules).

**Body extraction** (`bodyContent`, `extractHtml`, `ownWords`) — the same
extraction the rules saw, exported so you can show a preview or explain why a
rule fired. `extractHtml` returns the visible text, the quoted text, the text
the markup hid from the reader, and every anchor with its visible label.

**The attachment stage** (`assessAttachmentSignals`) — seven rules over what a
file claims to be against what its bytes actually are. Nothing is executed,
unpacked or inflated: a zip's own directory is read, never its contents. Listed
in full under [The attachment rules](#the-attachment-rules).

**Attachment primitives** (`inspectAttachment`, `sniffFileType`,
`inspectFilename`, `listZipEntries`) — the facts the rules scored, exported so
you can show them or score them differently. Zero dependencies, so a renderer
can use them too.

**The whole pipeline** (`scan`, `scanMany`) — raw RFC 5322 bytes in, one JSON
verdict out, all three stages included. See
[Scanning a whole message](#scanning-a-whole-message).

**Verdict plumbing** (`spamVerdict`, `isSpamScore`, `parseSpamReasons`,
`assessmentOf`, `mergeAssessments`) — the thresholds, the stored-reason codec,
and the seam that combines two stages into one verdict, with no dependencies at
all. Merging concatenates reasons and re-totals; it never ORs two booleans, so
two stages that each fall short can still add up to a filing.

## Scoring model

Additive, in the shape SpamAssassin made familiar: every rule that fires
contributes points and one human-readable sentence. Points are summed; the total
meets a threshold or it does not.

| Score | Verdict |
| --- | --- |
| `>= 5` (`SPAM_THRESHOLD`) | `spam` |
| `>= 3` (`SUSPICIOUS_THRESHOLD`) | `suspicious` |
| below that | `clean` |

No rule is a veto and no single rule can reach the spam threshold on evidence
that is merely suspicious. This matters more than the individual weights: a
false positive in a mail client is mail the recipient never learns existed, so a
rule that is right 95% of the time must not be able to file mail on its own.

Reasons are returned alongside the score precisely so a filing decision can be
explained to the person it affected.

## The header rules

Every rule `assessSpamSignals` can fire, with the weight it contributes. Only
the two 5-point rules can reach the spam threshold alone, and both are
categorical: something that saw more than the headers already decided, or the
recipient themselves said so.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `upstream-spam` | 5 | `X-Spam-Flag: YES`, `X-Spam-Status: Yes`, or an Exchange SCL of 5 or more |
| `known-spammer` | 5 | The caller says the recipient reported this sender |
| `auth-failed` | 3 | DMARC failed — or, only when DMARC is unknown, SPF **and** DKIM both failed |
| `display-name-spoof` | 3 | The friendly name claims a domain the address does not belong to |
| `brand-impersonation` | 3 | The friendly name borrows a protected brand's name (`PROTECTED_BRANDS`) on an address outside that brand's own domains — and outside any domain that carries the brand's name, so a bank writing from an unlisted `axisbankmail.bank.in` is not judged. Not charged on list mail (`List-Id`) or a ` via ` rewrite. Deliberately blind to lookalike domains (`paypal-secure.example`), which are a different tell |
| `sender-invalid` | 2 | No sender address, or one RFC 5322 cannot parse |
| `reply-to-freemail` | 2 | Replies go to free webmail while the message claims a corporate domain |
| `missing-message-id` | 2 | No `Message-ID` — every real mail server adds one |
| `date-skew` | 2 | The `Date` header is more than 96 hours from when the server received it |
| `fake-reply` | 2 | A `Re:` subject with no `In-Reply-To` and no `References` |
| `in-reply-to-self` | 2 | `In-Reply-To` names the message's own `Message-ID` — a reply to itself, which no mail client produces |
| `sender-punycode` | 1 | The sender domain is punycode/IDN — a homograph risk, not proof |
| `reply-to-mismatch` | 1 | Replies go to a different registrable domain than the sender's |
| `malformed-message-id` | 1 | A `Message-ID` that is not `<local@domain>` |
| `missing-date` | 1 | No `Date` header |
| `no-recipient` | 1 | Neither `To` nor `Cc` names anyone |
| `bulk-no-unsubscribe` | 1 | Declared bulk mail offering no `List-Unsubscribe` |
| `precedence-junk` | 1 | `Precedence: junk` — the sender labelled it themselves |

The weights are chosen so the classic combinations cross the line while no
single benign anomaly does: a spoofed display name on a message that failed
DMARC is 3 + 3, a forged `Re:` from an unauthenticated sender is 2 + 3, a
borrowed brand name on a message that forges its own threading is 3 + 2. A
forwarder that breaks DKIM, a cron job with no `Message-ID`, a home address in
`Reply-To` — each is one point or three, and each stays below 5 on its own.

`SPAM_HEADER_NAMES` and `BULK_HEADER_NAMES` are exported so your IMAP fetch can
ask for exactly the headers the rules read. A header a rule reads but the fetch
never asked for is a rule that silently never fires.

## The content rules

`assessContentSignals({ subject, text, html, recipientDomains? })` scores what the sender wrote.
Everything they did not write is removed first: quoted history, the signature
after a `-- ` delimiter, the mail client's own footer, and anything inside a
`blockquote` or a client's quote container (`gmail_quote`, `moz-cite-prefix`,
`yahoo_quoted` and the rest). When both a `text/plain` and a `text/html` part
exist only the HTML is scored — they say the same thing, and scoring both would
double every hit for no reason but the MIME shape.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `content-spam-vocabulary` | 1–2 | The sender's words match a scam vocabulary group. Once per group, capped at 2 overall |
| `content-hidden-text` | 2 | 120+ characters the message's own styling hides from the reader |
| `link-display-mismatch` | 2–4 each | A link's visible text names one registrable domain while its `href` goes to another. Up to three. 4 when the text names one of the caller's `recipientDomains` — the reader's own organisation — 3 when it names a protected brand's domain, 2 otherwise |
| `link-userinfo` | 2 | A link hides its destination behind `https://bank.example@evil.example/` |
| `link-bare-ip` | 2 | A link points straight at an IP address rather than a domain |
| `content-shouting` | 1 | Four or more consecutive words in capitals, or runs of `!!!` |
| `link-punycode` | 1 | A link goes to a punycode/IDN domain, which can imitate a familiar name |

**Two kinds of rule, and only one of them is capped.** The vocabulary and
shouting rules are an *interpretation* of prose; word lists age badly, and a
filter that can convict on vocabulary alone eventually eats somebody's ordinary
mail. Together they are worth 3 at the very most — enough to raise a suspicion
for a human to look at, never enough to reach `SPAM_THRESHOLD`. Matching every
group in the corpus **and** shouting the whole way through still cannot file a
message. The hidden-text and link rules are *facts about the bytes* — where a
link actually points, what the markup hid — and those accumulate without a cap,
because four of them at once is not a stronger opinion, it is four separate
deceptions. No single rule anywhere in the stage can reach `SPAM_THRESHOLD` on
its own; the heaviest, a link dressed as the reader's own domain, is 4. Pass
`recipientDomains` — the To and Cc addresses and the mailbox owner's own — to
turn that tier on; `scan` does it for you.

**The word lists are data, in this repo, enrichable by pull request.**
`src/data/spam-phrases.ts` groups phrases by the scam rather than by the word,
which is what makes the cap meaningful: twelve pharmacy phrases are one pharmacy
advert, not twelve pieces of evidence. `src/data/freemail-domains.ts` is the
freemail corpus, vendored rather than installed: the upstream package fetches
its list over the network from a `postinstall` script and rewrites its own
source, which makes every install non-reproducible and can leave a consumer with
a silently empty list. See the 0.2.0 entry in [CHANGELOG.md](./CHANGELOG.md).

Matching is done on NFKC-normalised, lowercased text with zero-width and soft-
hyphen characters stripped, on whole-word boundaries. So `ＹＯＵ ＨＡＶＥ ＷＯＮ`
and `you ha<U+200B>ve won` both match, and `wonderful` does not.

## The attachment rules

`assessAttachmentSignals(attachments)` scores what a file claims to be against
what its bytes actually are. Three sources, and the value is in where they
disagree: the **name** is a claim the sender wrote that the reader's operating
system nonetheless acts on, the **MIME type** is a second claim the sender
wrote, and the **bytes** are the only one of the three that cannot be written
to say something other than what the software will do.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `attachment-name-spoof` | 2 | The filename carries bidirectional override characters, so what is displayed is not what runs |
| `attachment-double-extension` | 2 | A document extension in front of an executable one — `invoice.pdf.exe` |
| `attachment-executable` | 2 | The file runs on a double click, by extension or by magic bytes |
| `attachment-type-mismatch` | 2 | The magic bytes contradict the extension, or the declared `Content-Type` |
| `attachment-macro` | 2 | A macro-enabled Office extension, or a zip that contains a VBA project whatever it is called |
| `attachment-archive-executable` | 2 | An archive contains a program — the container is there to get it past the envelope |
| `attachment-encrypted-archive` | 1 | An archive is password-protected, so nothing between here and the reader can look inside |

**Nothing is executed, unpacked or inflated.** An archive's central directory
is read — the names, the declared sizes, the encrypted flag — and that is all.
That is a security decision rather than an optimisation: a 42 KB zip bomb
expands to several petabytes, and every scanner that inflates what it is handed
needs a budget, a timeout and a recursion limit to survive being mailed one.
Reading the directory answers all four of the questions the rules ask and costs
a bounded walk. It is also why this entry has no dependencies — an inflater is
the one thing a scanner that is handed hostile archives should not carry.

**Each rule fires once per message.** Ten executables in one archive is one
decision the sender made, not ten. The reason names the first attachment that
triggered the rule and counts the others.

**This is not an antivirus, and a clean result does not mean safe to open.**
There is no signature database and no emulation here; what the stage can see is
structure. That is why no single rule is worth more than 2 points and why a
bare executable attachment reaches neither threshold on its own — a developer
mailing a build to a colleague sends the same bytes as a dropper, and the
difference is not visible from here. What is visible, and what the stage is
good at, is the combination that has no innocent version: a file whose name,
type and contents each say something different.

**It works without the bytes.** A caller that has only the MIME structure — a
client listing attachments before it has downloaded any — gets the name-based
rules and nothing else, rather than an error or a false clean.

**The extension lists are data, in this repo, enrichable by pull request.**
`src/data/attachment-extensions.ts` holds them, and note that there are two
executable lists rather than one. A `.js` file attached to an email is a
dropper; a `.js` file inside a zip is `node_modules`. What counts inside an
archive is the narrower set that has no innocent reason to be zipped up and
mailed — Windows binaries, script-host formats, shortcuts and installers.

## Security levels

`assessEmailSecurity` returns one of five, ordered by `LEVEL_RANK`:

| Level | Means |
| --- | --- |
| `verified` | Authentication passed and every link the sender wrote stays on their own domain — links inside quoted history belong to the message being answered and are not counted |
| `authenticated` | Authentication passed; nothing else to say |
| `unverified` | The server recorded no authentication verdict — common, not alarming |
| `caution` | Something is off: a deceptive link, or a suspicious score |
| `danger` | DMARC failed, the display name is spoofed, or the score is over the spam threshold |

`worstLevel(levels)` reduces several to the worst one, for a thread or a
conversation view — an empty list is `verified`, nothing to report. The human
copy for each level is not in this package — a library cannot know your
product's voice, its language, or its reading age.

Pass `bimi` (a `BimiLookup` from `/brand`, or the columns you cached from one)
and the assessment gains a `brand` check explaining the sender's mark: who
proved ownership of the domain and which authority vouched for it, or why no
tick is being shown. It never moves the level in either direction — most
legitimate senders publish no BIMI record, so scoring its absence would warn
about most of the world's mail, and a verified mark proves who owns a brand,
not that this message deserves trust. A mark is only ever reported as proof
under a DMARC pass: the certificate says who owns the brand, DMARC says this
message came from them. Leaving `bimi` out drops the row entirely; passing
`null` says "not looked up yet", which is a different thing to tell a reader.

If your client fetches bodies lazily, pass `bodyLoaded: false` until the body
is in hand. An absent body is not a body with no links in it: read as "checked,
found nothing" it makes every unfetched message `verified` — the top level,
awarded for a body nobody has looked at. With `bodyLoaded: false` the links
check reports `unknown`, the level stops at `authenticated`, and the assessment
sets `pending: true` so you can show "still checking" instead of a level you
would have to take back. What `pending` must NOT hide is a warning: `caution`
and `danger` come from the headers, which arrived with the message, so render
those as they are.

## Reading a stored verdict back

Score it once, store the number and the reasons, and read them back from
anywhere — including a browser — with no dependencies:

```ts
import { spamVerdict, parseSpamReasons } from '@sarv-in/mailguard/verdict';

spamVerdict(row.spam_score);            // 'spam' | 'suspicious' | 'clean' | null
parseSpamReasons(row.spam_reasons);     // SpamReason[], [] if absent or corrupt
```

`spamVerdict` returns `null` — not `'clean'` — for `null`/`undefined`. A message
that was never scanned and a message that scored zero are different facts, and
collapsing them shows a green tick on mail nothing ever looked at.

`parseSpamReasons` also renames what this package has renamed: a row written
under an older id comes back under the current one (`canonicalReasonId` is the
same mapping on its own), so a reader that switches on today's `SpamReasonId`
handles a verdict stored a year ago without a special case. An id it has never
heard of is passed through untouched rather than dropped — a verdict written
by a newer version still has to render.

### Re-scoring a message you only have part of

A mail client fetches headers first and bodies later, so the body stages run
long after the header verdict was stored. Re-running them has to **replace**
their own previous reasons, never append a second copy — and the headers that
produced the rest of the verdict are gone by then, so recomputing the lot is
not an option. `stageOfReason` is what makes that possible:

```ts
import { assessmentOf, mergeAssessments, parseSpamReasons, stageOfReason } from '@sarv-in/mailguard/verdict';

const kept = parseSpamReasons(row.spam_reasons).filter((reason) => stageOfReason(reason.id) !== 'content');
const rescored = mergeAssessments(assessmentOf(kept), assessContentSignals({ subject, text, html }));
```

`stageOfReason` returns `null` for an id this version has never heard of —
including one written by a NEWER release — and a caller should read that as
"leave it alone" rather than as "not mine". `SPAM_REASON_STAGES` is the whole
table if you want to partition reasons some other way.

## Origin IP: which address actually sent this

`Received:` headers are appended by each hop, and every hop below your own
boundary was written by someone you do not control. So `extractOriginIp` first
asks **your** receiving server's own `Authentication-Results`, the same header
the verdict is read from and chosen by the same rule (see
[Authentication results](#authentication-results-read-not-verified)). That
header names the client the server checked, in its SPF or iprev result:

- as `smtp.remote-ip=` or `policy.iprev=`;
- in Microsoft's SPF comment, `sender IP is …`;
- in Gmail's SPF comment, `designates … as permitted sender`, including the
  failing and neutral wordings that spam gets.

Only when that header names no address does it walk the trace. Pass the
`authserv` you pass `parseAuthenticationHeaders`:

```ts
extractOriginIp({ authHeaders: block, received: receivedLines, authserv: 'mx.google.com' });
```

It never reads `Received-SPF` or `ARC-Authentication-Results`. Either is as easy
to type into a message as a forged verdict. Earlier releases took the first
`client-ip=` anywhere in the block, so a sender listed on a blocklist could add
`Received-SPF: pass client-ip=<a clean address>` and have the blocklists asked
about that address instead. `Received-SPF` names no author (RFC 7208's
`receiver=` is optional, and Gmail omits it), and its position does not tie it
to your server either: Postfix writes it above its own `Received:` line, Gmail
below. Servers that write a real one also record the client in their
`Authentication-Results` (Gmail, Microsoft 365) or in their own `Received:`
line (Postfix), and the trace reads that line.

Without an `authserv`, the address has the same limitation as the verdict:
the topmost `Authentication-Results` is believed. If your server writes none,
whoever wrote the topmost one chooses the address.

Within a `Received:` line it reads the `from` clause only, stopping at `by` (the
receiving side, not the sender) and at `;` (the timestamp). It returns the first
**public unicast** address it finds, so a loopback content-filter hop or an
internal `10.x` relay is skipped rather than reported as the origin.

## Authentication results: read, not verified

This package **reads** the verdict your mail server already computed. It does
not perform SPF, DKIM or DMARC verification itself — that needs live DNS and the
original unmodified message, neither of which a header block contains.

The practical consequence: only trust these values for headers added **at or
above your own trust boundary**. A sender can type
`Authentication-Results: mx.example.com; dmarc=pass` into their own message, so
`parseAuthenticationHeaders` decides which headers to believe (RFC 8601):

- **Only `Authentication-Results`.** Never `ARC-Authentication-Results` (a copy a
  hop sealed for the next one to weigh) or `Received-SPF` (which names no
  author), and never a look-alike name such as `X-Authentication-Results`.
- **With `{ authserv }`**, every header carrying your receiving server's
  authserv-id, wherever it sits. RFC 8601 §5 obliges that server to delete any
  it did not write; for one that does not, the rule below keeps a forgery from
  outvoting it.
- **Without it**, the topmost header only.
- **When trusted headers disagree, the worse result wins**: a pass has to be
  unanimous, and one `fail` is never outvoted. (Several DKIM signatures in ONE
  header are the exception — one valid signature is a valid signature — and an
  SPF result for the envelope sender outranks one for the HELO name.)

```ts
parseAuthenticationHeaders(block, { authserv: 'mx.google.com' }); // Gmail's
parseAuthenticationHeaders(block, { authserv: ['mx1.example.com', 'mx2.example.com'] });
```

Microsoft 365 writes no authserv-id at all; its header parses (see
`parseAuthResultsHeader`) and is believed when it is the topmost and no id is
configured, but can never match one that is.

`scan` makes this decision for you from the `authserv` option — see
[Scanning a whole message](#scanning-a-whole-message).

To establish the verdict yourself instead of reading somebody else's, see the
next section.

## Verifying authentication yourself

Everything above reads a verdict another machine wrote down. The `/verify`
entry computes one: SPF, DKIM and DMARC against live DNS, over the original
unmodified bytes.

```ts
import { verifyAuthentication } from '@sarv-in/mailguard/verify';
import { scan } from '@sarv-in/mailguard/scan';

const verified = await verifyAuthentication(raw, {
  ip: '198.51.100.7', // the address that connected — SPF is a question about it
  helo: 'mail.example.com',
  mailFrom: 'billing@example.com', // the envelope sender, not the `From:` header
});

// A verification that did not complete hands back nothing rather than a guess,
// and `null` tells `scan` to fall back to the trusted headers.
const result = await scan(raw, { auth: verified.completed ? verified.auth : null });
```

**It needs [`mailauth`](https://www.npmjs.com/package/mailauth), and it asks for
it at the last possible moment.** The package is declared as an **optional peer
dependency** and reached through a dynamic `import` inside the one function
that uses it. Install it and verification works; leave it out and every other
part of this package behaves exactly as it did, with only a call to
`verifyAuthentication` throwing — and throwing a message that says what to
install. Nothing else in the source imports it, statically or otherwise, which
is pinned by the same test that walks the import graph for every other entry.

**`scan` will not do this for you, and that is the design.** `scan` and
`scanParsed` make no network calls at all: the same message scores the same way
on a laptop with no resolver, in a test, and in a bundle, and nothing you run
over fifty thousand messages quietly turns into fifty thousand DNS lookups. You
choose when to verify, with your own timeout and your own concurrency, and hand
the answer back through `options.auth`.

**Three things have to come from your MTA, because the message does not carry
them.** `ip` is the address that connected, and SPF is a question about that
address and nothing else — without it, `spf` comes back `unknown` rather than
guessed. `helo` is what the client announced itself as. `mailFrom` is the
envelope sender from `MAIL FROM`, which is not the `From:` header and routinely
differs on forwarded and bulk mail. A `.eml` file on disk has none of the
three; a receiving server has all of them.

**What comes back:**

| Field | |
| --- | --- |
| `auth` | the same `AuthStatus` the header reader produces, so it drops straight into `scan` and `assessEmailSecurity` |
| `completed` | `false` when the verification itself failed — a DNS timeout, a resolver error. `auth` then asserts nothing |
| `spfDomain` | the domain SPF was evaluated for, or `null` when it never was |
| `signatures` | every DKIM signature: signing domain, selector, `mailauth`'s own verbatim result word, its comment, and whether it aligned with the `From:` domain |
| `dmarcPolicy` | the policy the domain published — `none`, `quarantine`, `reject` |
| `error` | why it did not complete, or `null` |

**A verification that failed is not a verdict of `fail`.** A timeout, an
unreachable resolver or a missing record all return `completed: false` and an
`auth` of three `unknown`s, never a failure the rules would score. The
distinction matters because `auth-failed` is a 3-point rule: an outage on your
side must not start scoring everybody's mail as spam. `timeoutMs` defaults to
10 seconds, and `resolver` lets you supply your own — a cache, a stub in tests,
a DoH client.

**Signatures keep `mailauth`'s vocabulary, the rollup does not.** Per signature
you get the exact word the library used (`pass`, `fail`, `neutral`, `policy`,
`temperror`) and its comment, because that is diagnostic detail you cannot
reconstruct. The rolled-up `auth.dkim` is coarser on purpose: `neutral` (body
hash mismatch, no key, expired) and `policy` (a key below `minBitLength`) both
become `fail`, so that a verified verdict and a Gmail header verdict describe
the same message the same way rather than disagreeing about a word.

## Reputation: asking somebody else

Every other rule in this package is a fact about the message in front of you.
This one is not: it asks operators who keep blocklists what they have already
observed about the machine that delivered it and the domain it claims. That is
the strongest single signal in spam filtering, and the only one that requires
telling a third party what you are looking at.

```ts
import {
  assessReputation,
  checkReputation,
  SPAMHAUS_ZEN,
  SPAMCOP,
} from '@sarv-in/mailguard/reputation';
import { scan } from '@sarv-in/mailguard/scan';

const result = await scan(raw);

const reputation = await checkReputation(
  { ip: result.originIp, domain: result.message.fromAddress?.split('@')[1] },
  [SPAMHAUS_ZEN, SPAMCOP], // required: there is no default list
);

// Re-score with what the operators said. `checkReputation` never throws, so a
// blocklist outage costs the message nothing.
const scored = await scan(raw, { reputation: assessReputation(reputation) });
```

**There is no default list of zones, and there never will be.** `blocklists` is
a required argument because every list has terms: Spamhaus is free for
low-volume use and requires a paid data feed above it, SpamCop has its own
conditions, and several lists return a permanent "you are over quota" answer
rather than a listing once you pass their threshold. A package that queried
them by default would put you in breach of somebody's terms without you ever
choosing to. `BLOCKLISTS` is exported as a starting point to read, not a
default to inherit — you pass what you have the right to query.

**And it tells the operator what you are scanning.** Every lookup is a DNS
query naming a sender your user is receiving mail from, and it goes to that
operator's resolvers, and it is visible to whatever resolver you route through.
That is a real disclosure, which is the other half of why this is opt-in, in
its own entry, and never invoked by `scan`.

**The return code is the answer, not the fact that there was one.** A blocklist
replies to `2.0.0.127.zen.spamhaus.org` with an `A` record inside `127.0.0.0/8`
and the last octets say what kind of listing it is — `127.0.0.2` is Spamhaus's
SBL, `127.0.0.10` is the policy list saying "this address should not be
delivering mail directly at all", which is a far weaker signal about a message
that arrived via a relay. This package reads the code, scores per code where
the zone publishes a table, and reports both under `hits[].codes` and
`hits[].meanings`.

Three answers are emphatically **not** listings, and all three reach `errors`
instead:

- **`127.255.255.0/24`.** That range is the operator complaining, not
  answering: malformed query, a query that arrived via a public resolver, or
  you are over their volume limit. Reading "an A record came back" as "listed"
  turns a misconfigured resolver into a filter that files **every** message as
  spam at once.
- **Anything outside `127.0.0.0/8`.** A wildcard DNS provider, a captive portal
  or a hijacked response answers with a real address. No blocklist publishes a
  listing there.
- **A refusal the zone publishes inside `127.0.0.0/8`.** The URI lists answer
  `127.0.0.1` to a query from a public resolver or from a querier over the
  free-use limit. It is a refusal wearing the clothes of a listing, it arrives
  for every domain at once, and each zone declares its own in `refusals`.
  `127.0.0.1` is never read as a listing by any zone.

**Some zones answer in bits, not codes.** SURBL and URIBL pack their categories
into the last octet as a bitmask, so a domain that is both a phishing site and
a malware host comes back as `127.0.0.24` — an address that appears in no code
table. Those zones declare `bits` instead of `codes`, several records are ORed
together before they are read, and a listing reports every category it sets.
Reading a bitmask as an exact code silently downgrades the worst listings there
are; reading it as a boolean makes URIBL's grey list — bulk mail of dubious
value, not spam — indistinguishable from a spam run.

**Every described code carries a `category`** (`spam`, `exploited`,
`phishing`, `malware`, `botnet`, `policy`, `abused`, `grey`), reported on the
hit. It is what lets a consumer group listings across zones, or apply its own
points table, without copying this catalogue back out of the package. `abused`
is the one to read twice: a cracked WordPress install is listed, and the
domain's owner is a victim rather than the sender.

**A failed lookup is not a clean result.** A resolver timeout, a SERVFAIL, or
nothing worth querying all leave `completed: false` with no hits — never
`listed: false` presented as an all-clear. Zones that did answer are still in
`hits` and `checked`, so one operator's outage never discards another's
listing.

**Several lists agreeing counts once.** `assessReputation` charges the
**highest-scoring** hit per kind of target, not the sum. The public lists mirror
and feed each other, and ZEN is three lists in one zone — summing would make a
message's score depend on how many zones you happened to configure rather than
on the message. The address and the domain are separate facts about separate
things, so those two do add up — as far as `REPUTATION_MAX_POINTS`
(`SPAM_THRESHOLD + 1`), which is enough for a listed sender to be spam on this
evidence alone and no more. Pass `{ maxPoints: Infinity }` to score each
listing in full and run your own ceiling.

**What other recipients already said.** The one signal in this stage that no
lookup can find: if you run a host that counts spam reports, pass the count for
this sender's domain as `assessReputation(result, { userReports: 7 })`. Three
reports (`USER_REPORTS_MIN`) are worth three points (`USER_REPORT_POINTS`),
charged after the listings out of whatever is left of the budget — one report
is one opinion, and a crowd's opinion is not an operator's observation. Move
the line with `minUserReports`. A result with no `domain` ignores the count
rather than showing it against a blank name.

**A backlog goes through `checkReputationBatch`.** Scoring stored messages
after the fact means hundreds of addresses across several zones, and the two
obvious shapes are both wrong: sequential is an hour of round-trips, and
`Promise.all` over the lot opens a thousand simultaneous queries that c-ares
will not serve, the operator reads as an attack, and a home router drops on the
floor.

```ts
const results = await checkReputationBatch(
  rows.map((row) => ({ ip: row.originIp, domain: row.senderDomain })),
  [SPAMHAUS_ZEN, SPAMHAUS_DBL],
  { concurrency: 8 }, // queries in flight across the whole batch
);
// results[i] belongs to rows[i]; a row with nothing worth asking about comes
// back as completed: false rather than being dropped.
```

One resolver is built for the batch, results come back in the order the targets
were given, and a batch where nothing is worth asking about opens no socket at
all.

**What comes back:**

| Field | |
| --- | --- |
| `listed` | whether any zone returned a listing |
| `hits` | one per listing: the zone, what was asked about, the codes, their meanings, the points, and the TXT explanation if you asked for it |
| `checked` | the zones that gave a usable answer, listed or not |
| `errors` | the zones that did not, and why |
| `completed` | `false` if any zone failed, or if there was nothing worth asking about |

`timeoutMs` (default 5 s), `servers` (your own resolvers rather than the
system's) and `includeText` (fetch each hit's `TXT` explanation, one extra
query per listing) are the options. `query` replaces the DNS layer outright,
which is how the tests run without a network.

**Only public addresses are ever queried.** `checkReputation` reuses the same
gate as `extractOriginIp`, so private, loopback, link-local, CGNAT and reserved
ranges are skipped rather than asked about — no operator has anything to say
about `10.0.0.4`, and asking would publish your network layout to them one
query at a time.

**Node only.** `node:dns/promises` is reached through a dynamic `import`, so
the entry costs a browser bundle `ipaddr.js` and nothing else — but calling
`checkReputation` without an injected `query` needs a Node resolver.

## Domain age: how new is the domain

```ts
import { assessDomainAge, fetchRdapBootstrap, lookupDomainAge } from '@sarv-in/mailguard/age';

const bootstrap = await fetchRdapBootstrap(); // IANA's TLD → RDAP server table; fetch it once and keep it
const sender = await lookupDomainAge('powersublinks.com', { bootstrap });
const links = await Promise.all(linkDomains.map((d) => lookupDomainAge(d, { bootstrap })));
const age = assessDomainAge({ sender, links }); // a SpamAssessment, for mergeAssessments
```

The lure that motivated this was sent from a domain registered 78 days
earlier and linked to one registered **five** days earlier. Neither was on any
blocklist — a blocklist lists what has been reported, and a five-day-old
domain has not been. Registration date is the one fact about a phishing domain
that is true from the moment it is used, and RDAP (RFC 9083, mandatory for
every gTLD since 2019) is the registries' own JSON service for it: one HTTPS
GET per domain, no key, no port-43 WHOIS.

| Reason id | Points | Fires when |
| --- | --- | --- |
| `reputation-domain-new` | 3 / 2 / 1 | The sender's registrable domain was registered under 7 / 30 / 90 days ago |
| `reputation-link-new` | 3 / 2 / 1 | The **youngest** domain the message links to was registered under 7 / 30 / 90 days ago |

**Age alone never files a message.** The two together are capped at
`DOMAIN_AGE_MAX_POINTS` (`SPAM_THRESHOLD - 1`): a start-up's first mail from
its first domain to its first prospect is every signal here at once, and it is
not spam. It corroborates what the header and content stages found — on the
lure above, 1 + 3 on top of everything else.

**What comes back when it cannot answer is `status`, not a throw.**
`unsupported` for a TLD with no RDAP service (many ccTLDs) or a registry that
publishes no registration date; `not-found` for a domain the registry has no
record of; `error` for a refusal, a rate limit, an outage or an unreadable
record. None of them scores. The lookup takes an injected `fetch`, so it runs
wherever your fetch does and a test never opens a socket.

**Nothing here caches, and you should.** A registration date never changes, so
remember an answer for weeks rather than hours; the bootstrap file changes
rarely, so fetch it once per process with `fetchRdapBootstrap` and pass it to
every lookup. Every lookup tells a registry which domain your user received
mail from, which is the same disclosure a blocklist query makes — put it
behind the same setting.

## Brand marks: BIMI, VMC and favicons

`/brand` answers a different question from the rest of the package. The
scanner asks whether a message is spam; this asks what mark to show next to a
sender it has already decided to display — and it is the one entry that both
reaches the network and runs in a browser, because DNS and HTTPS are injected
rather than imported.

```ts
import { lookupBimi, discoverFavicon } from '@sarv-in/mailguard/brand';

const mark = await lookupBimi('brand.example');
if (mark.status === 'verified') {
  // mark.logo is a data: URI; mark.organization is who a Mark Verifying
  // Authority says owns it; mark.issuer is the authority that said so.
} else if (mark.status === 'logo') {
  // The domain published a logo under an enforcing DMARC policy, but nobody
  // third-party vouched for it. Show it without a tick, and mark.detail says
  // why the tick is missing.
} else {
  const icon = await discoverFavicon('brand.example');
}
```

**A logo is only ever shown under an enforcing DMARC policy.** That is BIMI's
whole premise: a spoofer must never get to wear the brand. `p=none`, no DMARC
record at all, or `pct` below 100 all mean no logo, whatever the BIMI record
says — and for a subdomain sender it is the organisational domain's `sp=` that
governs, since that is the policy that actually covers the mail.

**The tick is a third party's claim, and it is checked in full.** A Verified
Mark Certificate earns `status: 'verified'` only when the chain reaches a
**pinned** Mark Verifying Authority root (`MVA_ROOTS` — the certificates
themselves, fingerprinted, not a name to trust), the leaf carries the BIMI
extended key usage `1.3.6.1.5.5.7.3.31`, its SubjectAltName covers the From
domain, every certificate in the chain is inside its validity dates, and the
RFC 3709 logotype extension binds **this** logo — by SHA-256 digest, or by an
embedded copy that matches byte for byte. A certificate that fails any of
these demotes to `'logo'` with the reason in `detail`; it never silently
passes, and it never takes the logo away either.

**The logo itself is checked before it is shown.** `checkBimiSvg` requires SVG
Tiny PS and refuses a file carrying script, event handlers, `foreignObject`,
or any external reference — a logo is markup a stranger chose, rendered next
to their name in your reader's mail.

**Statuses are what a cache is keyed on.** `'none'` (no record) is an answer
worth remembering for a week; `'error'` (the resolver or the host could not be
reached) is worth about a minute. Nothing here caches — the caller owns that,
because the caller knows how long it wants to believe an answer.

**The certificate tooling is optional.** `@peculiar/x509` and `asn1js` are
optional peer dependencies loaded through a dynamic `import` on first use. An
install without them still gets the logo, the SVG check and the favicon; what
it loses is the tick, and `detail` says which package to add rather than
blaming the brand.

**The favicon is a disclosure, so put it behind a setting.** `discoverFavicon`
asks the domain's homepage for its declared icons, best first, then
`/favicon.ico`, falling back to the organisational domain for the `notify.`
and `mailer.` subdomains that serve no website. Every image is identified by
its own magic bytes, never by the `Content-Type` — a 200 HTML error page is a
very common answer to a missing favicon and must never become somebody's
avatar. Fetching one tells that domain, once, that a client at this address
looked it up: far less than the per-message tracking pixel that remote images
are, but not nothing.

## API

### Verdict — `@sarv-in/mailguard/verdict`

- `SPAM_THRESHOLD: 5`, `SUSPICIOUS_THRESHOLD: 3`
- `spamVerdict(score): 'spam' | 'suspicious' | 'clean' | null`
- `isSpamScore(score): boolean`
- `parseSpamReasons(json): SpamReason[]` — never throws; renamed ids come back under their current name
- `canonicalReasonId(id): SpamReasonId` — that renaming on its own
- `assessmentOf(reasons): SpamAssessment` — sums and applies both thresholds
- `mergeAssessments(...parts): SpamAssessment` — combines stages; `null` parts are skipped
- `unknownAuthStatus(): AuthStatus`, `rollUpAuthStatus(components)` — the one rollup both the header reader and the DNS verifier use
- `type SpamReason`, `SpamReasonId`, `SpamVerdict`, `SpamAssessment`, `AuthStatus`

### Identity — `@sarv-in/mailguard/identity`

- `registrableDomain(input): string | null` — eTLD+1
- `domainOfAddress(address): string | null`
- `domainsInText(text): string[]`
- `assessSender(name, address, brands?): PhishingReason[]` — each reason carries a `kind`: `domain`, `brand` or `punycode`
- `brandsNamedIn(text, brands?): ProtectedBrand[]`, `brandOwningDomain(host, brands?): ProtectedBrand | null`,
  `domainCarriesBrandName(brand, host): boolean`,
  `impersonatedBrand(name, senderDomain, brands?): ProtectedBrand | null` — the brand rule in pieces
- `PROTECTED_BRANDS` — the list, one file per brand in `src/data/brands/`, enrichable by pull request.
  `brands?` everywhere defaults to it; `SpamSignalInput`, `ContentSignalInput`, `SecurityInput`,
  `assessPhishing` and `ScanOptions` take the same `brands` field

### Links — `@sarv-in/mailguard/links`

- `linkMismatches(html): LinkMismatch[]` — `{ shown, actual }`, de-duplicated, capped at three
- `assessLinks(html): PhishingReason[]` — the same, phrased for a human
- `linkDomainsAllMatch(html, senderDomain, isVetted?): boolean` — pass `isVetted` to forgive
  a link the reader has already trusted
- `summarizeLinkDomains(html, senderDomain): LinkDomainSummary` — the counted form:
  `linkCount` and the `offDomain` links, so a UI can SAY why a message was not verified
- `assessPhishing({ fromName, fromAddress, html }): PhishingAssessment`
- `LINK_WRAPPER_DOMAINS: Set<string>`

### Scan — `@sarv-in/mailguard/scan`

- `scan(raw, options?): Promise<ScanResult>` — the whole pipeline over one message
- `scanParsed(email, options?): ScanResult` — the same, over an already-parsed message
- `scanMany(source, options?): AsyncGenerator<BulkScanResult>` — in input order
- `trustedAuthHeaders(headerLines, authserv?): string` — which verdicts survived
- `type ScanOptions`, `ScanResult`, `ScannedMessage`, `RawMessage`, `BulkScanInput`, `BulkScanOptions`, `BulkScanResult`

### Verify — `@sarv-in/mailguard/verify`

Needs the optional peer `mailauth`; nothing else in the package does.

- `verifyAuthentication(message, options?): Promise<AuthVerification>` — SPF, DKIM and DMARC against DNS
- `authVerificationFrom(result): AuthVerification` — the mapping alone, over a `mailauth` result you already have
- `type VerifyOptions`, `AuthVerification`, `VerifiedSignature`, `VerifyInput`, `DnsResolver`

### Reputation — `@sarv-in/mailguard/reputation`

Node only; `node:dns` is imported on first use. No zone is ever queried unless
you name it.

- `checkReputation(target, blocklists, options?): Promise<ReputationResult>` — the lookups; never throws
- `checkReputationBatch(targets, blocklists, options?): Promise<ReputationResult[]>` — many targets, one resolver, a bounded number of queries in flight
- `assessReputation(result, options?): SpamAssessment` — the result scored, for `scan`'s `options.reputation`
- `REPUTATION_MAX_POINTS` — the default ceiling on everything the stage adds
- `USER_REPORTS_MIN`, `USER_REPORT_POINTS` — how many other recipients must have reported a sender before it counts, and what it is worth
- `SPAMHAUS_ZEN`, `SPAMHAUS_DBL`, `SPAMCOP`, `BARRACUDA`, `SURBL`, `URIBL`, `BLOCKLISTS` — described zones to choose from, not a default
- `reverseIpLabel(ip)`, `normalizeQueryDomain(domain)`, `blocklistQueryName(target, blocklist)` — the query names, on their own
- `readBlocklistCodes(blocklist, codes): CodeReading` — what a set of return codes means
- `type Blocklist`, `BlocklistCode`, `BlocklistCategory`, `BlocklistKind`, `BlocklistHit`, `CodeReading`, `DnsQuery`, `ReputationOptions`, `ReputationBatchOptions`, `AssessReputationOptions`, `ReputationResult`, `ReputationTarget`, `ReputationLookupError`

### Age — `@sarv-in/mailguard/age`

Runs anywhere; HTTPS is injected.

- `lookupDomainAge(domain, options?): Promise<DomainAgeLookup>` — the registration date, age in days, registrar and RDAP server; never throws
- `assessDomainAge({ sender, links }, options?): SpamAssessment` — scored, capped at `DOMAIN_AGE_MAX_POINTS`
- `fetchRdapBootstrap(fetch?): Promise<RdapBootstrap | null>` — IANA's TLD table, to fetch once and pass in
- `rdapServerFor(domain, bootstrap): string | null`, `domainAgePoints(ageDays): number`
- `DOMAIN_AGE_TIERS`, `DOMAIN_AGE_MAX_POINTS`, `RDAP_BOOTSTRAP_URL`, `RDAP_MAX_BYTES`
- `type DomainAgeLookup`, `DomainAgeStatus`, `DomainAgeOptions`, `DomainAgeSubjects`, `AssessDomainAgeOptions`, `RdapBootstrap`

### Brand — `@sarv-in/mailguard/brand`

Runs anywhere; DNS and HTTPS are injected. `@peculiar/x509` and `asn1js` are
optional peers, imported on first use, and only the certificate check needs
them.

- `lookupBimi(fromDomain, options?): Promise<BimiLookup>` — the whole policy: DMARC, record, logo, certificate; never throws
- `discoverFavicon(domain, options?): Promise<FaviconResult>` — the fallback mark, as a `data:` URI
- `validateVmc(pem, domain, logo, options?): Promise<VmcResult>` — the certificate on its own
- `checkBimiSvg(bytes): SvgCheck` — SVG Tiny PS, and nothing executable
- `parseBimiRecord(txt)`, `parseDmarcRecord(txt)`, `dmarcEnforcesBimi(record, forSubdomain)` — the records, parsed
- `MVA_ROOTS` — the pinned Mark Verifying Authority roots, with fingerprints and provenance
- `extractLogotypeEvidence(certificate)`, `decodeLogoDataUri(uri)`, `vmcDomains(certificate)`, `fingerprintHex(bytes)` — the certificate internals
- `extractIconLinks(html, pageUrl)`, `rankIconCandidates(candidates)`, `sniffImageType(bytes)`, `faviconHosts(domain)` — favicon discovery, in pieces
- `fetchBounded(fetch, url, maxBytes, options?)`, `defaultFetch()` — the bounded HTTPS boundary both lookups share
- `BIMI_SELECTOR`, `BIMI_LOGO_MAX_BYTES`, `BIMI_EVIDENCE_MAX_BYTES`, `FAVICON_MAX_BYTES`, `HOMEPAGE_MAX_BYTES`, `BIMI_EKU_OID`, `LOGOTYPE_EXTENSION_OID`
- `type BimiLookup`, `BimiOptions`, `BimiStatus`, `BimiRecord`, `DmarcRecord`, `DmarcPolicyValue`, `VmcResult`, `VmcStatus`, `ValidateVmcOptions`, `SvgCheck`, `LogotypeEvidence`, `MarkVerifyingAuthorityRoot`, `FaviconResult`, `FaviconStatus`, `FaviconOptions`, `IconCandidate`, `FetchLike`, `FetchResponse`, `FetchedBytes`, `FetchBoundedOptions`

### Content — `@sarv-in/mailguard/content`

- `assessContentSignals(input): SpamAssessment` — the whole stage; `input.recipientDomains` turns on the reader's-own-domain tier of the link rule
- `bodyContent(input): BodyContent` — `{ words, anchors, hiddenText }`, what the rules saw
- `extractHtml(html): HtmlExtract` — `{ text, quotedText, hiddenText, anchors }`
- `ownWords(text): string`, `stripQuotedTail(text): string`, `QUOTE_MARKERS` — re-exported from `/quote` below
- `matchSpamVocabulary(text, groups?): VocabularyHit[]`, `vocabularyPoints(hits)`
- `normalizeForMatching(text)`, `containsPhrase(haystack, phrase)`, `collapseWhitespace(text)`
- `longestShoutRun(text): number`
- `SPAM_PHRASE_GROUPS`, `VOCABULARY_CAP`

### Quote — `@sarv-in/mailguard/quote`

Zero dependencies, and the one entry here that is not about spam at all: a reply
carries the mail it answers, and almost nothing you want to do with a body
should be done to somebody else's half of it.

- `stripQuotedTail(text): string` — everything above the quoted history, signature included. What a contact miner wants: the sign-off is the point, and the only one that must go is the sign-off of the person being replied to
- `ownWords(text): string` — the same cut, with the signature and the client footer removed too. What a scorer wants: a job title and a phone number are not an argument
- `QUOTE_MARKERS: readonly RegExp[]` — the markers both cuts share, exported so you can say which one fired

### Attachments — `@sarv-in/mailguard/attachments`

Zero dependencies: nothing here unpacks anything, so there is nothing to unpack
it with.

- `assessAttachmentSignals(attachments): SpamAssessment` — the whole stage
- `inspectAttachment(input): AttachmentFacts` — the facts one file yields, unscored
- `inspectFilename(name): FilenameFacts`, `extensionsOf(name)`, `stripBidiControls(name)`
- `sniffFileType(content): SniffedType | null` — the family the first bytes belong to
- `isExecutableType(type)`, `expectedTypesForExtension(ext)`, `expectedTypesForMimeType(type)`
- `listZipEntries(content): ZipListing | null` — the central directory, never the contents
- `asBytes(content): Uint8Array | null` — one correct view over every parser's shape
- `EXECUTABLE_EXTENSIONS`, `ARCHIVE_EXECUTABLE_EXTENSIONS`, `ARCHIVE_EXTENSIONS`, `MACRO_ENABLED_EXTENSIONS`, `DECOY_EXTENSIONS`

### Security — `@sarv-in/mailguard/security`

- `assessEmailSecurity(input): SecurityAssessment`
- `worstLevel(levels): SecurityLevel`
- `LEVEL_RANK`, `linkRuleKey(senderDomain, shown, actual)`, `parseAuthStatus(json)`
- `EMPTY_RULES`, `type LinkRuleSets`, `SecurityCheck`, `CheckStatus`, `BrandIdentity` — what the `bimi` input needs of a `/brand` lookup

### Header reading — `@sarv-in/mailguard/headers`

Zero dependencies, so a browser bundle can ask these questions without importing
the scanner.

- `headerLookupFromText(headers): HeaderLookup`, `headerValueFromText`, `headerValuesFromText`
- `bulkHeaderSignals(get): BulkHeaderSignals`, `hasBulkHeaderSignal(get)`, `BULK_HEADER_NAMES`
- `extractAuthHeaderBlock(headers): string | null`
- `parseAuthenticationHeaders(block, { authserv? }): AuthStatus` — the verdict of the headers worth believing
- `parseAuthResultsHeader(value): AuthResultsHeader` — one `Authentication-Results` value: authserv-id and statements, each with its properties and its comments as written
- `type AuthResult`, `AuthResultsHeader`, `AuthResultsOptions`
- `receivedAt(lines): number | null`, `receivedAtFromLine(line)` — delivery time from the trace

### Rules and scoring — `@sarv-in/mailguard`

- `extractOriginIp(sources): string | null` — reads headers, but needs an IP parser
- `originIpFromAuthHeaders(block, { authserv? })`, `originIpFromReceived(lines)`
- `normalizeIp(candidate)`, `isPublicIp(candidate)`
- `assessSpamSignals(input): SpamAssessment`, `SPAM_HEADER_NAMES`, `DATE_SKEW_SECONDS`
- `isFreemailAddress(address)`, `isValidMessageId(id)`, `hasReplyPrefix(subject)`
- `FREEMAIL_DOMAINS` — the vendored corpus, sorted and lowercased
- `linkTarget(href): LinkTarget | null`, `urlsInText(text)`, `anchorMismatches(anchors)`

## Contributing

Rules and word lists are the point of an open-source spam scanner — see
[CONTRIBUTING.md](./CONTRIBUTING.md). The short version: every rule arrives with
a fixture drawn from a real message, a cited source, and evidence that it adds
no false positive to the existing corpus. Coverage is enforced at 100% in CI,
because a spam rule with an untested branch silently files somebody's mail.

## Licence

MIT © Sarv. See [LICENSE](./LICENSE).
