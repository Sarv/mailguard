# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.3] - 2026-10-02

### Security

- **A forged `Authentication-Results` no longer reads as authenticated.**
  `parseAuthenticationHeaders` used to scan every `Authentication-Results`,
  `ARC-Authentication-Results` and `Received-SPF` line for substrings and look
  for `dmarc=pass` before `dmarc=fail`, so a sender who typed
  `Authentication-Results: …; dmarc=pass` into their own message was believed
  over the receiving server's failure. It is now an RFC 8601 parser that
  believes only `Authentication-Results`: with the new `{ authserv }` option,
  every header carrying your receiving server's authserv-id; without it, the
  topmost header only. ARC copies and `Received-SPF` never supply the verdict.
  When trusted headers disagree the worse result wins — a pass has to be
  unanimous — except that one passing DKIM signature in a header is a pass,
  and an SPF result for the envelope sender outranks one for the HELO name.
  `scan()` reads its verdict through the same rule, so a forged ARC header can
  no longer outrank the real verdict there either.
- **A forged `Received-SPF` no longer chooses the origin IP.** That IP is the
  address every DNS blocklist is asked about. `extractOriginIp` used to take
  the first `client-ip=` anywhere in the authentication block, ahead of every
  other source, so a listed spam source could type
  `Received-SPF: pass client-ip=<a clean address>` into its own message, and
  the blocklists were asked about the clean address instead.
  - The address now comes only from the receiving server's own
    `Authentication-Results`. That is the header the verdict is read from,
    chosen by the same rule, and it is read from its SPF or iprev result:
    `smtp.remote-ip=`, `policy.iprev=`, or the SPF comment (Gmail's
    `designates …`, `does not designate …` and `… is neither permitted nor
    denied`, and Microsoft's `sender IP is …`).
  - Failing that, the address comes from the `Received:` trace.
  - `Received-SPF` and `ARC-Authentication-Results` are never read. Neither
    names its author, and nothing ties a `Received-SPF` to the receiving
    server, not even its position.
  - Pass the new `authserv` option to `extractOriginIp` /
    `originIpFromAuthHeaders` (`scan()` passes its own), and the address
    comes only from that server's header.
  - With several headers carrying that id, only the topmost one that
    checked the client is read. A forgery that copied the id sits below the
    real header and is never consulted.
  - An envelope sender quoted into the server's comment cannot put words in
    its mouth: quoted stretches are not read.

### Added

- **`parseAuthResultsHeader(value)`** — one `Authentication-Results` value
  parsed: its authserv-id (`null` for Microsoft 365's id-less format) and each
  `method=result` statement with its `reason` and `ptype.property` values.
  Comments (nested included) and quoted strings are handled, so a `;` or
  `dmarc=pass` inside either is text, not syntax. Each statement carries its
  `comments` as written, which is where Gmail and Microsoft 365 record the
  client they checked.
- **`authserv` on `extractOriginIp` and `originIpFromAuthHeaders`** — the
  same value `parseAuthenticationHeaders` takes, so the origin IP and the
  verdict come from the same header.

### Changed

- `parseAuthenticationHeaders` reads only lines named
  `Authentication-Results`. A bare `dmarc=pass`, or any other header name,
  is no longer read — which also makes it safe to hand a whole raw header
  block. `spf=hardfail` (RFC 5451's spelling of `fail`) now reads as `fail`.
- `trustedAuthHeaders` reads a configured authserv-id with the same parser,
  so a version number or comment after the id (`mx.example.com 1;`) no longer
  hides the server's own header. It keeps only `Authentication-Results`
  lines: without an id, the topmost one, where it used to keep the topmost
  line of each name, so the topmost `Received-SPF` and ARC copy rode along.
- `extractOriginIp` and `originIpFromAuthHeaders` no longer read
  `Received-SPF` or `ARC-Authentication-Results`. A message whose only source
  of an address was one of them now takes it from the `Received:` trace, or
  records none.

## [0.4.2] - 2026-09-28

### Fixed

- **A number in a link's text is no longer read as a domain.** `domainsInText`
  now takes a bare token only under a real (ICANN) public suffix; `tldts`
  treats an unknown last label as a suffix, so `₹3.2`, `2.58` or `Mr.Smith`
  came back as "domains" and an invoice whose amounts link to the biller
  scored as three deceptive links. A written-out URL (`https://bank.example/`)
  still names its host whatever the suffix.
- **`sendclean.net` is a link wrapper.** Its click tracker
  (`track.sendclean.net/c/`) wraps signature links, so "www.sarv.com" going
  through it was charged as a link dressed as the reader's own domain.

## [0.4.1] - 2026-09-28

### Added

- **`authenticationFailed(auth)`** (`/verdict`, zero imports) — the one rule for
  "the sender's domain actively failed to authenticate": DMARC `fail`, or SPF
  and DKIM both failing when DMARC gave no verdict. The scorer's `auth-failed`
  and the shield's `danger` both read it now, instead of two copies.
- **Trust in a sender** — `SecurityInput.trustedSender`. The reader has
  vouched for this exact address; when the message authenticated, the sender
  name check and the spam score stop counting against it (both still shown,
  as passes, with the score and its reasons). Links and blocked links are
  still judged. Set aside when authentication FAILED — a forged copy of a
  trusted address is the likeliest forgery of all — and the sender check says
  so. `SecurityAssessment.trusted` reports whether the trust was applied.

### Changed

- **`in-reply-to-self` weighs 1 on its own and 2 only beside a sender-identity
  lie** (`brand-impersonation` or `display-name-spoof`). It was introduced on
  the premise that no real mailer names its own Message-ID in In-Reply-To;
  Axis Bank's genuine alert mailer does. Beside a lie it is still the Adobe
  Sign lure's pair, and those headers alone still reach the spam line.
- **`bulk-no-unsubscribe` counts only a message that DECLARES itself bulk**
  (`List-Id`, or `Precedence: bulk | list | junk`). `Feedback-ID` and an ESP's
  tracing headers name the sending pipe, not the kind of mail: a bank alert, an
  OTP or a receipt goes through the same pipes with no unsubscribe route,
  rightly, and was charged a point toward the spam line.

### Fixed

- **Indian banks writing from their `.bank.in` domains were flagged as
  impersonating themselves.** The RBI moved Indian banks to `.bank.in`, which is
  a public suffix, so Axis Bank's `axis.bank.in` has the registrable label
  `axis` — which carries no `axisbank` — and a genuine AutoPay notice scored
  `brand-impersonation` and was filed as spam. Axis Bank, SBI, HDFC Bank
  (`hdfc.bank.in`, `hdfcbank.bank.in`), ICICI Bank, Kotak and HSBC now list
  their live `.bank.in` sending domains, each audited as registered through
  IDRBT with SPF and DMARC `p=reject`. A domain under a registrant-verified
  suffix (`bank.in`, `.bank`) is matched by the list only, never by its short
  label, so `axis-login.example` writing as Axis Bank is still caught.

## [0.4.0] - 2026-09-24

### Added

- **Domain age** (`/age`, `tldts` only) — `lookupDomainAge(domain, options)`
  reads when a domain was registered from the registry's own RDAP record
  (RFC 9083), finding the right registry through IANA's bootstrap file, and
  `assessDomainAge({ sender, links })` scores it: `reputation-domain-new` for
  the sender's domain and `reputation-link-new` for the youngest domain the
  message links to, 3 / 2 / 1 points under 7 / 30 / 90 days. The lure that
  shipped 0.3.0 was sent from a 78-day-old domain and linked to a five-day-old
  one that no blocklist had heard of; a blocklist lists what has been
  reported, and fresh registration is the one fact about a campaign domain
  that is true before that. The two reasons together are capped at
  `DOMAIN_AGE_MAX_POINTS` (`SPAM_THRESHOLD - 1`), so age alone can never file
  a message: a start-up's first week looks exactly like this. Every failure —
  a TLD with no RDAP, a registry that publishes no date, a 404, a rate limit,
  an outage — is a `status` that scores nothing, and the lookup never throws.
  HTTPS is injected and nothing caches, as with `/brand`; a registration date
  never changes, so callers should remember answers for weeks.
- **`readBounded(response, maxBytes)`** (`/brand`) — the body half of
  `fetchBounded`, for a caller that needs the status code first. Shared with
  `/age`, so there is one place that refuses an oversized body.
- **A `brands` option wherever a sender is judged** — `assessSender`,
  `impersonatedBrand`, `brandsNamedIn`, `brandOwningDomain`, and the `brands`
  field of `SpamSignalInput`, `ContentSignalInput`, `SecurityInput`,
  `assessPhishing` and `ScanOptions`. It defaults to `PROTECTED_BRANDS`; a mail
  client passes `[...PROTECTED_BRANDS, own]` to protect the mailbox owner's own
  organisation without a pull request here, the way `matchSpamVocabulary`
  already takes its groups. The domain lookup is now an index built once per
  list rather than a scan per message.
- **Provenance for the brand list.** `ProtectedBrand` gains `sources` (HTTPS
  pages where the domains were checked) and `verified` (when). Required for
  every brand added from now on; the 39 that predate the fields are named in
  `test/brands.test.ts`, a list that can only shrink.
- **`scripts/verify-brands.mjs`** (`pnpm verify:brands`) — every listed domain
  checked against its registry (RDAP, or delegation where a ccTLD publishes
  none), SPF and DMARC. Fails on a domain nobody has registered, which is the
  dangerous direction: a listed domain may wear its brand's name
  unchallenged, and an unregistered one can be bought. Runs weekly in CI and
  on every pull request that touches the list.

### Changed

- **The brand list is one file per brand**, in `src/data/brands/`, assembled
  by `index.ts`. `PROTECTED_BRANDS` and `ProtectedBrand` are exported exactly
  as before. One file each makes an entry reviewable on its own, gives it a
  history of its own and room for a note on why a domain is or is not there.

### Fixed

- **A brand name on a free mailbox address is judged again.** 0.3.0 listed
  gmail.com and googlemail.com under Google, hotmail.com, live.com, msn.com and
  outlook.com under Microsoft, and icloud.com, me.com and mac.com under Apple.
  Anybody can open an address at those, and a listed domain is exempt from
  `brand-impersonation` — so "Microsoft account team" <anyone@outlook.com>,
  among the commonest lures there are, passed the rule written for it. Found
  by the first run of `verify-brands`; the nine are removed, each brand's file
  says why, and a test now refuses any listed domain that appears in the
  freemail corpus unless it is named as an exception with its reason. The
  brands' own notices come from their own domains and are unaffected.

## [0.3.0] - 2026-09-23

### Added

- **`brand-impersonation`** (header stage, 3 points) — the display name
  borrows a protected brand's name on an address outside that brand's own
  domains. `"Adobe Acrobat Sign" <Adobesign@powersublinks.com>` passed SPF,
  DKIM and DMARC — for powersublinks.com, which the attacker owns — and the
  existing display-name rule needed a DOMAIN in the name to have anything to
  compare, so a name with no dot in it sailed through under a green shield.
  Authentication says who sent a message, never whether they are who the name
  says; the one offline check left is knowing which domains a brand actually
  writes from. `src/data/brands.ts` holds that list — thirty-nine brands, each
  with the names it is impersonated with and the registrable domains it sends
  from, with the bar for an entry in the file header — and `brandsNamedIn`,
  `brandOwningDomain` and `impersonatedBrand` (`/identity`) read it.
  `assessSender` reports the match as `danger`, so the shield paints it red
  exactly as it does the embedded-domain spoof; the two are exclusive, because
  one display name is one lie. List mail is exempt: a list that rewrites From
  for DMARC puts the author's name on its own address, so the scorer drops the
  reason under a `List-Id` and every reader treats ` via ` in a name the same
  way. So is any sender domain that carries the brand's own name
  (`domainCarriesBrandName`): a brand's real sending domains outnumber any
  list — Axis Bank writes from `alerts.axisbankmail.bank.in` — and red on a
  bank statement is the false positive this package exists to avoid. The
  price, stated in the tests as a known limitation, is that a lookalike
  domain (`paypal-secure.example`) is not this rule's business; it is a
  different tell and needs a rule of its own.
- **`in-reply-to-self`** (header stage, 2 points) — `In-Reply-To` names the
  message's own `Message-ID`. No mail client produces a reply to itself; a
  phishing kit does, so that a threading view shows a conversation already
  under way. The campaign above did exactly this, and with the brand name it
  is 3 + 2 on the headers alone.
- **`ContentSignalInput.recipientDomains`** — who the message was addressed
  to, so `link-display-mismatch` can tell a link dressed as the READER'S OWN
  organisation ("Sarv.com Engagement Letter" pointing at kuaiyudh.top, 4
  points) from one borrowing a protected brand's domain (3) and from anyone
  else's (2). `scan` fills it from To and Cc; a client passes the mailbox
  owner's domain as well. The heaviest tier still sits below `SPAM_THRESHOLD`:
  a vendor newsletter wrapping a link to the reader's own site through a
  tracking host not on the wrapper list must not be filed on that alone.
- **`PhishingReason.kind`** — `domain`, `brand`, `punycode` or `link`, so a
  scorer can give each check its own reason id while a shield keeps reading
  `severity` alone.
- **`PROTECTED_BRANDS`** and the three helpers above are exported from
  `/identity` and the main entry. `normalizeForMatching` and `containsPhrase`
  moved to `src/text.ts`, which has no dependencies, so the identity entry and
  the vocabulary stage fold text the same way; both are still exported from
  `/content` under their old names, and `/identity` still costs `tldts` alone.

### Changed

- **Weights.** `link-display-mismatch` is 2, 3 or 4 by whose name the text
  borrowed (above); every other rule is unchanged. The content stage's
  guarantee is now "no single rule reaches `SPAM_THRESHOLD` alone" rather than
  "no single rule exceeds 2" — the 4-point tier is the one exception, and it
  is argued in `src/content/rules.ts`.

## [0.2.0] - 2026-09-21

### Added

- **`linkDomains(body, options)`** (`/links`) — the registrable domains a
  message links TO, which is the input a reputation check needs and a
  different question from the domain it was sent FROM: a phish is rarely sent
  from a listed domain, it links to one. Reads anchors, image-map `<area>`
  elements and `<form action>` — the last being where a credential-harvesting
  page posts what the reader typed, the most consequential destination in a
  phishing mail and the one that is never an anchor — plus bare URLs typed
  into an HTML body, which every client autolinks. Quoted history and link
  wrappers are excluded by default (`includeQuoted`, `includeWrappers` to
  override): charging a forwarder for the phish they forwarded is wrong, and
  without the wrapper list the cap fills with `sendgrid.net` and `t.co` before
  a real destination is reached. Capped at `LINK_DOMAINS_MAX` (20) distinct
  domains, in document order.
- **`HtmlExtract.links`** (`/content`) — every navigable destination in a
  document, in order, each flagged `quoted` and tagged with the element that
  offered it. Wider than `anchors` on purpose and answering a different
  question: an anchor is read for the pair a reader sees, words and
  destination, so the deceptive-link check needs exactly the elements that
  have visible words; "where could this message send me" has no such limit.
  `<iframe src>` and `<img src>` are deliberately absent — the client fetches
  those, the reader does not navigate to them, and counting them would put
  every tracking pixel's host into the answer.
- **`summarizeLinkDomains(html, senderDomain)`** (`/links`) — the counted form
  of `linkDomainsAllMatch`: how many links the sender wrote, and which ones
  leave their domain, each carrying the domains its text named. A boolean can
  decide a level but cannot explain it, and a UI that shows the same row of
  ticks under two different badges teaches a reader that the badge is
  arbitrary. `shownDomains(anchor, actual)` is exported from `/links` too, the
  one selection both the deception check and the trust-rule key are built on.
- **`stageOfReason` / `SPAM_REASON_STAGES`** (`/verdict`, no dependencies) —
  which stage produced a stored reason: `header`, `content`, `attachment` or
  `reputation`. For a consumer that scores a message in pieces, which every
  mail client does: headers arrive at sync, the body on demand, so re-running
  the body stages has to replace their own previous reasons rather than append
  a second copy — and the headers that produced the rest of the verdict are
  long gone by then. An id this version does not know returns `null`, meaning
  "leave it alone", so a verdict written by a newer release does not lose
  points on the way through an older reader.
- **Brand marks** (`/brand`, `htmlparser2` + `tldts`) — `lookupBimi(domain,
  options)` resolves what a sender domain publishes about its own logo: the
  DMARC policy that gates it, the `default._bimi` record, the SVG itself, and
  the Verified Mark Certificate that turns a picture into a verified identity.
  `discoverFavicon(domain, options)` is the fallback mark for the domains that
  publish no BIMI at all. Both return a `data:` URI, so whatever renders the
  mark never talks to the domain.
- **A logo is shown only under an enforcing DMARC policy.** That is BIMI's
  whole premise — a spoofer must never get to wear the brand — so `p=none`, no
  DMARC record, or `pct` below 100 mean no logo whatever the BIMI record says.
  For a subdomain sender the organisational domain's `sp=` governs, because
  that is the policy that actually covers the mail.
- **The tick is a full certificate check, against pinned roots.** `status:
  'verified'` needs the chain to reach one of the `MVA_ROOTS` shipped in the
  package — the certificates themselves, by SHA-256 fingerprint, not an
  authority's name — with the BIMI extended key usage `1.3.6.1.5.5.7.3.31` on
  the leaf, a SubjectAltName covering the From domain, every certificate
  inside its validity dates, and the RFC 3709 logotype extension binding
  **this** logo by digest or by an embedded copy that matches byte for byte
  (SHA-1 included, because Apple's VMCs still use it). Anything short of that
  demotes to `'logo'` with the reason in `detail`: never a silent pass, and
  never taking the brand's logo away over a certificate problem.
- **The logo is checked before it is shown.** `checkBimiSvg` requires SVG Tiny
  PS and refuses script, event handlers, `foreignObject` and every external
  reference, at a 32 KB ceiling with a gzip bomb refused on its decompressed
  size. A logo is markup a stranger chose, rendered beside their name in a
  reader's mail.
- **`@peculiar/x509` and `asn1js` are optional peer dependencies**, reached
  through dynamic `import`s inside the loader that needs them, and pinned as
  such by the entry-point test. An install without them still gets the logo,
  the SVG check and the favicon; what it loses is the tick, and the detail
  names the package to add rather than blaming the brand's certificate.
- **The favicon is identified by its bytes, never by its `Content-Type`.** A
  200 that is really an HTML error page is the usual answer to a missing
  favicon, and it must never become somebody's avatar. Discovery follows what
  a browser does — the icons the homepage declares, best first, then
  `/favicon.ico` — and falls back to the organisational domain for the
  `notify.` and `mailer.` subdomains that serve no website. Fetching one
  discloses to that domain, once, that a client at this address looked it up,
  which is why a consumer should put it behind a setting.
- **`'none'` and `'error'` are different answers.** A DNS miss means the
  domain publishes nothing and is worth caching for a week; a resolver failure
  or an unreachable host is worth about a minute. Nothing here caches — the
  caller owns that, because the caller knows how long it wants to believe an
  answer — but conflating the two is how a brand's logo disappears for
  everyone after one bad afternoon on the network.
- **The entry runs in a browser.** DNS and HTTPS are injected (`query` and
  `fetch`, defaulting to `node:dns` and the platform `fetch`), and every byte
  operation goes through the web platform — `Uint8Array`, `crypto.subtle`,
  `DecompressionStream` — rather than `node:buffer` or `node:zlib`. The
  injected `DnsQuery` is the same contract `/reputation` takes, now a shared
  resolver rather than one per stage, so a caller with its own DoH client or
  cache passes it to both.
- **Reputation** (`/reputation`, `ipaddr.js` only) — `checkReputation(target,
  blocklists, options)` asks DNS blocklists what they have published about the
  address a message was delivered from and the domain it claims, and
  `assessReputation(result)` turns the answer into a scored assessment.
  Spamhaus ZEN, Spamhaus DBL and SpamCop are described and exported; `node:dns`
  is reached through a dynamic `import`, so the entry costs a browser bundle
  nothing but `ipaddr.js`.
- **No default list of blocklists, deliberately.** `blocklists` is a required
  argument. Every list has terms — free below some volume, a paid feed above
  it, and a permanent "over quota" answer once you pass it — and every lookup
  discloses to that operator a sender your user is receiving mail from. A
  package that queried zones by default would put you in breach of somebody's
  terms, and disclose your users' mail, without you having chosen either.
  `BLOCKLISTS` is a list to read and pick from, not one to inherit.
- **The return code is read as the answer.** A listing is scored by which code
  came back where the zone publishes a table (`127.0.0.2` SBL against
  `127.0.0.10` "should not be delivering mail directly" are not the same
  evidence), and two kinds of answer are never listings: `127.255.255.0/24`,
  which is the operator reporting a malformed query, an open resolver or an
  exceeded quota, and anything outside `127.0.0.0/8`, which is a wildcard or
  hijacked response. Both reach `errors`. Reading "an A record came back" as
  "listed" turns one misconfigured resolver into a filter that files every
  message as spam at once.
- **A failed lookup is never a clean result.** A timeout, a SERVFAIL or a
  target not worth querying leave `completed: false` with no hits, rather than
  `listed: false` presented as an all-clear; zones that did answer keep their
  hits, so one operator's outage never discards another's listing.
  `checkReputation` does not throw. Only public addresses are queried — the
  same gate `extractOriginIp` uses — so private and reserved ranges are skipped
  rather than published to an operator one query at a time.
- **Several lists agreeing counts once.** `assessReputation` charges the
  highest-scoring hit per kind of target rather than the sum, because the
  public lists mirror each other and ZEN is three lists in one zone; summing
  would make a score depend on how many zones a deployment configured. The
  address and the domain are separate facts, so those two do add up — as far
  as `REPUTATION_MAX_POINTS` (`SPAM_THRESHOLD + 1`), which is enough for a
  listed sender to be spam on this evidence alone and no more. The address is
  charged first and the domain takes what is left, so a truncated reason is
  always the weaker half; `assessReputation(result, { maxPoints: Infinity })`
  lifts the ceiling for a caller running its own points table.
- **The shield explains the sender's mark.** `assessEmailSecurity` accepts a
  `bimi` input — a `BimiLookup` from `/brand`, or the columns a caller cached
  from one — and adds a `brand` check saying who proved ownership of the
  domain and which Mark Verifying Authority vouched for them, or why no tick
  is being shown. It never moves the level: most legitimate senders publish no
  BIMI record, so scoring its absence would warn about most of the world's
  mail, and a certificate proves who owns a brand rather than that this
  message deserves trust. Reported as proof only under a DMARC pass, because
  without one the sentence is what a spoofer would like the reader to see.
  Omitting the input drops the row; passing `null` says "not looked up yet".
- **Reports from other recipients** —
  `assessReputation(result, { userReports })` scores the one signal a lookup
  cannot find: how many other people have already reported this sender's
  domain as spam. Three reports (`USER_REPORTS_MIN`, movable per call with
  `minUserReports`) are worth three points (`USER_REPORT_POINTS`) under the
  new `reputation-user-reported` id — one report is one opinion, and a
  crowd's opinion is evidence but not an operator's observation. Charged
  after the listings out of what is left of the same budget, so the crowd
  can never carry a message over the stage's ceiling by itself, and ignored
  entirely when the result carries no domain to name.
- **Stored reasons are read under their current ids.** `parseSpamReasons`
  maps the ids Sarv Inbox shipped before this package existed
  (`ip-blocklisted`, `domain-blocklisted`, `user-reported`) onto the
  namespaced ones, and `canonicalReasonId(id)` exposes the same mapping on
  its own. A verdict cached a year ago still renders against today's
  `SpamReasonId` union, and an id from a newer version passes through
  untouched rather than being dropped — a reader that shows less is better
  than one that shows a blank row for the message somebody is trying to open.
- **Bitmask zones** — `Barracuda` (`b.barracudacentral.org`, registration
  required before its mirror answers anything but NXDOMAIN), `SURBL`
  (`multi.surbl.org`) and `URIBL` (`multi.uribl.com`) join the catalogue. The
  two URI lists pack their categories into the last octet, so a domain that is
  both a phishing site and a malware host answers `127.0.0.24` — an address in
  no code table. A zone declares `bits` instead of `codes`, several records are
  ORed before they are read, and every category the mask sets is reported.
  Reading a bitmask as an exact code downgrades the worst listings there are;
  reading it as a boolean makes URIBL's grey list — bulk mail of dubious value
  — indistinguishable from a spam run.
- **A zone may publish its refusal inside `127.0.0.0/8`.** Both URI lists
  answer `127.0.0.1` to a query from a public resolver or from a querier over
  the free-use limit: a refusal in the shape of a listing, arriving for every
  domain at once. `Blocklist.refusals` names those codes so the error carries
  the operator's own words, and a refusal that arrives beside a real listing
  never discards the listing.
- **A category on every described code** (`spam`, `exploited`, `phishing`,
  `malware`, `botnet`, `policy`, `abused`, `grey`), reported on the hit, so a
  consumer can group listings across zones or apply its own points table
  without copying the catalogue back out of the package.
- **`checkReputationBatch(targets, blocklists, options)`** — many targets over
  one resolver, with `concurrency` queries in flight (default 8). A backlog
  scored after the fact is hundreds of addresses across several zones, and
  both obvious shapes are wrong: sequential is an hour of round-trips, and
  `Promise.all` over the lot opens a thousand simultaneous queries that c-ares
  will not serve and an operator reads as an attack. Results come back in the
  order the targets were given, and a batch with nothing worth asking about
  opens no socket at all.
- **`ScanOptions.reputation`** — an assessment from a lookup you ran yourself,
  folded into the message's score. The same arrangement as `options.auth` and
  for the same reason: the DNS happens outside `scan`, on your schedule and
  against zones you are entitled to query, and absent or `null` contributes
  nothing.
- **`reputation-ip-listed` and `reputation-domain-listed`** (`/verdict`) — two
  new reason ids, so a stored verdict that includes a blocklist hit still reads
  back with `parseSpamReasons`.
- **Real authentication** (`/verify`, no static dependencies) —
  `verifyAuthentication(message, options)` checks SPF, DKIM and DMARC against
  live DNS over the original unmodified bytes, instead of reading a verdict
  some other machine wrote into a header. It returns the same `AuthStatus` the
  header reader produces, plus every DKIM signature with its signing domain,
  selector, verbatim result word, comment and alignment, the SPF domain, the
  published DMARC policy, and whether the verification completed at all.
- **`mailauth` is an optional peer dependency, loaded on demand.** It is
  reached through a dynamic `import` inside the one function that uses it, so
  installing this package does not install a DNS library and no bundle carries
  one by accident; the entry-point test that walks the source import graph
  pins that. Without it installed, `verifyAuthentication` throws a message
  naming what to install and everything else in the package is unaffected.
- **`ScanOptions.auth`** — a verified verdict used in place of the one read
  from `Authentication-Results`. This is how DNS verification reaches the
  rules, and it is deliberately the long way round: `scan` and `scanParsed`
  still make no network calls at all, so the same message scores the same way
  in a test, in a bundle and on a machine with no resolver, and a run over
  fifty thousand messages does not quietly become fifty thousand DNS lookups.
  `null` or absent falls back to the headers, so a verification that timed out
  degrades to what the trusted headers said rather than to nothing.
- **A failed verification is never a failed verdict.** A timeout, a resolver
  error or an unreachable nameserver return `completed: false` and three
  `unknown`s, never `fail`. `auth-failed` is worth 3 points, and an outage on
  the verifier's side must not start scoring everybody's mail. `timeoutMs`
  defaults to 10 seconds and `resolver` accepts your own — a cache, a stub, a
  DoH client.
- **`unknownAuthStatus` and `rollUpAuthStatus`** (`/verdict`, still zero
  dependencies) — the "two of three passed" rollup, extracted so the header
  reader and the DNS verifier cannot drift into disagreeing about the same
  three component verdicts. The verifier maps `mailauth`'s `neutral` (body
  hash mismatch, no key, expired) and `policy` (a key below `minBitLength`) to
  `fail` for the same reason: those are the cases Gmail writes as `dkim=fail`
  in the header the other producer reads.
- **`scan(rawMessage)` and `scanMany`** (`/scan`, adds `postal-mime`) — raw RFC
  5322 bytes in, one JSON verdict out, with both stages included. Everything
  else in the package takes pieces a mail client already has; this is for the
  other half of the audience, who have a maildir, an archive or a gateway
  handing them bytes and would otherwise have to reimplement not just the MIME
  parsing but the decisions about what in a message to believe. `scanParsed`
  takes an already-parsed message, so a caller who needed the MIME for their own
  reasons does not pay to parse it twice.
- **`ScanOptions.authserv`** — the RFC 8601 authserv-id your own boundary MTA
  stamps into `Authentication-Results`. Given one, only that server's verdicts
  are believed. This matters more than it looks: `Authentication-Results` is
  plain text that any hop can write, including the sender, who can type
  `dmarc=pass` into their own message. Without an authserv-id, `scan` keeps only
  the **topmost** line of each authentication header and discards the rest, on
  the conventional assumption that your own MTA was the most recent hop — a
  forged verdict sits at the bottom of the trace, because every hop prepends.
  `trustedAuthHeaders` is exported so a caller can see which lines survived.
- **`ScanOptions.receivedAt`, and `receivedAt` / `receivedAtFromLine`**
  (`/headers`, still zero dependencies) — the delivery time the date-skew rule
  compares the sender's `Date:` against, read off the topmost `Received:` line.
  A raw `.eml` has no IMAP INTERNALDATE, so without this the skew rule could
  never fire on a scanned file and a message dated three years out would score
  the same as one dated correctly. Pass your own INTERNALDATE when you have one.
- **Bulk-stream guarantees.** `scanMany` yields results **in input order** even
  though the scans overlap — a bulk API whose output order depends on how long
  each message took is one nobody can write a stable test, or a resumable job,
  against. A message that cannot be read is reported as `{ error }`, never
  thrown: one bad message in a mailbox of fifty thousand must not end the run.
  The source is consumed lazily and at most `concurrency` messages are held at
  once, so it works on a mailbox larger than memory.
- **The attachment stage** (`/attachments`, **zero dependencies**) —
  `assessAttachmentSignals` scores what a file claims to be against what its
  bytes actually are, with seven new rules: `attachment-name-spoof`,
  `attachment-double-extension`, `attachment-executable`,
  `attachment-type-mismatch`, `attachment-macro`,
  `attachment-archive-executable` and `attachment-encrypted-archive`. The
  filename and the `Content-Type` are claims the sender wrote; the magic bytes
  are the only one of the three that cannot be made to say something other than
  what the reader's software will do, and the disagreement between them is the
  signal. `scan` runs the stage automatically on the bytes `postal-mime`
  decoded, so a caller gets it without changing anything.
- **Nothing is executed, unpacked or inflated.** An archive's central directory
  is read — names, declared sizes, the encrypted flag — and nothing else. That
  is a security decision, not an optimisation: a 42 KB zip bomb expands to
  several petabytes, and a scanner that inflates what it is handed needs a
  budget, a timeout and a recursion limit to survive being mailed one. It is
  also why the entry costs nothing: an inflater is the one dependency a scanner
  handed hostile archives should not carry. The directory walk is bounded at
  2,000 entries, and a listing that hit the bound says so rather than pretending
  it saw everything.
- **`inspectAttachment`, `sniffFileType`, `inspectFilename`, `listZipEntries`,
  `asBytes`** — the facts the rules scored, exported so a consumer can display
  them or score them differently. `asBytes` is the one place content is turned
  into a byte view, which is what keeps a Node `Buffer` — nearly always a window
  onto a larger shared pool — from being read from the start of the pool rather
  than the start of the file.
- **Attachment extension lists as data** — `src/data/attachment-extensions.ts`,
  with two executable lists rather than one. A `.js` file attached to an email
  is a dropper; a `.js` file inside a zip is `node_modules`. What counts inside
  an archive is the narrower set with no innocent reason to be zipped and
  mailed: Windows binaries, script-host formats, shortcuts and installers.
- **The stage is not an antivirus and does not claim to be.** No signature
  database, no emulation; a clean result means "nothing structurally
  deceptive", never "safe to open". No rule is worth more than 2 points and a
  bare executable attachment reaches neither threshold on its own — a developer
  mailing a build to a colleague sends the same bytes as a dropper. It is the
  combination that files a message.
- **The body-content stage** (`/content`, `htmlparser2` + `tldts`) —
  `assessContentSignals` scores what the message says with seven new rules:
  `content-spam-vocabulary`, `content-shouting`, `content-hidden-text`,
  `link-display-mismatch`, `link-bare-ip`, `link-userinfo` and `link-punycode`.
  It scores the sender's **own** words: quoted history, the signature after a
  `-- ` delimiter, the mail client's footer and anything inside a `blockquote`
  or a client quote container are removed first. Otherwise the person who
  forwards a phish to their IT desk is scored as the phisher, and a long thread
  gets worse every time somebody hits reply. Where both a `text/plain` and a
  `text/html` part exist, only the HTML is scored — they say the same thing, and
  scoring both would double every hit for no reason but the MIME shape.
- **The stage cap.** The vocabulary and shouting rules are an interpretation of
  prose rather than a fact about it, so together they are worth 3 at the very
  most: enough to raise a suspicion for a human, never enough to reach
  `SPAM_THRESHOLD` and file a message. Word lists age badly, and one that can
  convict alone eventually eats somebody's ordinary mail. The hidden-text and
  link rules are facts about the bytes and accumulate uncapped. No single rule
  in the stage is worth more than 2 points.
- **Word lists as data, enrichable by pull request** — `src/data/spam-phrases.ts`
  groups phrases by the scam rather than by the word, which is what makes the
  cap meaningful: twelve pharmacy phrases are one pharmacy advert, not twelve
  pieces of evidence. Matching is on NFKC-normalised, lowercased text with
  zero-width and soft-hyphen characters stripped, on whole-word boundaries, so
  the fullwidth and invisible-character tricks match and `wonderful` does not.
- **Body extraction, exported** — `bodyContent`, `extractHtml` (visible text,
  quoted text, hidden text and every anchor with its label), `ownWords`,
  `matchSpamVocabulary`, `vocabularyPoints`, `normalizeForMatching`,
  `containsPhrase`, `collapseWhitespace` and `longestShoutRun`. A client that
  wants to explain why a rule fired needs to see exactly what the rule saw.
- **`assessmentOf` and `mergeAssessments`** (`/verdict`, still zero
  dependencies), plus `SpamAssessment`, which moved here from the header rules.
  Merging concatenates reasons and re-totals rather than OR-ing two booleans, so
  a header stage and a content stage that each fall short of the threshold can
  still add up to a filing. Two call sites each computing `isSpam` for
  themselves is how two parts of a product start disagreeing about one message.
- **Shared URL helpers** (`linkTarget`, `urlsInText`, `anchorMismatches`,
  `LINK_WRAPPER_DOMAINS`), extracted so the link stage and the content stage
  answer "where does this actually go?" with one implementation.
- **`FREEMAIL_DOMAINS`** is now exported — the corpus the freemail rules read.
- **The reply cut is its own entry** (`/quote`, no dependencies) —
  `stripQuotedTail(text)` returns everything above the quoted history with the
  signature left in place, `ownWords(text)` takes the signature and the client
  footer out as well, and `QUOTE_MARKERS` is the corpus both share. Two callers
  want opposite things from one cut: a scorer must not charge a sender for the
  phone number under their own name, and a contact miner is reading for exactly
  that number. They were two marker lists in two repositories, which is how a
  rule drifts invisibly — both copies go on returning a plausible string.

### Changed

- **`assessEmailSecurity`'s Links row now names the fact that decided the
  level.** It reported only the deception test — "Link domains match what they
  show" — while `verified` vs `authenticated` turns on a different question:
  whether every link stays on the sender's own domain. Two messages could show
  seven identical green ticks under two different badges with nothing on
  screen to tell them apart. The row now reads
  `…; 2 links leave example.net (docs.google.com, status.io)` when links go
  out, `…, and every link stays on example.net` when they do not, and
  `The sender wrote no links in this message` when there were none: an absence
  is no longer reported as a check that ran and passed.
- **BREAKING (behavioural): `linkDomainsAllMatch` takes an optional `isVetted`
  predicate, and `assessEmailSecurity` passes one.** A link pair the user has
  trusted now also stops blocking `verified`. Its doc comment had promised this
  for two releases while the function had no way to ask — so trusting a pair
  lifted a message out of `caution` and then withheld the top level for the
  very link that had just been forgiven, which reads as the setting being
  ignored. Messages with a trusted off-domain pair will move from
  `authenticated` to `verified`.
- **`ownWords` recognises more of the quoted history**, having taken in the
  markers the other implementation carried: an attribution `html-to-text` has
  collapsed into the middle of a line (the shape most HTML mail arrives in),
  one that opens with the sender's name instead of "On", the French, German
  and Spanish forms, `Begin forwarded message:`, and an indented `>` prefix.
  In the other direction it no longer cuts at a bare `From:` line or at a
  five-character underscore rule, both of which occur in ordinary prose and in
  signatures — a false cut deletes the sender's own words, silently. Scores
  computed over long or non-English threads may go DOWN, which is the point:
  those points were being charged for words somebody else wrote.
- **BREAKING (behavioural): the link checks now find links in Node.** They
  previously parsed HTML with the ambient `DOMParser`, so in Node they found
  nothing at all: the ingest-time scorer silently reported "no deceptive links"
  on every message it ever scored, while a renderer running the identical code
  on the identical message found them. HTML is now parsed with `htmlparser2`,
  so there is one implementation and one answer everywhere. If you scored mail
  server-side against 0.1.x, those verdicts were computed without the link
  rules and are worth re-running. `linkDomainsAllMatch` no longer has a
  "could not read the HTML" case; it now answers from what the HTML says.
- `postal-mime` is the MIME parser rather than `mailparser`: zero dependencies,
  dual CJS/ESM, no `engines` floor, and browser-safe. `mailparser` brings nine
  dependencies and declares `engines: node >=20`, which this package cannot
  inherit while claiming `>=18`.
- `htmlparser2` is pinned to `^10.1.0` deliberately. v11 and v12 are ESM-only
  and declare `engines: node >=20.19.0`; v10.1.0 is the last dual CJS/ESM line
  with no engines floor, and this package publishes CJS and claims `>=18`.

### Removed

- **The `free-email-domains` dependency, and with it an install-time network
  fetch.** Its `postinstall` script downloaded lists from a HubSpot CDN and two
  `raw.githubusercontent.com` URLs and rewrote its own `domains.js` with the
  result. The corpus is now vendored at `src/data/freemail-domains.ts` — 14,028
  lowercased, sorted, de-duplicated entries — under the upstream MIT licence,
  with tests that pin it populated, sorted, de-duplicated and free of anything
  that is not a bare hostname.
- `happy-dom` as a dev dependency. No test needs a DOM any more; the whole suite
  runs in the `node` environment.

### Security

- A dependency that fetches its own data at install time is a supply-chain hole
  that every consumer of this package would inherit: the content that ends up on
  disk depends on what three remote URLs served at install time, which nobody
  reviews, no lockfile pins, and a firewall or a 404 turns into a silently empty
  list. An empty freemail corpus does not fail — `has(domain)` simply answers
  false — so every freemail rule stops firing and nothing anywhere says so.
  Vendoring makes the corpus reviewable in a diff and identical on every install.

- **Header reading** (`/headers`, zero dependencies) — `headerLookupFromText`,
  `headerValueFromText`, `headerValuesFromText`, `bulkHeaderSignals`,
  `hasBulkHeaderSignal`, `BULK_HEADER_NAMES`, `extractAuthHeaderBlock` and
  `parseAuthenticationHeaders`, all of which were previously reachable only
  through the package root. Whether a sender declared itself bulk is a question
  a UI asks as often as a sync does, and both sides have to get the same answer;
  the root entry costs an address parser and a freemail corpus to import, which
  in a browser bundle is dead weight. A test pins this entry's dependency count
  at zero. Origin-IP extraction stays in the root entry — it reads headers too,
  but needs an IP parser.

## [0.1.0] - 2026-09-19

First release. The header stage, extracted from the Sarv Inbox mail client,
where these rules run on real mail at ingest.

### Added

- **Verdict plumbing** (`/verdict`, zero dependencies) — `SPAM_THRESHOLD`,
  `SUSPICIOUS_THRESHOLD`, `spamVerdict`, `isSpamScore`, `parseSpamReasons`, and
  the `SpamReason` / `AuthStatus` types. Importable on its own so a renderer can
  read a stored score back without pulling in a scanner.
- **Sender identity** (`/identity`, `tldts` only) — `registrableDomain`,
  `domainOfAddress`, `domainsInText` and `assessSender`, which flags a friendly
  name claiming one brand while the address belongs to another eTLD+1.
- **Authentication results** — `extractAuthHeaderBlock` pulls the
  `Authentication-Results` / `ARC-Authentication-Results` / `Received-SPF`
  block out of a raw header dump, and `parseAuthenticationHeaders` reads the
  SPF/DKIM/DMARC verdicts out of it. Reads what your MTA decided; does not
  verify against DNS.
- **Origin IP** — `extractOriginIp` and friends, returning the public unicast
  address a message actually came from, preferring the SPF evaluator's own
  record over the `Received:` trace and rejecting private, loopback,
  link-local, CGNAT and reserved ranges.
- **Header lookup** — `headerLookupFromText`, `headerValueFromText` and
  `headerValuesFromText`, which read a named header out of a raw block and
  unfold continuation lines, so callers with a header dump rather than a
  parsed envelope can feed the rules directly.
- **Bulk-mail headers** — `bulkHeaderSignals` and `hasBulkHeaderSignal` over
  `List-Id`, `List-Unsubscribe`, `Precedence`, `Auto-Submitted`, `Feedback-ID`
  and the common ESP trace headers, plus `BULK_HEADER_NAMES` so a fetch can ask
  for exactly what is read.
- **The header rule set** — `assessSpamSignals`, sixteen additive rules
  covering upstream spam verdicts, reported senders, authentication failure,
  display-name spoofing, IDN homographs, undeliverable and mismatched
  addresses, missing or malformed `Message-ID`, date skew, forged reply
  subjects, hidden recipients and bulk mail with no unsubscribe. Exports
  `SPAM_HEADER_NAMES`, `DATE_SKEW_SECONDS` and `isFreemailAddress`.
- **Deceptive links** (`/links`, `tldts` only) — `linkMismatches`,
  `assessLinks`, `linkDomainsAllMatch` and `assessPhishing`, finding anchors
  whose visible text names one registrable domain while the `href` goes to
  another. Thirty ESP and URL-shortener domains are skipped, because
  legitimate marketing mail routinely wraps links through them.
- **Security levels** (`/security`, `tldts` only) — `assessEmailSecurity`
  returning one of `verified | authenticated | unverified | caution | danger`
  with a per-check breakdown, plus `worstLevel`, `LEVEL_RANK`, `linkRuleKey`
  and `parseAuthStatus`. The human copy for each level is deliberately left to
  the caller: a library cannot know a product's voice or language.
- **RFC helpers** — `isValidMessageId` and `hasReplyPrefix`, with no schema
  library behind them.

### Security

- Every regular expression carried over from the originating codebase was
  rewritten to be free of super-linear backtracking — the authentication-header
  scanner, the `Received:` `from` clause, the generic header lookup and the
  reply-prefix matcher, four instances of the same shape — and
  `regexp/no-super-linear-backtracking` is enforced as an **error** in this
  repository rather than a warning. This package's input is mail an attacker
  chose, parsed at ingest: a quadratic pattern against a large header block is
  not a slow scan, it is a mail flow that stops.
- The `Received:` `from` clause is walked token by token instead of matched,
  which cannot backtrack at all, and stops at `by` and `;` so that an address
  appearing in a timestamp or in the receiving side of a hop can never be
  reported as the origin.
- Without a `DOMParser` — in Node, in a worker — every link check returns
  "found nothing" rather than throwing, with one deliberate exception:
  `linkDomainsAllMatch` returns **false**. Its claim is that every link stays
  on the sender's own domain, and that must not be asserted about HTML nobody
  was able to read.

[Unreleased]: https://github.com/Sarv/mailguard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Sarv/mailguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Sarv/mailguard/releases/tag/v0.1.0
