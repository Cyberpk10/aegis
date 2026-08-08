# Corpus sources, provenance, and licenses

All availability/terms below were verified live on **2026-08-07** while building this pipeline
(`ml/aegis_ml/download/`). Re-verify before relying on this for anything beyond internal defensive
research — dataset hosting and terms can and do change. Raw data itself is never committed (see
root `.gitignore` — `ml/data/` and `ml/models/`); this file is the durable record of what was used
and under what terms.

## Nazario phishing corpus — `label=phishing`, `source=nazario`

- **Primary**: `https://monkey.org/~jose/phishing/` — `phishing0.mbox`, `phishing1.mbox`,
  `phishing2.mbox`, `phishing3.mbox`, `20051114.mbox`.
- **Fallback**: Wayback Machine, resolved per-file via `https://archive.org/wayback/available`.
  Verified a snapshot of the corpus index from **2026-06-07** listing all the files above as still
  present, plus yearly `phishing-2015` .. `phishing-2025` entries and a `private-phishing4.mbox`.
- **Verification note**: `monkey.org` was unreachable from the sandbox this pipeline was written
  in (`curl` connection refused), while general internet access from the same shell worked fine
  (e.g. `google.com` returned 200) — this looks like a sandbox-specific network policy rather than
  the site being down. The downloader tries monkey.org first and falls back to Wayback
  automatically, so it should work either way depending on where it's actually run.
- **Scope decision**: only the 5 classic files above are ingested. The yearly `phishing-2015..2025`
  entries appeared in the directory listing with no file extension — whether each is a file or a
  subdirectory wasn't confirmed, so they're **not** ingested in Stage 1 rather than risk silently
  saving an HTML directory listing as if it were mbox content. `private-phishing4.mbox` is excluded
  (access-restricted). Revisit as a future extension once each entry's shape is confirmed.
- **License/terms**: no `LICENSE.txt` content was retrievable (the file is linked from the index but
  wasn't itself archived). `README.txt` (fetched via Wayback, 2025-07-17 snapshot) states the corpus
  is hand-classified by Jose Nazario from his personal inbox, "not meant to be exhaustive but rather
  representative," explicitly **should not contain malware** (e.g. malicious executable
  attachments), and that earlier mailboxes were anonymized (destination IPs/domains) while later
  ones were not. No formal reuse license is stated; used under the long-standing research-use
  convention this corpus has been cited under in the security literature (widely cited — see Google
  Scholar for "nazario phishingcorpus"). The maintainer's README says he'd "love to get a peek" at
  resulting publications.
- **Alternate mirror (not used by the script, documented for manual fallback)**: Academic Torrents,
  `https://academictorrents.com/details/a77cda9a9d89a60dbdfbe581adf6e2df9197995a` — 4,555 `.eml`
  files, 37.48MB, a third-party 2015 re-upload of the same corpus. No explicit license stated. Would
  need a BitTorrent client; intentionally not scripted here to avoid that dependency.

## SpamAssassin public corpus (ham subset) — `label=benign`, `source=spamassassin`

- **URL**: `https://spamassassin.apache.org/old/publiccorpus/` — confirmed live, file listing
  scraped directly at verification time.
- **Files used**: `20030228_easy_ham.tar.bz2` (2,500 messages), `20030228_hard_ham.tar.bz2` (250
  messages), `20030228_easy_ham_2.tar.bz2` (1,400 messages) — 4,150 benign messages total. The
  `spam`/`spam_2` archives in the same listing are **not** used (not needed for this corpus).
- **License/terms** (from the live README): copyright for message text "remains with the original
  senders." Explicit restriction: **"Do NOT send these emails into a live email system"** (avoids
  bounce-back to real addresses in the corpus). Messages were sourced from public forums, submitters
  who gave explicit consent, the maintainer's personal correspondence, and public newsletters; some
  address obfuscation was applied for privacy. Offered specifically for spam-filter research/testing.
  The maintainer requests notification if the corpus is used in academic papers.

## Enron email dataset (subset) — `label=benign`, `source=enron`

- **URL**: `https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz` — confirmed live
  (HTTP 200, `Content-Length: 423254787`, no auth).
- **Subset taken**: rather than extracting the full archive (~500k messages across 150 custodians),
  the pipeline streams the `.tar.gz` directly and reservoir-samples a configurable number of
  messages (default 6,000, seed 42) from each custodian's `_sent_mail/` folder only — mail the
  custodian personally wrote, a cleaner "legitimate business email" signal than inbox/received mail.
  The full ~423MB still has to be transferred once (CMU doesn't offer partial/range downloads of a
  subset); only the sampled subset is written to `ml/data/raw/enron/`.
- **License/terms**: no explicit license stated on the page. The dataset was originally made public
  via the Federal Energy Regulatory Commission's investigation into Enron and has been hosted by CMU
  since; the page asks users to **"be sensitive to the privacy of the people involved,"** notes that
  attachments are excluded and some messages were redacted at affected employees' request. Widely
  treated in the research community as the standard public "real" email corpus given the lack of
  comparable alternatives.
- **Caveat**: the CMU page notes a 2026 disclosure about possible header-spoofing/impersonation in
  parts of the corpus. This doesn't block using it as benign training data here (the content itself
  is genuine internal business correspondence), but `from_addr` may be unreliable for a small
  fraction of messages — worth remembering if `from_addr` is ever used as a model feature.

## PhishTank — reference-only, **not** part of the unified email corpus

- **URL**: `https://data.phishtank.com/data/online-valid.csv` (redirects to a signed CDN URL) —
  confirmed live and downloadable without registration at verification time (13.5MB CSV, real
  current data). An API key is optional and only raises rate limits; not required for this one-shot
  bulk fetch.
- **Why it's excluded from the corpus schema**: PhishTank's data is URL-only —
  `phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target` —
  never raw headers, subject, body text, or a from-address. It structurally cannot fill
  `{id, raw_headers, subject, body_text, from_addr, label, source}` with real email content.
  Fabricating placeholder email rows from bare URLs was considered and rejected in favor of keeping
  the training corpus free of non-representative synthetic data (see project decision log / plan).
  `aegis_ml.download.phishtank.download_phishtank_reference()` still fetches the feed to
  `ml/data/raw/phishtank/online-valid.csv` as a standalone reference file for possible future
  URL-reputation feature work (e.g. cross-referencing URLs found inside other emails) — it is never
  read by `normalize.py`/`dedupe.py`/`split.py`.
- **Terms**: operated by Cisco Talos Intelligence Group; PhishTank states the data is free for both
  website and API use. Governed by Cisco's general Terms of Use/Privacy policy — no PhishTank-specific
  bulk-data reuse license text was found beyond that reference.

## Design rules for downstream stages
- **`label` is binary** (`phishing` | `benign`) — that's the ground truth these public corpora
  actually provide. There's no public source for a `suspicious` middle class; mapping to Aegis's
  runtime three-way verdict is a later M3 concern, not corpus assembly.
- **No feature fitting before the split.** `split.py` only ever touches deduped raw text/schema
  fields — no vectorizer, no corpus-wide statistic. Whatever fits features in a later M3 stage must
  fit on the `train` split only, to avoid leakage into `val`/`test`.
