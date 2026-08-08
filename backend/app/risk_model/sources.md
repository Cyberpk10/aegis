# Financial risk model — assumption sources, provenance, and methodology

All figures below were verified live on **2026-08-07** via direct fetch of the citing page
(not just a search-result snippet), per the same discipline used in `ml/corpus/sources.md`.
Re-verify before relying on this for anything beyond internal defensive reporting — these are
industry-average figures, not a substitute for an actuarial or insurance-grade loss model.

## Business Email Compromise — `bec_avg_loss_usd` = $129,242

- **Primary source**: FBI Internet Crime Complaint Center (IC3), *2024 Internet Crime Report*
  (`https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf`). The report states BEC losses
  totaled **$2.77 billion** across **21,442** reported complaints in 2024.
- **Verification**: confirmed via two independent direct fetches of pages quoting the report —
  `certifid.com/article/fbi-ic3-cybercrime-report` and `abnormal.ai` — both citing the same
  $2.77B / 21,442 figures from the IC3 report.
- **Computed average**: $2,770,000,000 / 21,442 ≈ **$129,242 per reported incident**. This is a
  government-collected complaint dataset (not a vendor survey), the most rigorous single source
  available for this figure.
- **Cross-reference**: `totalassure.com/blog/average-cost-phishing-attack`, aggregating IBM's
  *Cost of a Data Breach Report 2025*, DeepStrike's *Phishing Statistics 2025*, and Hoxhunt's
  *Phishing Trends Report*, independently cites **$160,000** as the average BEC incident cost —
  a different methodology (industry-vendor aggregation vs. reported-complaint average) landing
  in the same order of magnitude, which corroborates the IC3-derived figure without being
  identical to it. The IC3 figure is used as the default because its underlying data
  (government-reported complaints with a stated total-loss and total-count) is directly
  auditable, rather than a vendor's internal survey methodology.

## Credential-harvesting phishing — `credential_phishing_avg_loss_usd` = $97,000

- **What was ruled out**: IBM's widely-cited *Cost of a Data Breach Report* figure (~$4.8–4.88
  million average, 2024/2025 editions) is the cost of a **full enterprise data breach** —
  investigation, containment, customer notification, regulatory response, ~254 days average
  time to detect and contain. That is the wrong scope for "the expected loss from one phishing
  email that Aegis flagged" — using it here would produce absurdly inflated per-detection
  numbers. `totalassure.com`'s own breakdown table lists "Credential Harvesting" at this same
  $4.88M full-breach figure, confirming it isn't a smaller per-incident number.
- **An unverifiable figure was explicitly discarded**: a widely-repeated "$842,462 credential
  theft incident cost," attributed to a "Ponemon-Sullivan Privacy Report," could **not** be
  located on a direct fetch of `ponemonsullivanreport.com/2025/` and was not used anywhere in
  this model.
- **What was used instead**: the same `totalassure.com` breakdown table (IBM/DeepStrike/Hoxhunt
  aggregation, verified via direct fetch 2026-08-07) lists **QR-code phishing** — a
  credential-harvesting delivery method — at **$97,000 average cost per incident**, explicitly
  distinguished in the source table from the $4.88M full-breach figure. This is the
  best-scoped, directly-cited *per-incident* (not per-breach) figure found for a
  credential-harvesting-style attack, and is used here as a **conservative proxy** for
  credential-harvesting phishing generally, not a literal claim that all such incidents involve
  a QR code.
- **Caveat**: this is a proxy, not a precisely-scoped citation. If a better-scoped figure
  becomes available (e.g. from an internal incident-cost log or a cyber-insurance actuarial
  table), override `RISK_CREDENTIAL_PHISHING_AVG_LOSS_USD` rather than relying on this default
  for board-level reporting.

## Generic / other phishing — `generic_phishing_avg_loss_usd` = $97,000

- No distinct verified per-incident figure was found for phishing that fires neither a
  payment/wire-transfer indicator nor a credential-harvesting indicator (e.g. a malicious
  attachment or a lookalike-domain sender with no explicit ask). This bucket defaults to the
  same conservative proxy as `credential_phishing_avg_loss_usd` above, on the reasoning that an
  attacker who got this far (past spam/auth filtering, indicators fired, human review
  triggered) represents a comparable order of magnitude of risk even without a named payload.
  Override independently via `RISK_GENERIC_PHISHING_AVG_LOSS_USD` if better data is available.

## Verdict prevention weights

- `verdict_prevention_weight_malicious` = 1.0, `verdict_prevention_weight_suspicious` = 0.0 —
  these are **not** cited figures; they are an operator judgment call about how much confidence
  to place in a given verdict before counting its avg loss as "avoided." The conservative
  default counts only high-confidence "malicious" detections. An operator with a track record of
  reliable "suspicious" triage (e.g. via `analyst_agreement`/KRIs on the Dashboard) may
  reasonably set `RISK_WEIGHT_SUSPICIOUS` above 0.

## Design rules for downstream use
- **Always return inputs alongside output.** `GET /api/risk/financial`'s `assumptions` block is
  populated from `RiskModelAssumptions.to_response_dict()` on every call — there is no code path
  that returns a dollar figure without the assumptions that produced it.
- **Residual risk is scoped only to Aegis's own labeled data** (analyst-confirmed false
  negatives within the period) — it is not an estimate of a wider, unknowable "total threat
  population." See the `note` field on every `residual_risk` response.
- **This is a simplified point estimate, not a full FAIR/Monte Carlo model.** No loss-magnitude
  distributions, no confidence intervals — a single deterministic number per bucket, by design,
  per the brief's explicit "deliberately simple" requirement.
