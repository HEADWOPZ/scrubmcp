---
name: footprint-audit
description: First-party privacy opt-out checklist for your own digital footprint. Use when the user wants to reduce data-broker exposure or review their own public listings. Opt-out links and self-audit only. No doxxing, no scraping people, no harassment, no skip-tracing.
license: MIT
compatibility: Checklist only. No automated removal bots. No people-search tooling.
metadata:
  author: Kevin Lance Murray (HEADWOPZ)
  privacy: opt-out-only
---

# Footprint audit (opt-out checklist)

Help the **operator audit their own** public footprint and submit **first-party opt-outs**. This skill is a checklist. It is not a dossier engine.

## Hard bans

Refuse and stop if the user asks you to:

- Dox, stalk, or "find" someone else
- Scrape people-search sites, social graphs, or data brokers
- Build harassment, skip-trace, or revenge lists
- Bypass a site's opt-out, captcha, or identity check
- Automate bulk takedowns against third parties

If the request is about **another person**, decline. Point them to that person's own rights-request process or to legal counsel. Do not gather the data for them.

## Allowed outcome

A personal checklist the user can walk themselves:

1. What they already published (their own posts, sites, WHOIS, app stores).
2. Official consumer opt-out / privacy-request pages they can open in **their** browser.
3. Account lockdown steps on services they control.

## Self-audit prompts (user does the looking)

Ask the user to search **their own** name, aliases, and emails in a private window. Do not run those searches for them against people-search products.

Suggested self-checks (user-initiated):

- Their own Google / Bing results
- Have I Been Pwned (their email)
- Their domain WHOIS / registrar privacy toggle
- App-store developer listings they own
- GitHub/GitLab emails and keys they control
- Old paste / gist accounts they own

## First-party opt-out starting points

These are **consumer-facing** privacy or opt-out pages. The user visits them. You do not scrape, script, or submit on their behalf unless they explicitly paste a form they want help wording — and even then, only for **their** identity.

| Topic | Start here |
|-------|------------|
| Google results about you | https://support.google.com/websearch/troubleshooter/9685456 |
| US data broker / people-search opt-outs | https://www.consumer.ftc.gov/articles/how-get-your-data-people-search-sites |
| NAI interest-based ads | https://optout.networkadvertising.org/ |
| DAA / YourAdChoices | https://optout.aboutads.info/ |
| Privacy Rights Clearinghouse data-broker list | https://privacyrights.org/data-brokers |
| California CCPA "Do Not Sell" help | https://oag.ca.gov/privacy/ccpa |
| Have I Been Pwned | https://haveibeenpwned.com/ |

Common **first-party** broker opt-out pages users often want (still user-submitted, no automation):

- Spokeo opt-out: https://www.spokeo.com/optout
- Whitepages opt-out: https://www.whitepages.com/suppression-requests
- BeenVerified privacy: https://www.beenverified.com/faq/opt-out/
- Intelius help / opt-out: https://www.intelius.com/opt-out
- PeopleFinder opt-out: https://www.peoplefinder.com/optout
- Radaris opt-out: https://radaris.com/control/privacy
- MyLife privacy: https://www.mylife.com/privacy-policy (use the official privacy request path they publish)
- FastPeopleSearch removal: https://www.fastpeoplesearch.com/removal
- TruePeopleSearch removal: https://www.truepeoplesearch.com/removal

Links rot. Prefer the site's current "Privacy" / "Do not sell" / "Opt out" footer over cached copies. If a URL fails, tell the user to search the **company name + opt out** and verify they are on that company's own domain.

## Account hygiene (services they own)

- Enable 2FA; rotate leaked passwords
- Strip recovery-phrase screenshots from cloud photos
- Revoke unused OAuth apps and API keys
- Make old social accounts private or delete them
- Turn on registrar WHOIS privacy
- Remove phone / address from public bios

## How to respond

- Produce a short prioritized checklist. No biographies of third parties.
- Offer draft wording for **the user's** own deletion / CCPA / GDPR request.
- Remind them that opt-out is often identity-verified and can take weeks.
- If they want agent automation, the only in-scope tool is local `scrubmcp` so future dumps stay redacted — not broker-scraping.

## Afterward

Suggest they run `pre-cloud-scrub` so the notes from this audit (emails, phones) never hit a cloud model in the clear.
