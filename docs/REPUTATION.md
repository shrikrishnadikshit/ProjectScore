# Reputation module (online reputation management)

Watches what customers and the press say about a brand: app store reviews, social posts, forum threads
and news. Each item is scored for sentiment, the brand gets a 0 to 100 reputation score with a daily
trend, a spike in negative mentions raises a crisis alert, and the team can triage mentions and draft
replies. It also tracks which pages rank when people search for the brand.

This is the marketing side of reputation. Security brand protection (look-alike domains, fake sites,
breach news) lives in the security ratings product.

## Switching it on

The module is **off** unless `REPUTATION_MODULE=on` is set on the server. While it is off, every
`/api/reputation/*` route returns 404 and the Reputation menu item is hidden, so it cannot affect the
security ratings launch. Its tables (`rep_brands`, `rep_mentions`, `rep_search_snapshots`) are created
either way but stay empty.

## Settings

| Variable | Default | What it does |
|---|---|---|
| `REPUTATION_MODULE` | `off` | Turns the module on. |
| `REPUTATION_POLL_MINUTES` | `360` | How often each brand is checked automatically. |
| `REPUTATION_MAX_BRANDS` | `5` | Brands per organisation. |
| `REPUTATION_CRISIS_MIN` | `5` | Minimum negative mentions in 24 hours for a crisis alert. |
| `REPUTATION_CRISIS_FACTOR` | `3` | ...and at least this many times the usual daily number (last 7 days). |
| `REPUTATION_RETENTION_DAYS` | `365` | Mentions and search snapshots older than this are deleted. |
| `REPUTATION_NEWS`, `REPUTATION_HACKERNEWS`, `REPUTATION_BLUESKY`, `REPUTATION_APPLE` | `on` | Set to `off` to stop using that free source. |
| `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET` | unset | Turns on Reddit. See the terms note below. |
| `GOOGLE_PLACES_API_KEY` | unset | Turns on live Google reviews (paid). |
| `BRAVE_SEARCH_API_KEY` | unset | Turns on search result tracking (paid). |
| `ANTHROPIC_API_KEY` | unset | Turns on AI-drafted replies (paid per use). Without it, replies come from templates. |
| `REPUTATION_AI_REPLIES` | `on` | Set to `off` to keep templates even when the key is set. |

## Data sources and their terms

| Source | Cost | Commercial use | Notes |
|---|---|---|---|
| **GDELT news** (api.gdeltproject.org) | Free | Allowed; GDELT data is open for any use with attribution | One request every 5 seconds; the collector waits between brands. Titles only, no article text. |
| **Hacker News** (hn.algolia.com) | Free | Public API, no stated restriction | |
| **Bluesky** (public.api.bsky.app) | Free | Allowed under Bluesky's developer guidelines | Bluesky has at times restricted unauthenticated search. If it fails, the dashboard says so and other sources still work. |
| **Apple App Store reviews** (public RSS feed) | Free | Public feed; Apple's terms don't address it directly | Up to 500 most recent reviews per country. **Check with a lawyer before selling this.** |
| **Reddit** | Free tier | **Needs Reddit's written approval for commercial use** (Reddit Data API terms) | Off until keys are added. |
| **Google reviews** (Places API) | Paid, with a free monthly credit | Allowed, but Google's terms **forbid storing** review content | Fetched live and never saved, shows at most 5 reviews, and must display "Reviews from Google". |
| **Brave Search API** | Paid plans | Check that the plan you buy allows **storing results** | We store rank, title, link and a short snippet per weekly snapshot. |
| **Claude (Anthropic API)** | Paid per use | Allowed | Only the review text, rating, brand name and reply contact are sent. |
| **CSV import / added by hand** | Free | Customer's own data | For Google Business Profile exports, Trustpilot, Glassdoor, support desks and anything else. |

### Not included, and why

- **X (Twitter):** read access needs a paid API plan (from about USD 200 a month).
- **Facebook, Instagram, LinkedIn:** their APIs only cover pages the customer owns, after an app review by Meta or LinkedIn.
- **Google Play reviews:** Google has no public review feed. The Play Developer API covers only the customer's own apps (needs their service account). Scraping breaks Google's terms.
- **Trustpilot, Yelp, Glassdoor:** business APIs are paid and tied to the reviewed business's own account. Customers can import an export instead.
- **Posting replies for the customer:** needs each platform's owner APIs (Google Business Profile, App Store Connect). Replies are drafted here and posted by the person.

## Privacy

Mentions contain public posts and reviewer display names, which is personal data under GDPR and India's
DPDP Act. We keep only what is needed (author name, text, link, date), delete it after
`REPUTATION_RETENTION_DAYS`, and delete everything for a brand when it is removed. The privacy policy
draft should mention this module before it is switched on for customers.

## How the score works

- Each mention gets a sentiment from -1 to +1 using VADER (runs on our server) plus a short list of
  business words such as "scam", "refund" and "outage". When there's a star rating, it counts for 70%.
- Text that isn't English is scored neutral unless it has a star rating.
- Reputation score = 60% from the average sentiment of mentions in the period (mapped to 0 to 100) and
  40% from the average star rating, when there are ratings. It needs at least 5 mentions.
- Anyone in the organisation can correct a label; the correction feeds the score.
