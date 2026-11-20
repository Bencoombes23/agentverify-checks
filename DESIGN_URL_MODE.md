# DESIGN: optional URL mode for claim-vs-source checks (NOT IMPLEMENTED)

Status: design note only. AV-018 ships `quote_in_text`, `number_in_text` and `date_in_text` on text the
**caller supplies**. No code in this repository fetches a URL, and none should be added until the owner
approves this design. This document says how a fetcher could be added safely, and what it still would
not prove.

## Goal

Let a caller pass `source_url` instead of `source_text`, so an agent need not paste the page. The
service would fetch the page, extract text, then run the same deterministic checks and bind the result
in the same signed receipt.

## Hard requirements (all must hold, or the feature stays off)

1. **Off by default.** Enabled only by an explicit setting (for example `AGENTVERIFY_URL_MODE=1`) that
   the operator sets deliberately. Disabled means `source_url` is rejected with 422, the fetch module is
   not imported, and behaviour is identical to today.
2. **Scheme allowlist.** `https` only (optionally `http` behind a second flag for tests). Reject `file:`,
   `ftp:`, `gopher:`, `data:`, `javascript:` and anything else. Reject userinfo in the URL
   (`https://user:pass@host`) and non-default ports unless allow-listed.
3. **SSRF protection, applied after DNS resolution.** Resolve the hostname ourselves, then connect to the
   resolved IP (pinned, so a second lookup cannot return a different address: no DNS rebinding). Refuse
   if **any** resolved address is loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`,
   `192.168/16`, `fc00::/7`), link-local (`169.254/16` including cloud metadata `169.254.169.254`,
   `fe80::/10`), unspecified, multicast, reserved, carrier-grade NAT (`100.64/10`), or an IPv4-mapped /
   6to4 / NAT64 form of any of those. Reject IP-literal and numeric-encoded hosts (decimal, octal, hex)
   unless they pass the same check. Use the standard library `ipaddress` checks plus an explicit
   denylist, not string matching on the hostname. Optionally also support an operator allowlist of
   hostnames, which is the safest mode.
4. **Every redirect is re-checked.** Follow redirects manually (not by the HTTP library), at most 3, and
   run steps 2 and 3 on each hop's URL and resolved IP. A redirect to a disallowed scheme or address
   fails the request. Do not carry state across origins.
5. **Size and time limits.** Connect timeout ~5 s, total deadline ~10 s, read in chunks and abort once
   the body exceeds the same text limit used for supplied text (default 64 KiB after decoding; a hard
   raw limit such as 1 MiB before extraction). Cap decompression output (guard against zip bombs): do not
   enable transparent decompression beyond the limit, or refuse `Content-Encoding` other than identity /
   bounded gzip.
6. **Content-type allowlist.** `text/plain`, `text/html`, `application/xhtml+xml`, and possibly
   `application/json`. Everything else (PDF, images, archives, binaries) is refused. HTML is reduced to
   text by a small, deterministic, documented extractor (drop `script`/`style`, decode entities, collapse
   whitespace). The extractor version is recorded. No JavaScript is executed, ever.
7. **No credentials, no ambient state.** No cookies, no `Authorization` forwarding, no caller headers
   forwarded, no proxy credentials, no client certificates. A fixed, honest `User-Agent` naming the
   service. A fetch is anonymous GET only. A cookie jar is never created.
8. **robots / terms note.** Respect `robots.txt` for the service's user agent (fetch and cache it
   under the same SSRF rules), and document that the operator is responsible for the terms of use of
   sites they point it at. Do not bypass paywalls, logins or bot protection; if the response is a
   login wall, CAPTCHA or error page, the check runs on that text and will fail honestly.
9. **Rate limiting and abuse controls.** A per-key concurrency and request budget for fetches (they cost
   far more than a local check), a global cap on in-flight fetches, and no fetch on unauthenticated
   requests. Fetched content is never stored beyond the request; only hashes are kept.
10. **Logging.** Log scheme, host and outcome class only; never full URLs with query strings (they may
    carry tokens), never bodies, never headers.
11. **Auth and payment unchanged.** URL mode sits behind the same API-key (and optional x402) gate as
    every other route. It adds no new unauthenticated path.

## What the receipt would record

In addition to today's fields (claim, normalisation flags, SHA-256 of the normalised text):

- `source_url` as requested and `final_url` after redirects (query string redacted or hashed if it could
  hold secrets),
- `fetched_at` (UTC, from the server clock),
- HTTP status, `content_type`, raw byte length,
- `raw_sha256` (hash of the bytes received) **and** `source_sha256` (hash of the extracted, normalised
  text), plus the extractor name/version,
- the resolved IP class (not the address itself) and the redirect count.

The full page text is still not stored in the receipt. A third party can re-check the claim only if they
obtain the same text (see below).

## What URL mode would NOT prove

- **The page can change.** The receipt proves what the service received at `fetched_at`, not what the
  page says now or said when the agent read it. Anyone re-fetching later may get different text and a
  different hash. Without an archived copy, third-party reproduction is not guaranteed.
- **Not authoritative.** A match shows the fetched text contains the claim, not that the page is true,
  current, the original publisher, or the document the agent actually cited.
- **Personalised and blocked content.** Geo-fenced, paywalled, A/B-tested, cookie-gated or
  JavaScript-rendered pages may return different text to the service than to a human or the agent. A
  failed check may only mean the service saw something else.
- **Extraction loss.** HTML-to-text extraction can drop, reorder or merge text (tables, captions,
  hidden elements), so a quote visible in a browser might not be found, and hidden text might be found.
- **Server clock and TLS only.** `fetched_at` is the service's clock; TLS authenticates the host name,
  not the owner's intent.
- **Prompt-injection stays out of scope.** Fetched text is data. It is never interpreted as
  instructions; the checks are pure string/number/date matching.

## Suggested rollout (if approved)

1. Implement the fetcher as one small module with the SSRF layer first and tests that drive it with a
   fake resolver and fake transport (private, loopback, metadata, rebinding, redirect-to-private,
   oversize, wrong content type, slow-loris). No real network in tests.
2. Ship disabled; enable on one operator-chosen host allowlist.
3. Keep supplied-text mode as the recommended path for high-assurance use, because the caller can
   archive the exact text and anyone can re-verify the hash.
