# AgentVerify: deterministic claim checker with signed receipts

AgentVerify re-checks claims that an AI agent (or a person) makes, using fixed rules instead of another model's opinion. Send a list of claims, get one result row per claim: **passed** or **failed**, with the evidence. Optionally, each result comes with an **Ed25519-signed receipt** that anyone can verify offline.

It is built for agent pipelines that need a cheap, repeatable second check on numbers, quotes and dates before the result is used, reported or sent on.

## What it checks

| Check type | What it does | Example |
|---|---|---|
| `arithmetic`, `subtract`, `multiply`, `divide` | Recomputes with exact decimals, never floats | 19.99 × 3 = 59.97 |
| `percentage`, `profit_margin`, `roi` | Recomputes the percentage | 50 of 200 is 25% |
| `rental_yield`, `compound_growth`, `loan_payment` | Recomputes common finance figures | monthly payment on a loan |
| `quote_in_text` | Is this quote an exact substring of the text you supplied? | quote vs. a pasted article |
| `number_in_text` | Does this number appear as a standalone number in your text? | "$3.2m" matches 3,200,000 when scaling is allowed |
| `date_in_text` | Does this calendar date appear in your text, in any common written form? | 2026-11-20 vs "20 November 2026" |

## How to use it

1. Open the Actor and paste your checks into the **Checks** field as a JSON array.
2. Run it.
3. Read the results in the **Dataset** (one row per check, in input order), or call the Actor from the API or an MCP client.

```json
{
  "checks": [
    {"calculation_type": "percentage", "claimed_result": "25", "inputs": {"part": "50", "whole": "200"}},
    {"calculation_type": "number_in_text", "claimed_result": "3200000", "unit": "$", "allow_scaling": true,
     "source_text": "Seed funding was $3.2m in 2025."}
  ]
}
```

Each result row contains `status` (`passed` or `failed`), the claimed and calculated values, an explanation and, for text checks, evidence (a SHA-256 of the normalised text and the match position). A request that is malformed gets a row with `status: "error"` and a reason, and is not charged.

## Signed receipts (optional)

Switch on **Sign receipts** and provide your own signing key (base64url of 32 random bytes). Each result then carries a receipt with the claim, the result, a timestamp and an Ed25519 signature. The receipt binds the claim and a hash of your source text, not the text itself.

To verify a receipt offline, use the `verify_receipt` function in the open-source `agentverify_client` package (MIT licence, see the repository), with the public key you trust. The public key is printed in the run log.

Keep your key private: anyone who holds it can produce receipts that verify as yours. Apify stores secret inputs encrypted.

## What a pass does and does not prove

- A pass on arithmetic means the number is right for the inputs you gave. It does not prove the inputs are right.
- A pass on a text check means **the text you supplied contains the claim** after simple normalisation (quotes, dashes, spaces). It does not prove the claim is true, that the text is the real or current source, or that it was not edited first.
- There is no meaning-based matching: a paraphrase fails. The Actor never fetches web pages.
- A signature proves the receipt is unmodified and came from the holder of the key. It does not prove the claim is true.
- Numbers must be between roughly 1E-18 and 1E+18 and at most 30 digits. Very large or very small correct results can be rejected as errors.
- Early software, MIT licensed, no security audit and no uptime guarantee.

## Pricing

You pay per event, so you pay for what you check:

- **Verification**: charged for each check that returns a passed or failed result.
- **Signed receipt**: charged in addition, for each receipt issued.
- Error rows (malformed requests) are not charged.

Current prices are shown in the Pricing tab. Set a maximum spend per run and the Actor stops when it is reached. Apify's own start fee also applies.

## FAQ

**Can it check a web page for me?** No. It only checks text you send, and it makes no network requests. Fetch the page yourself and pass the text.

**How many checks per run?** Up to 1,000.

**Is it open source?** Yes, MIT: https://github.com/Bencoombes23/agentverify-checks

**Where do I report a problem?** Use the Issues tab on this Actor.
