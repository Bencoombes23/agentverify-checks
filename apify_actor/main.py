"""Apify Actor entry point: batch deterministic checks with optional signed receipts."""
from __future__ import annotations

import os

from apify import Actor

from apify_actor.engine import MAX_CHECKS_PER_RUN, process_check


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}
        checks = actor_input.get("checks")
        sign = bool(actor_input.get("signReceipts", False))
        signing_key = actor_input.get("signingKey")

        if not isinstance(checks, list) or not checks:
            await Actor.fail(status_message="Input 'checks' must be a non-empty array.")
            return
        if len(checks) > MAX_CHECKS_PER_RUN:
            await Actor.fail(status_message=f"At most {MAX_CHECKS_PER_RUN} checks per run.")
            return
        if sign:
            if not signing_key:
                await Actor.fail(status_message="signReceipts needs a signingKey (base64url of 32 random bytes).")
                return
            # Read by app.receipts at signing time. Never logged or written to the dataset.
            os.environ["AGENTVERIFY_SIGNING_KEY_B64"] = str(signing_key)
            try:
                from app.receipts import public_key_info
                Actor.log.info("Signing with public key %s", public_key_info()["public_key"])
            except RuntimeError:
                await Actor.fail(status_message="signingKey is not valid base64url of exactly 32 bytes.")
                return

        stopped_early = False
        for index, raw in enumerate(checks):
            item, events = process_check(index, raw, sign)
            first, *extra = events or [None]
            # push_data charges the first event only for items the user receives.
            charge = await Actor.push_data(item, charged_event_name=first) if first else await Actor.push_data(item)
            for event in extra:
                charge = await Actor.charge(event_name=event) or charge
            if charge is not None and getattr(charge, "event_charge_limit_reached", False):
                stopped_early = index < len(checks) - 1
                break

        if stopped_early:
            await Actor.set_status_message(
                f"Stopped at your spending limit after {index + 1} of {len(checks)} checks.")
        else:
            await Actor.set_status_message(f"Done: {len(checks)} checks processed.")
