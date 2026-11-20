"""Deterministic claim-vs-source checks on CALLER-SUPPLIED text (AV-018). No network, no floats.

Verdicts are substring/token evidence only: "the supplied text contains this quote / number /
date". They say nothing about whether the text is true, authentic or the real cited source.
"""
import hashlib
import re
import unicodedata
from datetime import date
from decimal import Decimal, localcontext

NORM_VERSION = "av-text-norm-1"
MAX_SOURCE_CHARS = 65536
MAX_CLAIM_CHARS = 2000
MIN_QUOTE_CHARS = 3
MAX_UNIT_CHARS = 8

_QUOTES = {ord(c): "'" for c in "‘’‚‛′ʼ"}
_QUOTES.update({ord(c): '"' for c in "“”„‟″"})
_DASHES = {ord(c): "-" for c in "‐‑‒–—―−﹘﹣－"}
_INVISIBLE = {ord(c): None for c in "­​⁠﻿"}
_TRANSLATE = {**_QUOTES, **_DASHES, **_INVISIBLE, 0x2026: "..."}


def normalise(text: str, case_fold: bool = False) -> str:
    """NFC -> map typographic quotes/dashes/ellipsis, drop invisible chars -> collapse all
    Unicode whitespace to one space and strip -> optional casefold (then NFC again)."""
    text = unicodedata.normalize("NFC", text).translate(_TRANSLATE)
    text = " ".join(text.split())
    if case_fold:
        text = unicodedata.normalize("NFC", text.casefold())
    return text


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
        return True
    except UnicodeEncodeError:  # lone surrogate from JSON escapes
        return False


class TextCheckError(ValueError):
    """Invalid input discovered after normalisation (mapped to HTTP 422 by the verifier)."""


def _source_block(source_norm: str, case_fold: bool) -> dict:
    return {
        "normalisation": {"version": NORM_VERSION, "unicode": "NFC", "case_fold": case_fold},
        "source_sha256": sha256_hex(source_norm),
        "source_normalised_chars": len(source_norm),
    }


# ---------------------------------------------------------------- quote_in_text
def check_quote(claim: str, source: str, case_fold: bool):
    claim_n = normalise(claim, case_fold)
    source_n = normalise(source, case_fold)
    if len(claim_n) < MIN_QUOTE_CHARS:
        raise TextCheckError(f"Quote must be at least {MIN_QUOTE_CHARS} characters after normalisation")
    if not source_n:
        raise TextCheckError("Source text is empty after normalisation")
    offset = source_n.find(claim_n)
    evidence = {**_source_block(source_n, case_fold), "claim_normalised_chars": len(claim_n),
                "found": offset >= 0, "match_offset": offset,
                "match_count": source_n.count(claim_n) if offset >= 0 else 0}
    if offset < 0:
        # Bounded hint only (verdict is unaffected): longest claim prefix present in the source.
        lo, hi = 0, len(claim_n)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if source_n.find(claim_n[:mid]) >= 0:
                lo = mid
            else:
                hi = mid - 1
        evidence["closest_hint"] = {"longest_claim_prefix_chars": lo,
                                    "offset": source_n.find(claim_n[:lo]) if lo else -1}
    return offset >= 0, evidence


# ---------------------------------------------------------------- number_in_text
_NUM = re.compile(r"(?<![\w.,])(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(?!\d)")
_TIGHT = re.compile(r"(k|m|bn|mn|b)(?![A-Za-z0-9])", re.I)
_SPACED = re.compile(r"\s(thousand|million|billion|bn|mn)(?![A-Za-z0-9])", re.I)
_SCALE = {"k": 3, "thousand": 3, "m": 6, "mn": 6, "million": 6, "b": 9, "bn": 9, "billion": 9}
_SYMBOLS = "$£€¥"
_SIGN_OK_BEFORE = " ([{:=;,/\"'"


def valid_unit(unit: str) -> bool:
    return 0 < len(unit) <= MAX_UNIT_CHARS and (unit in list(_SYMBOLS) + ["%"] or unit.isalpha())


def _unit_ok(s: str, start: int, end: int, unit: str) -> bool:
    if unit in _SYMBOLS:
        return s[max(0, start - 2):start].rstrip(" ").endswith(unit) or s[end:end + 2].lstrip(" ").startswith(unit)
    if unit == "%":
        return s[end:end + 2].lstrip(" ").startswith("%")
    unit = unit.casefold()
    n = len(unit)
    after = s[end:]
    after = after[1:] if after.startswith(" ") else after
    if after[:n].casefold() == unit and not after[n:n + 1].isalnum():
        return True
    before = s[:start]
    before = before[:-1] if before.endswith(" ") else before
    return (len(before) >= n and before[-n:].casefold() == unit
            and not before[-n - 1:-n].isalnum())


def scan_numbers(source_n: str, allow_scaling: bool, unit):
    """Yield (offset, Decimal) for each standalone number in the (normalised) source."""
    for m in _NUM.finditer(source_n):
        start, end = m.start(), m.end()
        nxt = source_n[end:end + 2]
        if nxt[:1] in (".", ",") and nxt[1:2].isdigit():
            continue  # part of a malformed/longer number such as 1.2.3 or 1,23
        digits = m.group(1).replace(",", "") + (m.group(2) or "")
        if len(digits.replace(".", "")) > 30:
            continue
        value = Decimal(digits)
        scale_end = end
        scale = _TIGHT.match(source_n, end) or _SPACED.match(source_n, end)
        if scale:
            if not allow_scaling:
                continue  # "3.2m" is not the standalone number 3.2
            value = Decimal(format(value.scaleb(_SCALE[scale.group(1).lower()]), "f"))  # no E-notation
            scale_end = scale.end()
        p = start
        if p and source_n[p - 1] in _SYMBOLS:
            p -= 1
        if p and source_n[p - 1] in "-+" and (p == 1 or source_n[p - 2] in _SIGN_OK_BEFORE):
            if source_n[p - 1] == "-":
                value = -value
        if unit is not None and not _unit_ok(source_n, start, scale_end, unit):
            continue
        yield start, value


def check_number(claimed: Decimal, tolerance: Decimal, source: str, allow_scaling: bool, unit):
    source_n = normalise(source)
    if not source_n:
        raise TextCheckError("Source text is empty after normalisation")
    unit_n = None if unit is None else (unit if unit in _SYMBOLS + "%" else unit.casefold())
    with localcontext() as ctx:
        ctx.prec = 60
        found = list(scan_numbers(source_n, allow_scaling, unit_n))
        best = None
        for offset, value in found:
            diff = abs(value - claimed)
            if best is None or diff < best[2]:
                best = (offset, value, diff)
        passed = best is not None and best[2] <= tolerance
    evidence = {**_source_block(source_n, False), "allow_scaling": allow_scaling, "unit": unit_n,
                "numbers_scanned": len(found), "found": passed,
                "match_offset": best[0] if passed else -1,
                "match_count": sum(1 for _, v in found if abs(v - claimed) <= tolerance) if found else 0}
    return passed, (best[1] if best else None), (best[2] if best else None), evidence


# ---------------------------------------------------------------- date_in_text
_MONTHS = {"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
           "august": 8, "september": 9, "sept": 9, "october": 10, "november": 11, "december": 12,
           "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9,
           "oct": 10, "nov": 11, "dec": 12}
_MON = "(" + "|".join(sorted(_MONTHS, key=lambda k: (-len(k), k))) + ")"
_ISO = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?!\d)")
_DMY_TEXT = re.compile(r"(?<!\d)(\d{1,2})(?:st|nd|rd|th)?\s+" + _MON + r"(?![a-z])\.?,?\s+(\d{4})(?!\d)", re.I)
_MDY_TEXT = re.compile(r"(?<![a-z])" + _MON + r"(?![a-z])\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?!\d)", re.I)
_NUM_DMY = re.compile(r"(?<![\d/.-])(\d{1,2})([/.-])(\d{1,2})\2(\d{4})(?!\d)")
_NUM_YMD = re.compile(r"(?<![\d/.-])(\d{4})([/.-])(\d{1,2})\2(\d{1,2})(?!\d)")
_ISO_CLAIM = re.compile(r"\d{4}-\d{2}-\d{2}")


def parse_iso_claim(text: str) -> date:
    if not _ISO_CLAIM.fullmatch(text):
        raise TextCheckError("Date claim must be an ISO date YYYY-MM-DD")
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise TextCheckError("Date claim is not a valid calendar date")


def _safe_date(y, m, d):
    try:
        return date(int(y), int(m), int(d))
    except ValueError:
        return None


def scan_dates(source_n: str, date_format):
    """Yield (offset, date, format_name) for every recognised, valid date."""
    for m in _ISO.finditer(source_n):
        yield m.start(), _safe_date(*m.groups()), "ISO"
    for m in _DMY_TEXT.finditer(source_n):
        yield m.start(), _safe_date(m.group(3), _MONTHS[m.group(2).lower()], m.group(1)), "D Month YYYY"
    for m in _MDY_TEXT.finditer(source_n):
        yield m.start(), _safe_date(m.group(3), _MONTHS[m.group(1).lower()], m.group(2)), "Month D, YYYY"
    if date_format in ("DMY", "MDY"):
        for m in _NUM_DMY.finditer(source_n):
            a, b, y = m.group(1), m.group(3), m.group(4)
            d, mo = (a, b) if date_format == "DMY" else (b, a)
            yield m.start(), _safe_date(y, mo, d), date_format
    elif date_format == "YMD":
        for m in _NUM_YMD.finditer(source_n):
            yield m.start(), _safe_date(m.group(1), m.group(3), m.group(4)), "YMD"


def check_date(claim: str, source: str, date_format):
    target = parse_iso_claim(claim)
    source_n = normalise(source)
    if not source_n:
        raise TextCheckError("Source text is empty after normalisation")
    hits = sorted((off, fmt) for off, d, fmt in scan_dates(source_n, date_format) if d == target)
    evidence = {**_source_block(source_n, False), "date_format": date_format, "found": bool(hits),
                "match_offset": hits[0][0] if hits else -1, "match_count": len(hits),
                "matched_formats": sorted({fmt for _, fmt in hits})}
    return bool(hits), evidence
