from decimal import Decimal
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app import textcheck

CalculationType = Literal[
    "arithmetic", "subtract", "multiply", "divide", "percentage",
    "rental_yield", "profit_margin", "roi", "compound_growth", "loan_payment",
    # AV-018: claim-vs-source checks on caller-supplied text (no fetching).
    "quote_in_text", "number_in_text", "date_in_text",
]
TEXT_KINDS = frozenset({"quote_in_text", "number_in_text", "date_in_text"})
# Fields each text kind may use besides calculation_type/source_text.
_TEXT_ALLOWED = {
    "quote_in_text": {"claim_text", "case_insensitive"},
    "number_in_text": {"claimed_result", "tolerance", "allow_scaling", "unit"},
    "date_in_text": {"claim_text", "date_format"},
}
_TEXT_FIELDS = ("claim_text", "source_text", "case_insensitive", "allow_scaling", "unit", "date_format")


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    calculation_type: CalculationType
    claimed_result: Decimal | None = None
    inputs: dict[str, Decimal] = Field(default_factory=dict, max_length=6)
    tolerance: Decimal = Field(default=Decimal("0.01"), ge=0, le=1000)
    # AV-018 text-check fields. All optional; rejected for the arithmetic categories.
    claim_text: str | None = Field(default=None, min_length=1, max_length=textcheck.MAX_CLAIM_CHARS)
    source_text: str | None = Field(default=None, min_length=1, max_length=textcheck.MAX_SOURCE_CHARS)
    case_insensitive: bool | None = None
    allow_scaling: bool | None = None
    unit: str | None = Field(default=None, min_length=1, max_length=textcheck.MAX_UNIT_CHARS)
    date_format: Literal["DMY", "MDY", "YMD"] | None = None

    @model_validator(mode="after")
    def check_values(self):
        kind = self.calculation_type
        if kind in TEXT_KINDS:
            self._check_text_kind(kind)
        else:
            if self.claimed_result is None:
                raise ValueError("claimed_result is required")
            if not self.inputs:
                raise ValueError("inputs must contain at least 1 item")
            if any(getattr(self, name) is not None for name in _TEXT_FIELDS):
                raise ValueError("Text-check fields are not allowed for this calculation_type")
        for value in [self.claimed_result, self.tolerance, *self.inputs.values()]:
            if value is None:
                continue
            if not value.is_finite() or len(value.as_tuple().digits) > 30 or abs(value.adjusted()) > 18:
                raise ValueError("Numbers must be finite, at most 30 digits and within supported magnitude")
        return self

    def _check_text_kind(self, kind):
        if self.inputs:
            raise ValueError("inputs must be empty for text-check categories")
        if self.source_text is None:
            raise ValueError("source_text is required")
        allowed = _TEXT_ALLOWED[kind]
        for name in ("claim_text", "claimed_result", "case_insensitive", "allow_scaling", "unit", "date_format"):
            if getattr(self, name) is not None and name not in allowed:
                raise ValueError(f"{name} is not allowed for {kind}")
        if "tolerance" in self.model_fields_set and "tolerance" not in allowed:
            raise ValueError(f"tolerance is not allowed for {kind}")
        required = "claimed_result" if kind == "number_in_text" else "claim_text"
        if getattr(self, required) is None:
            raise ValueError(f"{required} is required for {kind}")
        for text in (self.source_text, self.claim_text, self.unit):
            if text is not None and not textcheck.encodable(text):
                raise ValueError("Text must be valid Unicode (no lone surrogates)")
        if self.unit is not None and not textcheck.valid_unit(self.unit):
            raise ValueError("unit must be a currency symbol, %, or up to 8 letters")


class VerificationResponse(BaseModel):
    status: Literal["passed", "failed"]
    calculation_type: str
    # Optional so text checks (quote/date) need not invent numeric values; always set for arithmetic.
    claimed_result: Decimal | None = None
    calculated_result: Decimal | None = None
    difference: Decimal | None = None
    tolerance: Decimal | None = None
    explanation: str
    evidence: dict[str, Any] | None = None  # text checks only: hashes, offsets, flags

class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requests: list[VerificationRequest] = Field(min_length=1, max_length=50)

class BatchResponse(BaseModel):
    total: int
    passed: int
    failed: int
    results: list[VerificationResponse]
