from decimal import Decimal
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CalculationType = Literal[
    "arithmetic", "subtract", "multiply", "divide", "percentage",
    "rental_yield", "profit_margin", "roi", "compound_growth", "loan_payment"
]

class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    calculation_type: CalculationType
    claimed_result: Decimal
    inputs: dict[str, Decimal] = Field(min_length=1, max_length=6)
    tolerance: Decimal = Field(default=Decimal("0.01"), ge=0, le=1000)

    @model_validator(mode="after")
    def check_values(self):
        for value in [self.claimed_result, self.tolerance, *self.inputs.values()]:
            if not value.is_finite() or len(value.as_tuple().digits) > 30 or abs(value.adjusted()) > 18:
                raise ValueError("Numbers must be finite, at most 30 digits and within supported magnitude")
        return self

class VerificationResponse(BaseModel):
    status: Literal["passed", "failed"]
    calculation_type: str
    claimed_result: Decimal
    calculated_result: Decimal
    difference: Decimal
    tolerance: Decimal
    explanation: str

class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requests: list[VerificationRequest] = Field(min_length=1, max_length=50)

class BatchResponse(BaseModel):
    total: int
    passed: int
    failed: int
    results: list[VerificationResponse]
