from decimal import Decimal, InvalidOperation, localcontext
from fastapi import HTTPException
from app.models import VerificationRequest, VerificationResponse

REQUIRED = {
    "arithmetic": {"a", "b"},
    "subtract": {"a", "b"},
    "multiply": {"a", "b"},
    "divide": {"a", "b"},
    "percentage": {"part", "whole"},
    "rental_yield": {"monthly_rent", "purchase_price"},
    "profit_margin": {"revenue", "cost"},
    "roi": {"gain", "investment"},
    "compound_growth": {"principal", "annual_rate", "years"},
    "loan_payment": {"principal", "annual_rate", "years"},
}

def verify(request: VerificationRequest) -> VerificationResponse:
    kind = request.calculation_type
    x = request.inputs
    if set(x) != REQUIRED[kind]:
        raise HTTPException(422, detail={
            "message": "Incorrect input fields",
            "required": sorted(REQUIRED[kind]),
            "received": sorted(x),
        })
    try:
        with localcontext() as ctx:
            ctx.prec = 40
            hundred = Decimal(100)
            if kind == "arithmetic":
                result = x["a"] + x["b"]
            elif kind == "subtract":
                result = x["a"] - x["b"]
            elif kind == "multiply":
                result = x["a"] * x["b"]
            elif kind == "divide":
                if x["b"] == 0:
                    raise HTTPException(422, detail="Cannot divide by zero")
                result = x["a"] / x["b"]
            elif kind == "percentage":
                if x["whole"] == 0:
                    raise HTTPException(422, detail="Whole cannot be zero")
                result = x["part"] / x["whole"] * hundred
            elif kind == "rental_yield":
                if x["purchase_price"] <= 0 or x["monthly_rent"] < 0:
                    raise HTTPException(422, detail="Purchase price must be positive and rent nonnegative")
                result = x["monthly_rent"] * 12 / x["purchase_price"] * hundred
            elif kind == "profit_margin":
                if x["revenue"] <= 0 or x["cost"] < 0:
                    raise HTTPException(422, detail="Revenue must be positive and cost nonnegative")
                result = (x["revenue"] - x["cost"]) / x["revenue"] * hundred
            elif kind == "roi":
                if x["investment"] <= 0:
                    raise HTTPException(422, detail="Investment must be positive")
                result = x["gain"] / x["investment"] * hundred
            elif kind == "compound_growth":
                p, rate, years = x["principal"], x["annual_rate"], x["years"]
                if p < 0 or rate < -100 or years < 0 or years != years.to_integral_value() or years > 100:
                    raise HTTPException(422, detail="Invalid principal, annual rate or whole-number years (0-100)")
                result = p * (1 + rate / hundred) ** int(years)
            else:
                p, rate, years = x["principal"], x["annual_rate"], x["years"]
                if p <= 0 or rate < 0 or years <= 0 or years > 100 or years * 12 != (years * 12).to_integral_value():
                    raise HTTPException(422, detail="Invalid loan terms; term must be a whole number of months")
                months = int(years * 12)
                monthly_rate = rate / Decimal(1200)
                if monthly_rate == 0:
                    result = p / months
                else:
                    factor = (1 + monthly_rate) ** months
                    result = p * monthly_rate * factor / (factor - 1)
            difference = abs(result - request.claimed_result)
            if not result.is_finite() or not difference.is_finite():
                raise HTTPException(422, detail="Non-finite calculation result")
            return VerificationResponse(
                status="passed" if difference <= request.tolerance else "failed",
                calculation_type=kind,
                claimed_result=request.claimed_result,
                calculated_result=result,
                difference=difference,
                tolerance=request.tolerance,
                explanation=f"Deterministic verification: {kind}",
            )
    except (InvalidOperation, OverflowError, ZeroDivisionError):
        raise HTTPException(422, detail="Calculation could not be evaluated")
