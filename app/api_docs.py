"""OpenAPI metadata only: the existing middleware remains the auth authority."""
from fastapi.openapi.utils import get_openapi

SCHEME = "ApiKeyAuth"
CLAIM_EXAMPLE = {"calculation_type": "arithmetic", "claimed_result": "3",
                 "inputs": {"a": "1", "b": "2"}, "tolerance": "0.01"}
RESULT_EXAMPLE = {"status": "passed", "calculation_type": "arithmetic", "claimed_result": "3",
                  "calculated_result": "3", "difference": "0", "tolerance": "0.01",
                  "explanation": "Deterministic verification: arithmetic"}


def configure_openapi(app):
    def openapi():
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, description=app.description,
                             routes=app.routes)
        components = schema.setdefault("components", {})
        components.setdefault("securitySchemes", {})[SCHEME] = {
            "type": "apiKey", "in": "header", "name": "X-API-Key",
            "description": "Exactly one API-key header is required when key authentication applies. "
                           "The middleware validates credentials, duplicates, quotas and rate limits. "
                           "Explicit guarded local-development bypass is a separate operator configuration.",
        }
        components.setdefault("schemas", {})["AgentVerifyError"] = {
            "type": "object", "required": ["detail"], "properties": {"detail": {}},
            "description": "Generic middleware or business-rule detail. Authentication/configuration errors do not echo credentials. "
                           "Validation detail may echo submitted input; do not put secrets in request bodies.",
        }
        error_content = {"application/json": {"schema": {"$ref": "#/components/schemas/AgentVerifyError"}}}
        for path, item in schema.get("paths", {}).items():
            for method, operation in item.items():
                if method not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                    continue
                public = method == "get" and path in {"/health", "/pricing"}
                operation["security"] = [] if public else [{SCHEME: []}]
                responses = operation.setdefault("responses", {})
                responses.setdefault("503", {"description": "Security configuration invalid or quota service unavailable; fail closed.",
                                              "content": error_content})
                if not public:
                    responses.setdefault("401", {"description": "Missing, invalid or repeated API-key header.",
                        "headers": {"WWW-Authenticate": {"schema": {"type": "string", "example": "ApiKey"}}},
                        "content": error_content})
                    responses.setdefault("429", {"description": "Process-local minute limit or durable daily request quota exhausted.",
                        "headers": {"Retry-After": {"schema": {"type": "string"},
                                    "description": "Fixed retry hint, not a precise next-admission guarantee."}},
                        "content": error_content})
                if "422" in responses:
                    responses["422"]["description"] = (
                        "Invalid request or business inputs. Normal details are preserved; unencodable validation details "
                        "are replaced with a generic error item. An earlier quota reservation is not refunded.")
                    responses["422"]["content"]["application/json"]["schema"] = {"anyOf": [
                        {"$ref": "#/components/schemas/HTTPValidationError"},
                        {"$ref": "#/components/schemas/AgentVerifyError"},
                    ]}
        for path in ("/verify", "/verify/signed"):
            operation = schema["paths"][path]["post"]
            operation["requestBody"]["content"]["application/json"]["example"] = CLAIM_EXAMPLE
            operation["responses"].setdefault("400", {"description": "Body could not be parsed.", "content": error_content})
        verify = schema["paths"]["/verify"]["post"]
        verify["description"] = ("Evaluate a supported calculation using supplied inputs. HTTP 200 means evaluation completed; "
                                 "inspect status for passed/failed. Tolerance is an absolute difference in output units. "
                                 "Decimal request/response strings avoid binary floating-point ambiguity. Input provenance is not verified.")
        verify["responses"]["200"]["content"]["application/json"]["example"] = RESULT_EXAMPLE
        batch = schema["paths"]["/verify/batch"]["post"]
        batch["requestBody"]["content"]["application/json"]["example"] = {"requests": [CLAIM_EXAMPLE]}
        batch["description"] = "Check up to 50 claims. An invalid claim rejects the batch; an earlier quota reservation is not refunded."
        schema["paths"]["/verify/signed"]["post"]["description"] = (
            "Return an Ed25519 receipt, including for a failed calculation. A valid signature does not mean the claim passed "
            "or that supplied inputs are true. Establish issuer trust separately; receipts are not encrypted.")
        schema["paths"]["/receipts/check"]["post"]["description"] = (
            "Check signature integrity against this instance's currently configured issuer. Repeated verification is allowed. "
            "No payload-schema, freshness, expiration, single-use or historical-issuer guarantee is made.")
        schema["paths"]["/health"]["get"]["description"] = "Liveness only; success does not prove authentication, signing or database readiness."
        schema["paths"]["/payments/preview"]["get"]["responses"].update({
            "402": {"description": "Opt-in development simulation only. No payment is requested or processed."},
            "404": {"description": "Development preview disabled."},
        })
        app.openapi_schema = schema
        return schema
    app.openapi = openapi
