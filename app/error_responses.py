"""Preserve ordinary validation errors; safely represent unencodable errors."""
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse


async def safe_validation_error(request, exception):
    try:
        return await request_validation_exception_handler(request, exception)
    except (RecursionError, ValueError, OverflowError):
        # The request is already invalid. Do not echo its unencodable input or
        # turn a validation failure into a server error/traceback. No size policy.
        return JSONResponse(status_code=422, content={"detail": [{
            "type": "invalid_request", "loc": ["body"],
            "msg": "Invalid request; detailed errors could not be safely serialized",
        }]})


def configure_error_responses(app):
    app.add_exception_handler(RequestValidationError, safe_validation_error)
