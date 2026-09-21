"""Dependency-free authenticated receipt protocol shared by scorer and Linux checks."""
import base64
import hashlib
import hmac
import json
import re


def verify_receipt(stdout: str, key: bytes) -> dict | None:
    """Reject unauthenticated/invalid control fields; retain authenticated bad output."""
    try:
        envelope = json.loads(stdout)
        body, tag = envelope["body"], envelope["tag"]
        if not isinstance(body, str) or not isinstance(tag, str):
            return None
        if not hmac.compare_digest(hmac.new(key, body.encode(), hashlib.sha256).hexdigest(), tag):
            return None
        receipt = json.loads(body)
        if (not isinstance(receipt, dict)
                or type(receipt["returncode"]) is not int
                or type(receipt["timeout"]) is not bool
                or type(receipt["overflow"]) is not bool
                or receipt.get("stage") not in ("compile", "run")
                or not re.fullmatch(r"/tmp/cjt-[a-zA-Z0-9_-]+", receipt["cwd"])
                or any(type(receipt.get(flag, False)) is not bool
                       for flag in ("cleanup_failed", "supervisor_error"))):
            return None
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None

    # Only candidate-controlled fields are interpreted here. Their malformed
    # shape/encoding cannot erase authentication or turn failure into a retry.
    receipt["output_not_decodable"] = False
    try:
        if not isinstance(receipt["output"], str):
            raise ValueError("Invalid output shape")
        receipt["output"] = base64.b64decode(receipt["output"], validate=True).decode("utf-8")
    except (ValueError, TypeError, KeyError, UnicodeError):
        receipt["output"] = ""
        receipt["output_not_decodable"] = True
    return receipt


def receipt_failure(receipt: dict) -> str | None:
    """Authenticated execution failures are INCORRECT in both task directions."""
    if receipt["output_not_decodable"]:
        return "output not decodable."
    if receipt.get("cleanup_failed"):
        return "candidate cleanup failed."
    if receipt.get("supervisor_error"):
        return "candidate execution failed."
    if receipt["timeout"]:
        return f"{receipt['stage']} timeout."
    if receipt["overflow"]:
        return "output limit exceeded."
    if receipt["returncode"] != 0:
        return f"{receipt['stage']} error (exit {receipt['returncode']})."
    if receipt["stage"] != "run":
        return "run did not complete."
    return None
