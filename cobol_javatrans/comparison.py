"""Verbatim upstream parse/is_equal rules at commit 2b14b7bf7e55556205654c6f7657fa60e36251fa."""
import math

class ParseError(Exception):
    pass


def parse(result, result_type, true):
    """Parse COBOL output value according to the expected Python type."""
    try:
        match result_type:
            case "Bool":
                return _parse_bool(result[0])
            case "Int":
                return _parse_int(result[0])
            case "Float":
                return _parse_float(result[0])
            case "String":
                return _parse_string(result[0])
            case {"List": "Int"}:
                return [_parse_int(x) for x in result][: len(true)]
            case {"List": "Float"}:
                return [_parse_float(x) for x in result][: len(true)]
            case {"List": "String"}:
                return [_parse_string(x) for x in result][: len(true)]
            case _:
                raise ParseError(f"Invalid result type: {result_type}")
    except Exception as e:
        raise ParseError(f"Result {result} of type {result_type} failed: {e}")


def _parse_bool(res: str) -> bool:
    return res.strip() == "1"


def _parse_int(res: str) -> int:
    res = res.strip()
    if res.startswith("p") or res.startswith("y"):
        return -int(res[1:])
    return int(res)


def _parse_float(res: str) -> float:
    res = res.strip()
    if res.startswith("p") or res.startswith("y"):
        return -float(res[1:])
    return float(res)


def _parse_string(res: str) -> str:
    return res.strip()


def is_equal(result_type, result, true):
    """Compare parsed result with expected value."""
    match result_type:
        case "Float":
            return math.isclose(result, true, abs_tol=0.001)
        case {"List": "Float"}:
            return all(math.isclose(r, t, abs_tol=0.001) for r, t in zip(result, true))
        case _:
            return result == true


