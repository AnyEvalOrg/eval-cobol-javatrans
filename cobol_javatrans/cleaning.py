"""Upstream response cleaners, applied after fenced-block extraction."""
def clean_response_for_eval(code: str) -> str:
    """Clean up model-generated COBOL code for evaluation."""
    # Remove duplicate WORKING-STORAGE SECTION
    tmp = "WORKING-STORAGE SECTION.\n       WORKING-STORAGE SECTION."
    code = code.replace(tmp, "WORKING-STORAGE SECTION.")

    try:
        # Ensure proper COBOL indentation (column 8+)
        if code[0] != " ":
            code = "       " + code

        working_index = code.index("WORKING-STORAGE SECTION.")
        try:
            procedure_index = code.index("PROCEDURE DIVISION USING")
        except ValueError:
            procedure_index = code.index("PROCEDURE DIVISION.")
        linkage_index = code.index("LINKAGE SECTION.")

        if working_index > linkage_index:
            working_division = code[working_index:procedure_index]
            prefix = code[:linkage_index]
            procedure = code[procedure_index:]
            linkage_section = code[linkage_index:working_index]
            code = prefix + working_division + linkage_section + procedure
    except Exception:
        pass

    return code


def clean_java_response(code: str) -> str:
    """Clean up model-generated Java code for evaluation."""
    # Truncate at duplicate import block (model repeating itself)
    idx = code[100:].find("import java")
    if idx != -1:
        return code[: idx + 100]
    return code


