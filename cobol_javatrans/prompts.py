"""Explicit field allowlists keep target answers and structured tests private."""
SYSTEM_MESSAGE = 'Translate the supplied program faithfully. Return exactly one fenced code block in the requested language.'


def user_prompt(record: dict, direction: str) -> str:
    if direction == 'cobol_to_java':
        return (
            'Translate this COBOL program into Java as a class named Solution. '
            'Implement the exact entry point method name, signature, and types shown in the target Java skeleton. '
            'Return the complete program in one fenced java block.\n\n'
            'Source COBOL program:\n```cobol\n' + record['COBOL_canonical_solution'] + '\n```\n\n'
            'Target Java skeleton (preserve its method signature):\n```java\n' + record['Java_prompt'] + '\n```'
        )
    if direction == 'java_to_cobol':
        return (
            'Translate this Java program into COBOL using the target skeleton below. '
            'Preserve the IDENTIFICATION DIVISION, PROGRAM-ID, and all LINKAGE SECTION items and layouts: '
            'the caller invokes this PROGRAM-ID USING LINKED-ITEMS. '
            'Complete WORKING-STORAGE SECTION (place it before LINKAGE SECTION) and PROCEDURE DIVISION USING LINKED-ITEMS. '
            'Store the return value in RESULT and end with END PROGRAM followed by the PROGRAM-ID. '
            'Return the complete program in one fenced cobol block, with COBOL source starting in column 8 or later.\n\n'
            'Source Java program:\n```java\n' + record['Java_canonical_solution'] + '\n```\n\n'
            'Target COBOL skeleton:\n```cobol\n' + record['COBOL_prompt'] + '\n```'
        )
    raise ValueError('Unknown translation direction')
