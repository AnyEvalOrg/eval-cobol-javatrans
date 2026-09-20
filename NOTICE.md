COBOL-JavaTrans data and parsing/cleaning adaptations derive from COBOL-Coder,
https://github.com/COBOL-Coder/COBOL-Coder, commit
2b14b7bf7e55556205654c6f7657fa60e36251fa, Apache License 2.0.
The upstream license is retained verbatim in UPSTREAM-LICENSE and LICENSE.

The AnyEval packaging, publication filtering, Helm chart and authenticated
supervisor structure are adapted from the local eval-livecodebench template.
Changes include bidirectional translation prompts, shell-free compiler/runtime
steps, GnuCOBOL output-file transport, a bounded process limit supporting compilers
and JVM threads, and reserved-UID descendant reaping between steps.
