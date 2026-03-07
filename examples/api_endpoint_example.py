"""PromptFuzz example — test an HTTP API endpoint.

Uses httpbin.org as a harmless echo endpoint to demonstrate URL mode.
"""

from promptfuzz import Fuzzer

if __name__ == "__main__":
    # httpbin echoes back the JSON body — the 'response' key won't exist,
    # so the runner falls back to the raw response text.
    fuzzer = Fuzzer(
        target="https://httpbin.org/post",
        context="HTTP echo endpoint demo",
        categories=["edge_case"],
        max_workers=3,
        timeout=15.0,
        input_field="message",
        output_field="data",
    )
    result = fuzzer.run()
    result.report()
    result.save("api_report.html")
