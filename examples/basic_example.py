"""Basic PromptFuzz example — test a simple echo chatbot."""

from promptfuzz import Fuzzer


def chat(message: str) -> str:
    """Simulate a naive chatbot that echoes user messages."""
    return f"Hello! I'm a helpful assistant. You said: {message}"


if __name__ == "__main__":
    fuzzer = Fuzzer(
        target=chat,
        context="demo echo chatbot",
        categories=["jailbreak"],
    )
    result = fuzzer.run()
    result.report()
    result.save("report.html")
