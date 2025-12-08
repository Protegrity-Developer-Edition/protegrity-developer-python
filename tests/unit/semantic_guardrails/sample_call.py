# first raise SGR service
# SDK expects in localhost:8001

from protegrity_developer_python.utils.semantic_guardrails import (
    MessageRiskRequest,
    MessageBatchRiskRequest,
)
from protegrity_developer_python.utils.semantic_guardrails import scan_messages


sample_messages = [
    MessageRiskRequest(
        id="msg1",
        from_="user",
        to="ai",
        content="Hello, how are you?",
        processors=["customer-support"],
    ),
    MessageRiskRequest(
        id="msg2",
        from_="ai",
        to="user",
        content="I'm doing well, thank you!",
        processors=["pii"],
    ),
]


def main() -> None:
    out = scan_messages(MessageBatchRiskRequest(messages=sample_messages))
    print(out)


if __name__ == "__main__":
    main()
