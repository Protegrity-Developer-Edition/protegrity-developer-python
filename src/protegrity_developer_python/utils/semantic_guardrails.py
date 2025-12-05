"""Synchronous client for Semantic Guardrails API."""

from __future__ import annotations

from typing import Literal, Any
import requests
import json
from pydantic import BaseModel, Field

from protegrity_developer_python.utils.constants import get_config
from protegrity_developer_python.utils.logger import get_logger


_config = get_config("semantic-guardrails")
BASE_URL = _config["endpoint_url"]

logger = get_logger()


# --------------------------------------------------
# Exceptions
# --------------------------------------------------


class SemanticGuardrailsError(Exception):
    """Base exception for Semantic Guardrails SDK."""

    pass


class APIError(SemanticGuardrailsError):
    """Raised when the API returns an error response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


# --------------------------------------------------
# Client
# --------------------------------------------------


def scan_messages(request: MessageBatchRiskRequest) -> MessageBatchRiskResponse:
    """
    Scan a batch of messages for security risks.

    Args:
        request: Batch of messages to scan

    Returns:
        Risk assessment for each message and overall batch assessment
    """

    try:
        response = requests.post(
            f"{BASE_URL}/conversations/messages/scan",
            json=request.model_dump(mode="json", by_alias=True, exclude_none=True),
        )
        response.raise_for_status()
        return MessageBatchRiskResponse.model_validate(response.json())
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


def list_domain_models() -> list[DomainModelResponse]:
    """
    Get information about available domain models.

    Returns:
        List of domain models with their configurations
    """
    try:
        response = requests.get(f"{BASE_URL}/domain-models/")
        response.raise_for_status()
        return [DomainModelResponse.model_validate(item) for item in response.json()]
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request failed: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


# --------------------------------------------------
# Data models
# --------------------------------------------------

SenderRole = Literal["user", "ai", "context"]
RiskOutcome = Literal["approved", "rejected", "skipped"]


class ProcessorResult(BaseModel):
    """Individual processor execution result."""

    name: str
    score: float
    explanation: str | None = None


class MessageRiskRequest(BaseModel):
    """Request model for scanning a single message.

    from_ field is mapped to 'from' in JSON output.

    """

    id: str | None = Field(
        None, description="Optional message ID. SGR will generate one if not provided."
    )
    from_: SenderRole = Field(..., description="Sender role")
    to: SenderRole = Field(..., description="Recipient role")
    content: str = Field(
        ..., min_length=0, max_length=10024, description="Message content"
    )
    processors: list[str] | None = Field(
        None,
        max_length=1,
        description="Processing methods to be used. If None, message is skipped.",
    )

    model_config = {"populate_by_name": True}

    def model_dump(
        self, mode: str = "json", by_alias: bool = True, exclude_none: bool = True
    ) -> dict[str, Any]:
        """Custom model dump to convert to JSON-compatible dict.

        Args:
            mode (str): The mode for dumping the model. Only 'json' is supported.
            by_alias (bool): Whether to use field aliases.
            exclude_none (bool): Whether to exclude fields with None values.
        Returns:
            dict[str, Any]: The dumped model as a dictionary.
        """

        if mode != "json":
            raise ValueError(
                "Only 'json' mode is supported in this custom dump method."
            )

        out = super().model_dump(
            mode=mode, by_alias=by_alias, exclude_none=exclude_none
        )
        out["from"] = out.pop("from_")  # Rename 'from_' to 'from'

        return out


class MessageRiskResponse(BaseModel):
    """Response model for a single scanned message."""

    id: str | None = Field(None, description="Message ID")
    outcome: RiskOutcome = Field(..., description="Risk assessment outcome")
    score: float | None = Field(
        None, ge=0.0, le=1.0, description="Risk score. Higher means riskier."
    )
    processors: list[ProcessorResult] = Field(
        default_factory=list, description="Processor results"
    )


class BatchRiskResponse(BaseModel):
    """Overall batch risk assessment."""

    outcome: Literal["approved", "rejected"] = Field(
        ..., description="Overall batch risk assessment outcome"
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Aggregate risk score for the batch. Higher means riskier.",
    )
    rejected_messages: list[str] = Field(
        ..., description="List of rejected message IDs"
    )


class MessageBatchRiskRequest(BaseModel):
    """Request model for scanning a batch of messages."""

    messages: list[MessageRiskRequest] = Field(
        ..., min_length=1, description="List of messages to risk score"
    )

    def model_dump(
        self, mode: str = "json", by_alias: bool = True, exclude_none: bool = True
    ) -> dict[str, Any]:
        """Custom model dump to convert to JSON-compatible dict.

        Args:
            mode (str): The mode for dumping the model. Only 'json' is supported.
            by_alias (bool): Whether to use field aliases.
            exclude_none (bool): Whether to exclude fields with None values.
        Returns:
            dict[str, Any]: The dumped model as a dictionary.
        """

        if mode != "json":
            raise ValueError(
                "Only 'json' mode is supported in this custom dump method."
            )

        out = {"messages": []}
        for _msg in self.messages:
            msg = _msg.model_dump(
                mode=mode, by_alias=by_alias, exclude_none=exclude_none
            )
            out["messages"].append(msg)

        return out


class MessageBatchRiskResponse(BaseModel):
    """Response model for a batch of scanned messages."""

    messages: list[MessageRiskResponse] = Field(
        ..., description="Individual message risk responses"
    )
    batch: BatchRiskResponse = Field(..., description="Overall batch risk assessment")


class DomainModelResponse(BaseModel):
    """Domain model information."""

    domain: str = Field(..., description="Namespace domain of the domain model")
    model_name: str = Field(..., description="Domain model name")
    threshold: float = Field(..., description="In-domain threshold")
