from dataclasses import asdict, dataclass, field
from typing import Literal


@dataclass
class Address:
    value: str
    network: str
    validation: str
    source: str
    page_url: str
    context: str
    role: str = "unknown"
    screenshot: str | None = None


@dataclass
class Observation:
    step: int
    url: str
    title: str
    text: str
    controls: list[dict]
    addresses: list[Address]
    screenshot: str
    fingerprint: str
    status_code: int | None = None


@dataclass
class Verdict:
    classification: Literal["SCAM", "NOT_SCAM"]
    confidence: float
    reasoning: str
    evidence: list[str] = field(default_factory=list)
    needs_review: bool = False


@dataclass
class Result:
    url: str
    status: str = "pending"
    classification: str = "NOT_SCAM"
    confidence: float = 0.0
    reasoning: str = "No evidence collected."
    evidence: list[str] = field(default_factory=list)
    needs_review: bool = True
    crypto_addresses: list[Address] = field(default_factory=list)
    address_candidates: list[Address] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    access_diagnostic: str | None = None
    analysis_mode: str = "rules"

    def to_dict(self):
        return asdict(self)
