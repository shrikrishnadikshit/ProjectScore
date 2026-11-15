from dataclasses import dataclass, field


@dataclass
class RawFinding:
    risk_factor: str
    code: str
    title: str
    severity: str
    asset_value: str
    evidence: dict = field(default_factory=dict)
    detection_confidence: float = 1.0
