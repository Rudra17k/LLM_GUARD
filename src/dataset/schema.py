from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class InjectionType(str, Enum):
    """High-level category of prompt injection."""
    BENIGN = "benign"
    DIRECT = "direct"
    INDIRECT = "indirect"


class AttackFamily(str, Enum):
    """Granular attack techniques and benign classes."""
    # Direct injection families
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLEPLAY_AUTHORITY = "roleplay_authority"
    INSTRUCTION_OVERRIDE = "instruction_override"
    OBFUSCATION_ENCODING = "obfuscation_encoding"
    
    # Indirect injection families
    DELIMITER_SPOOFING = "delimiter_spoofing"
    MARKDOWN_EXFILTRATION = "markdown_exfiltration"
    HIDDEN_DOCUMENT_PAYLOAD = "hidden_document_payload"
    
    # Benign families
    BENIGN_GENERAL = "benign_general"
    BENIGN_CODING = "benign_coding"
    BENIGN_SECURITY_DISCUSSION = "benign_security_discussion"


class PromptSample(BaseModel):
    """Schema for a single data point in our prompt injection corpus."""
    id: str = Field(description="Unique identifier for the sample")
    text: str = Field(description="The prompt payload or document snippet")
    label: int = Field(description="0 for benign, 1 for injection (direct or indirect)")
    injection_type: InjectionType = Field(description="High-level category: benign, direct, or indirect")
    attack_family: AttackFamily = Field(description="Specific attack vector or benign category")
    provenance: str = Field(description="Origin source (e.g., synthetic, bipia, jailbreakbench, alpaca)")
    language: str = Field(default="en", description="ISO 639-1 language code")
    metadata: Optional[dict] = Field(default_factory=dict, description="Arbitrary extra details (e.g., target model, author)")

    @field_validator("label")
    @classmethod
    def validate_label_matches_type(cls, v: int, info):
        # We will add cross-field validation once values are present
        if v not in (0, 1):
            raise ValueError("Label must be 0 (benign) or 1 (injection)")
        return v

    def is_injection(self) -> bool:
        return self.label == 1
