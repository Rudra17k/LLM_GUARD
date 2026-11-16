import re
import unicodedata

# Comprehensive mapping of Cyrillic and Greek homoglyphs to Latin equivalents
HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lowercase
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
    # Greek lowercase
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'υ': 'u', 'χ': 'x',
    # Greek uppercase
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
})

# Zero-width, formatting, and invisible characters
ZERO_WIDTH_REGEX = re.compile(r'[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]')

# Single character spacing: collapse isolated single letters separated by space or separator
# e.g. "I g n o r e" -> "Ignore", "a-l-l" -> "all"
SPACED_LETTER_REGEX = re.compile(r'(?<=\b[a-zA-Z])[ _\-\.](?=[a-zA-Z]\b)')

# Multiple whitespace runs
MULTI_SPACE_REGEX = re.compile(r'\s+')


class InputNormalizer:
    """
    Normalizes incoming untrusted text to prevent adversarial evasion attacks.
    Applies:
      1. Unicode NFKD decomposition (normalizes full-width and compatibility characters)
      2. Homoglyph translation (Cyrillic and Greek lookalikes to Latin)
      3. Zero-width and invisible character stripping
      4. Single-character separator collapsing (space, dot, dash, underscore)
      5. Whitespace run normalization
    """

    @classmethod
    def normalize(cls, text: str) -> str:
        if not text:
            return ""

        # 1. Unicode NFKD normalization
        normalized = unicodedata.normalize("NFKD", text)

        # 2. Homoglyph translation
        normalized = normalized.translate(HOMOGLYPH_MAP)

        # 3. Strip zero-width and invisible characters
        normalized = ZERO_WIDTH_REGEX.sub("", normalized)

        # 4. Collapse spaced single characters
        normalized = SPACED_LETTER_REGEX.sub("", normalized)

        # 5. Collapse consecutive whitespace
        normalized = MULTI_SPACE_REGEX.sub(" ", normalized).strip()

        return normalized
