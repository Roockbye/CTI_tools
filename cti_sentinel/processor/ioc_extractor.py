"""
IOC Extractor - Extraction d'IOCs par regex (sans LLM) pour rapidité.
Utilisé en complément du LLM pour une extraction exhaustive.
"""

import re
import logging
from typing import Dict, List, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ExtractedIOC:
    """IOC extrait avec son contexte."""
    type: str
    value: str
    context: str = ""
    confidence: int = 80


# Patterns regex compilés pour performance
IOC_PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    ),
    "md5": re.compile(r'\b[0-9a-fA-F]{32}\b'),
    "sha1": re.compile(r'\b[0-9a-fA-F]{40}\b'),
    "sha256": re.compile(r'\b[0-9a-fA-F]{64}\b'),
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
    "email": re.compile(
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|io|co|me|xyz|top|club|online|site|website|tech|store|app|dev|ru|cn|tk|ml|ga|cf|gq|work|live|pro|mobi|name|aero|travel|museum|coop|asia|cat|jobs|tel|post|xxx|pw|cc|tv|ws|la|in|de|fr|uk|es|it|nl|br|jp|kr|au|nz|za|ua|pl|cz|hu|ro|bg|hr|rs|si|sk|se|no|fi|dk|at|ch|be|lu|ie|pt|gr|tr|il|eg|ma|tn|ng|ke|gh|tz|et|dz|ly|sd|cm|ci|sn|ml|bf|ne|td|gn|mw|zm|zw|bw|na|sz|ls|mg|mu|mz|ao|cd|cg|ga|gq|st|cv|sc|km|dj|er|so|rw|bi|ug|ss|cf|tg|bj|lr|sl|gw|mr|gm|sh|ac|io)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        r'(?:/[^\s<>"{}|\\^`\[\]]*)?',
        re.IGNORECASE
    ),
    "bitcoin": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b'),
    "ja3": re.compile(r'\b[0-9a-fA-F]{32}\b'),  # Même format MD5, contextualisé
}

# IPs privées et réservées à exclure
PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.'),
    re.compile(r'^169\.254\.'),
    re.compile(r'^224\.'),
    re.compile(r'^255\.'),
]

# Domaines légitimes à exclure
WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "github.com", "linkedin.com",
    "youtube.com", "wikipedia.org", "reddit.com", "cloudflare.com",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "amazonaws.com", "windows.net", "office.com", "office365.com",
    "mozilla.org", "w3.org", "schema.org", "creativecommons.org",
    "example.com", "example.org", "example.net", "localhost",
    "t.co", "bit.ly", "goo.gl", "ow.ly",
}

# Emails légitimes à exclure
WHITELIST_EMAILS = {
    "noreply@", "no-reply@", "support@", "info@", "admin@",
    "contact@", "sales@", "marketing@", "security@",
}

# Faux positifs hash courants (hex strings qui ne sont pas des hashes)
HASH_FALSE_POSITIVES = {
    "0" * 32, "f" * 32, "0" * 40, "f" * 40, "0" * 64, "f" * 64,
}


class IOCExtractor:
    """Extracteur d'IOCs par regex, rapide et sans dépendance LLM."""

    def __init__(self, whitelist_domains: Set[str] = None):
        self.whitelist_domains = whitelist_domains or WHITELIST_DOMAINS

    def extract(self, text: str) -> List[ExtractedIOC]:
        """
        Extrait tous les IOCs d'un texte.

        Args:
            text: Texte brut à analyser

        Returns:
            Liste d'IOCs extraits et dédupliqués
        """
        if not text:
            return []

        iocs: List[ExtractedIOC] = []
        seen_values: Set[str] = set()

        # Extraire chaque type d'IOC
        for ioc_type, pattern in IOC_PATTERNS.items():
            # Éviter les doublons JA3/MD5 (même pattern)
            if ioc_type == "ja3":
                continue

            matches = pattern.finditer(text)
            for match in matches:
                value = match.group().strip()

                # Déduplier
                if value.lower() in seen_values:
                    continue

                # Valider et filtrer
                if self._is_valid_ioc(ioc_type, value):
                    context = self._extract_context(text, match.start(), match.end())
                    confidence = self._compute_confidence(ioc_type, value, context)

                    iocs.append(ExtractedIOC(
                        type=ioc_type,
                        value=value,
                        context=context,
                        confidence=confidence,
                    ))
                    seen_values.add(value.lower())

        logger.debug("Extraction: %d IOCs trouvés", len(iocs))
        return iocs

    def extract_cves(self, text: str) -> List[str]:
        """Extrait uniquement les CVE IDs."""
        if not text:
            return []
        return list(set(IOC_PATTERNS["cve"].findall(text)))

    def _is_valid_ioc(self, ioc_type: str, value: str) -> bool:
        """Valide un IOC extrait pour filtrer les faux positifs."""

        if ioc_type == "ipv4":
            # Exclure IPs privées
            for pattern in PRIVATE_IP_RANGES:
                if pattern.match(value):
                    return False
            # Vérifier que les octets sont valides
            parts = value.split(".")
            if len(parts) != 4:
                return False
            return True

        elif ioc_type in ("md5", "sha1", "sha256"):
            # Exclure les faux positifs connus
            if value.lower() in HASH_FALSE_POSITIVES:
                return False
            # Exclure si c'est un nombre pur (pas un hash)
            if value.isdigit():
                return False
            # Vérifier la longueur exacte
            expected_lengths = {"md5": 32, "sha1": 40, "sha256": 64}
            return len(value) == expected_lengths[ioc_type]

        elif ioc_type == "domain":
            domain_lower = value.lower()
            # Exclure les domaines whitelistés
            for wl in self.whitelist_domains:
                if domain_lower == wl or domain_lower.endswith(f".{wl}"):
                    return False
            # Longueur minimale
            if len(domain_lower) < 4:
                return False
            return True

        elif ioc_type == "url":
            url_lower = value.lower()
            # Exclure les URLs de domaines whitelistés
            for wl in self.whitelist_domains:
                if wl in url_lower:
                    return False
            return True

        elif ioc_type == "email":
            email_lower = value.lower()
            # Exclure les emails génériques
            for wl in WHITELIST_EMAILS:
                if email_lower.startswith(wl):
                    return False
            # Exclure les emails de domaines whitelistés
            domain = email_lower.split("@")[-1]
            if domain in self.whitelist_domains:
                return False
            return True

        elif ioc_type == "cve":
            # Toujours valide si le pattern matche
            return True

        return True

    def _extract_context(self, text: str, start: int, end: int, window: int = 100) -> str:
        """Extrait le contexte autour d'un IOC (fenêtre de caractères)."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        context = text[ctx_start:ctx_end].strip()
        # Nettoyer le contexte
        context = " ".join(context.split())
        return context[:250]

    def _compute_confidence(self, ioc_type: str, value: str, context: str) -> int:
        """Calcule un score de confiance pour l'IOC."""
        confidence = 70

        # CVEs sont toujours fiables
        if ioc_type == "cve":
            return 95

        # Hashes avec contexte de malware = haute confiance
        if ioc_type in ("md5", "sha1", "sha256"):
            if any(kw in context.lower() for kw in ["malware", "hash", "sample", "trojan", "ransomware"]):
                confidence = 90
            else:
                confidence = 60  # Pourrait être un hash non-malware

        # IPs avec contexte de C2/malware
        if ioc_type == "ipv4":
            if any(kw in context.lower() for kw in ["c2", "c&c", "command", "control", "malicious", "beacon"]):
                confidence = 90
            elif any(kw in context.lower() for kw in ["attacker", "threat", "compromise"]):
                confidence = 80

        # Domaines avec contexte
        if ioc_type == "domain":
            if any(kw in context.lower() for kw in ["malicious", "phishing", "malware", "c2"]):
                confidence = 85
            else:
                confidence = 50  # Pourrait être légitime

        return confidence

    def to_dict_list(self, iocs: List[ExtractedIOC]) -> List[Dict]:
        """Convertit les IOCs en liste de dictionnaires."""
        return [
            {
                "type": ioc.type,
                "value": ioc.value,
                "context": ioc.context,
                "confidence": ioc.confidence,
            }
            for ioc in iocs
        ]
