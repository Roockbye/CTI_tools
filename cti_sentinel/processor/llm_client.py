"""
LLM Client - Interface avec Ollama pour le traitement intelligent des articles CTI.
Prompts spécialisés pour l'analyse de menaces cyber.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp import ClientTimeout

from cti_sentinel.config import ConfigLoader

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client async pour l'API Ollama."""

    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self.base_url = self.config.get("llm.ollama.base_url", "http://localhost:11434")
        self.model = self.config.get("llm.ollama.model", "mistral:7b")
        self.fallback_model = self.config.get("llm.ollama.fallback_model", "llama3:8b")
        self.temperature = self.config.get("llm.ollama.temperature", 0.1)
        self.max_tokens = self.config.get("llm.ollama.max_tokens", 4096)
        self.timeout = ClientTimeout(total=self.config.get("llm.ollama.timeout", 120))
        self.max_retries = self.config.get("llm.ollama.max_retries", 3)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def is_available(self) -> bool:
        """Vérifie si Ollama est accessible et le modèle disponible."""
        try:
            session = await self._get_session()
            async with session.get(f"{self.base_url}/api/tags") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    if self.model in models or self.model.split(":")[0] in [m.split(":")[0] for m in models]:
                        return True
                    logger.warning(
                        "Modèle %s non trouvé. Modèles disponibles: %s",
                        self.model, ", ".join(models)
                    )
                    return False
        except Exception as e:
            logger.error("Ollama non accessible: %s", str(e))
            return False

    async def generate(
        self,
        prompt: str,
        system: str = "",
        model: str = None,
        temperature: float = None,
        max_tokens: int = None,
        json_mode: bool = False,
    ) -> Optional[str]:
        """
        Génère une réponse avec Ollama.

        Args:
            prompt: Prompt utilisateur
            system: Prompt système
            model: Modèle à utiliser (override)
            temperature: Température (override)
            max_tokens: Tokens max (override)
            json_mode: Forcer la sortie JSON

        Returns:
            Texte de la réponse ou None en cas d'erreur
        """
        session = await self._get_session()
        payload = {
            "model": model or self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature or self.temperature,
                "num_predict": max_tokens or self.max_tokens,
            },
        }
        if system:
            payload["system"] = system
        if json_mode:
            payload["format"] = "json"

        for attempt in range(1, self.max_retries + 1):
            try:
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    else:
                        error = await resp.text()
                        logger.warning(
                            "Erreur Ollama (%d): %s (tentative %d/%d)",
                            resp.status, error[:200], attempt, self.max_retries
                        )
            except Exception as e:
                logger.warning(
                    "Erreur requête Ollama: %s (tentative %d/%d)",
                    str(e), attempt, self.max_retries
                )

            # Essayer le modèle de fallback
            if attempt == self.max_retries - 1 and payload["model"] != self.fallback_model:
                logger.info("Basculement vers le modèle fallback: %s", self.fallback_model)
                payload["model"] = self.fallback_model

        return None

    async def generate_json(
        self, prompt: str, system: str = "", **kwargs
    ) -> Optional[Dict[str, Any]]:
        """Génère une réponse JSON structurée."""
        response = await self.generate(
            prompt=prompt, system=system, json_mode=True, **kwargs
        )
        if not response:
            return None

        try:
            # Essayer de parser le JSON
            return json.loads(response)
        except json.JSONDecodeError:
            # Essayer d'extraire le JSON du texte
            try:
                start = response.find("{")
                end = response.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(response[start:end])
            except json.JSONDecodeError:
                pass

            # Dernier recours: chercher un bloc JSON dans le texte
            try:
                start = response.find("[")
                end = response.rfind("]") + 1
                if start != -1 and end > start:
                    return {"items": json.loads(response[start:end])}
            except json.JSONDecodeError:
                pass

            logger.warning("Impossible de parser la réponse JSON du LLM")
            return None


# ============================================================================
# PROMPTS SPÉCIALISÉS CTI
# ============================================================================

CTI_SYSTEM_PROMPT = """Tu es un analyste expert en Cyber Threat Intelligence (CTI).
Tu analyses des articles de sécurité informatique et tu fournis des analyses structurées et précises.
Tu réponds TOUJOURS en JSON valide quand on te le demande.
Tu es concis, factuel et précis. Tu ne spécules pas.
Tu connais parfaitement le framework MITRE ATT&CK, les CVE, et l'écosystème des menaces cyber."""


SEVERITY_SCORING_PROMPT = """Analyse cet article de sécurité et attribue un score de sévérité.

ARTICLE:
Titre: {title}
Source: {source}
Contenu: {content}

Réponds en JSON avec cette structure exacte:
{{
    "severity": "CRITIQUE|HAUTE|MOYENNE|FAIBLE|INFO",
    "confidence": 85,
    "reasoning": "Justification courte en français",
    "categories": ["Ransomware", "APT", "0-day", "Data Breach", "Phishing", "Vulnerability", "Malware", "DDoS", "Supply Chain", "Espionnage", "Géopolitique", "Autre"],
    "impact_sectors": ["finance", "santé", "énergie", "gouvernement", "industrie", "télécoms", "défense", "tous"]
}}

Règles de scoring:
- CRITIQUE: 0-day exploité activement, ransomware majeur en cours, breach massive, APT active contre infrastructure critique
- HAUTE: CVE critique (CVSS ≥ 9), nouvelle campagne APT confirmée, malware très répandu, breach significative
- MOYENNE: CVE haute (CVSS 7-8.9), nouvelle variante malware, campagne phishing ciblée, incident régional
- FAIBLE: CVE moyenne (CVSS 4-6.9), rapport de recherche, tendance observée
- INFO: Article éducatif, mise à jour produit, opinion, patch disponible sans exploit"""


IOC_EXTRACTION_PROMPT = """Extrais tous les indicateurs de compromission (IOCs) de cet article.

ARTICLE:
Titre: {title}
Contenu: {content}

Réponds en JSON avec cette structure exacte:
{{
    "iocs": [
        {{"type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email|cve|yara|ja3", "value": "...", "context": "description courte"}}
    ],
    "cves": ["CVE-YYYY-NNNNN"],
    "mitre_techniques": ["T1059.001"],
    "threat_actors": ["APT28", "Lazarus"],
    "malware_families": ["Emotet", "Cobalt Strike"],
    "targeted_countries": ["France", "USA"],
    "targeted_sectors": ["finance", "santé"]
}}

IMPORTANT:
- N'invente AUCUN IOC, extrais uniquement ceux explicitement mentionnés dans le texte
- Pour les IPs, vérifie que ce sont des adresses valides
- Pour les hashes, vérifie la longueur (MD5=32, SHA1=40, SHA256=64)
- Ignore les IPs privées (10.x, 192.168.x, 172.16-31.x)
- Ignore les domaines légitimes connus (google.com, microsoft.com, etc.)"""


SUMMARY_PROMPT = """Génère un résumé exécutif en français de cet article de cybersécurité.

ARTICLE:
Titre: {title}
Source: {source}
Date: {date}
Contenu: {content}

Réponds en JSON:
{{
    "summary_fr": "Résumé en 3-5 phrases en français. Clair, factuel, actionnable.",
    "key_points": ["Point clé 1 en français", "Point clé 2", "Point clé 3"],
    "defensive_actions": ["Action défensive recommandée 1", "Action 2"],
    "related_topics": ["sujet connexe 1", "sujet 2"]
}}"""


TTP_IDENTIFICATION_PROMPT = """Identifie les Tactiques, Techniques et Procédures (TTPs) MITRE ATT&CK dans cet article.

ARTICLE:
Titre: {title}
Contenu: {content}

Réponds en JSON:
{{
    "ttps": [
        {{
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "confidence": "high|medium|low",
            "evidence": "Citation du texte qui justifie cette identification"
        }}
    ],
    "kill_chain_phase": "Reconnaissance|Weaponization|Delivery|Exploitation|Installation|C2|Actions",
    "attack_complexity": "low|medium|high"
}}

IMPORTANT: Ne liste que les techniques explicitement décrites ou fortement impliquées dans l'article."""


EVENT_CORRELATION_PROMPT = """Analyse cet article en le comparant avec le contexte de menaces suivant et identifie les corrélations.

ARTICLE:
Titre: {title}
Contenu: {content}

CONTEXTE (articles/menaces récents):
{context}

Réponds en JSON:
{{
    "correlations": [
        {{
            "related_to": "Titre ou identifiant de l'élément corrélé",
            "correlation_type": "same_campaign|same_actor|same_malware|same_vulnerability|related_event",
            "confidence": "high|medium|low",
            "explanation": "Explication de la corrélation en français"
        }}
    ],
    "campaign_assessment": "Est-ce que cet article fait partie d'une campagne connue ? Laquelle ?",
    "trend": "Tendance observée en français"
}}"""


FLASHCARD_GENERATION_PROMPT = """Génère des flashcards éducatives CTI à partir de cet article.

ARTICLE:
Titre: {title}
Contenu: {content}

Génère 2-4 flashcards en JSON:
{{
    "flashcards": [
        {{
            "category": "apt|cve|technique|malware|concept|défense",
            "question": "Question en français",
            "answer": "Réponse détaillée en français (2-3 phrases)",
            "difficulty": "débutant|intermédiaire|avancé"
        }}
    ]
}}

Les flashcards doivent être:
- Pertinentes pour un analyste CTI en formation
- Factuelles et basées sur l'article
- Variées en difficulté"""


YARA_SIGMA_PROMPT = """À partir de ces IOCs et TTPs, génère des règles de détection si pertinent.

IOCs: {iocs}
TTPs: {ttps}
Contexte: {context}

Réponds en JSON:
{{
    "yara_rule": "Règle YARA si des hashes/patterns de fichiers sont disponibles, sinon null",
    "sigma_rule": "Règle Sigma au format YAML si des comportements détectables sont identifiés, sinon null",
    "detection_notes": "Notes sur la détection en français"
}}

IMPORTANT: Ne génère des règles que si les IOCs/TTPs le justifient. Privilégie la qualité à la quantité."""
