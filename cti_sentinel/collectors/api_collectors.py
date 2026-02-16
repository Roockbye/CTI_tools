"""
API Collectors - Collecteurs pour les APIs de Threat Intelligence.
NVD, AlienVault OTX, abuse.ch (URLhaus, MalwareBazaar, ThreatFox), MITRE ATT&CK.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from cti_sentinel.collectors.base import BaseCollector
from cti_sentinel.config import ConfigLoader

logger = logging.getLogger(__name__)


# ============================================================================
# NVD - National Vulnerability Database
# ============================================================================

class NVDCollector(BaseCollector):
    """Collecte les CVE récentes depuis l'API NVD 2.0."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("vulnerabilities", "nvd")

        super().__init__(
            name="nvd",
            category="vulnerabilities",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 5),
            timeout=60,
        )
        self.base_url = source_cfg.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.api_key = source_cfg.get("api_key", "")

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les CVE publiées/modifiées récemment."""
        items = []

        # Récupérer les CVE des dernières 24h
        now = datetime.now(timezone.utc)
        pub_start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 100,
            "startIndex": 0,
        }

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        start_index = 0
        total_results = 1  # Initial, sera mis à jour

        while start_index < total_results:
            params["startIndex"] = start_index
            data = await self.fetch(
                self.base_url, params=params, headers=headers, use_cache=False
            )

            if not data or not isinstance(data, dict):
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln_wrapper in vulnerabilities:
                try:
                    cve_data = vuln_wrapper.get("cve", {})
                    item = self._parse_cve(cve_data)
                    if item:
                        items.append(item)
                except Exception as e:
                    self.logger.warning("Erreur parsing CVE: %s", str(e))
                    self.stats["errors"] += 1

            start_index += len(vulnerabilities)
            self.logger.info(
                "📊 NVD: %d/%d CVE traitées", start_index, total_results
            )

            # Respecter strictement le rate limit NVD (https://nvd.nist.gov/developers/start-here)
            # Sans clé API : max 5 requêtes par 30s → 7s de délai (marge de sécurité)
            # Avec clé API : max 50 requêtes par 30s → 0.7s de délai
            if not self.api_key:
                await asyncio.sleep(7)
            else:
                await asyncio.sleep(0.7)

        self.stats["new"] = len(items)
        self.logger.info("✅ NVD: %d CVE collectées", len(items))
        return items

    def _parse_cve(self, cve_data: dict) -> Optional[Dict[str, Any]]:
        """Parse une CVE depuis le format NVD 2.0."""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return None

        # Description
        descriptions = cve_data.get("descriptions", [])
        desc_en = ""
        desc_fr = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                desc_en = desc.get("value", "")
            elif desc.get("lang") == "fr":
                desc_fr = desc.get("value", "")

        # Métriques CVSS
        metrics = cve_data.get("metrics", {})
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v2_score = None

        # CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            primary = next((m for m in cvss_v31 if m.get("type") == "Primary"), cvss_v31[0])
            cvss_data = primary.get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")

        # CVSS v3.0 fallback
        if not cvss_v3_score:
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                primary = next((m for m in cvss_v30 if m.get("type") == "Primary"), cvss_v30[0])
                cvss_data = primary.get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")

        # CVSS v2
        cvss_v2_list = metrics.get("cvssMetricV2", [])
        if cvss_v2_list:
            cvss_v2_score = cvss_v2_list[0].get("cvssData", {}).get("baseScore")

        # Sévérité
        severity = self._score_to_severity(cvss_v3_score)

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwe_ids.append(cwe_val)

        # Références
        references = [
            ref.get("url") for ref in cve_data.get("references", [])
        ]

        # Dates
        published = cve_data.get("published")
        modified = cve_data.get("lastModified")

        # Produits affectés (CPE)
        products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe = cpe_match.get("criteria", "")
                        products.append(cpe)

        return {
            "type": "vulnerability",
            "cve_id": cve_id,
            "title": f"{cve_id} - {desc_en[:200]}",
            "content": desc_en,
            "description_fr": desc_fr,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source_name": "nvd",
            "source_category": "vulnerabilities",
            "published_at": self._parse_date(published),
            "modified_at": self._parse_date(modified),
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v2_score": cvss_v2_score,
            "severity": severity,
            "cwe_ids": cwe_ids,
            "references": references,
            "products_cpe": products,
            "raw_data": cve_data,
        }

    @staticmethod
    def _score_to_severity(score: Optional[float]) -> str:
        """Convertit un score CVSS en niveau de sévérité."""
        if score is None:
            return "INFO"
        if score >= 9.0:
            return "CRITIQUE"
        if score >= 7.0:
            return "HAUTE"
        if score >= 4.0:
            return "MOYENNE"
        if score > 0:
            return "FAIBLE"
        return "INFO"

    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
        """Parse une date ISO depuis l'API NVD."""
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# AlienVault OTX
# ============================================================================

class OTXCollector(BaseCollector):
    """Collecte les pulses de threat intelligence depuis AlienVault OTX."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("threat_intel", "alienvault_otx")

        super().__init__(
            name="alienvault_otx",
            category="threat_intel",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 20),
        )
        self.base_url = source_cfg.get("base_url", "https://otx.alienvault.com/api/v1")
        self.api_key = source_cfg.get("api_key", "")

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les pulses récentes depuis OTX."""
        items = []

        if not self.api_key:
            self.logger.warning("⚠️ OTX: Clé API requise, collecte limitée")
            return await self._collect_public()

        headers = {"X-OTX-API-KEY": self.api_key}

        # Pulses souscrites
        url = f"{self.base_url}/pulses/subscribed"
        params = {"limit": 50, "page": 1, "modified_since": self._get_since_date()}

        for page in range(1, 4):  # Max 3 pages
            params["page"] = page
            data = await self.fetch(url, headers=headers, params=params, use_cache=False)

            if not data or not isinstance(data, dict):
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                try:
                    item = self._parse_pulse(pulse)
                    if item:
                        items.append(item)
                except Exception as e:
                    self.logger.warning("Erreur parsing pulse OTX: %s", str(e))
                    self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    async def _collect_public(self) -> List[Dict[str, Any]]:
        """Collecte les pulses publiques récentes (sans clé API)."""
        items = []
        url = f"{self.base_url}/pulses/activity"
        data = await self.fetch(url, use_cache=True)

        if data and isinstance(data, dict):
            for pulse in data.get("results", [])[:50]:
                try:
                    item = self._parse_pulse(pulse)
                    if item:
                        items.append(item)
                except Exception as e:
                    self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    def _parse_pulse(self, pulse: dict) -> Optional[Dict[str, Any]]:
        """Parse un pulse OTX."""
        title = pulse.get("name", "")
        if not title:
            return None

        # Extraire les IOCs
        indicators = pulse.get("indicators", [])
        iocs = []
        for ind in indicators:
            ioc_type = self._map_otx_type(ind.get("type", ""))
            if ioc_type:
                iocs.append({
                    "type": ioc_type,
                    "value": ind.get("indicator", ""),
                    "title": ind.get("title", ""),
                })

        # Tags
        tags = pulse.get("tags", [])

        # TTPs
        attack_ids = [
            att.get("id", "")
            for att in pulse.get("attack_ids", [])
        ]

        return {
            "type": "threat_intel",
            "title": title,
            "content": pulse.get("description", ""),
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
            "source_name": "alienvault_otx",
            "source_category": "threat_intel",
            "author": pulse.get("author", {}).get("username"),
            "published_at": self._parse_date(pulse.get("created")),
            "iocs": iocs,
            "tags": tags,
            "attack_ids": attack_ids,
            "targeted_countries": pulse.get("targeted_countries", []),
            "adversary": pulse.get("adversary"),
            "malware_families": pulse.get("malware_families", []),
            "references": pulse.get("references", []),
            "raw_data": pulse,
        }

    @staticmethod
    def _map_otx_type(otx_type: str) -> Optional[str]:
        """Mappe les types OTX vers nos types IOC."""
        mapping = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "URI": "url",
            "FileHash-MD5": "md5",
            "FileHash-SHA1": "sha1",
            "FileHash-SHA256": "sha256",
            "email": "email",
            "CVE": "cve",
            "YARA": "yara",
            "Mutex": "mutex",
            "CIDR": "cidr",
            "JA3": "ja3",
        }
        return mapping.get(otx_type)

    def _get_since_date(self) -> str:
        """Date de début pour la requête (24h glissantes)."""
        return (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")

    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# URLhaus (abuse.ch)
# ============================================================================

class URLhausCollector(BaseCollector):
    """Collecte les URLs malveillantes depuis URLhaus."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("threat_intel", "urlhaus")

        super().__init__(
            name="urlhaus",
            category="threat_intel",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 10),
        )
        self.base_url = source_cfg.get("base_url", "https://urlhaus-api.abuse.ch/v1")

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les URLs malveillantes récentes."""
        items = []

        # Récupérer les URLs récentes
        data = await self.fetch(
            f"{self.base_url}/urls/recent/",
            method="POST",
            json_data={"limit": 100},
            use_cache=False,
        )

        if not data or not isinstance(data, dict):
            # Fallback: essayer le feed CSV
            data = await self.fetch(
                f"{self.base_url}/urls/recent/limit/100/",
                method="GET",
                use_cache=False,
            )
            if not data:
                return items

        urls_list = data.get("urls", [])
        if not urls_list and isinstance(data, dict):
            urls_list = data.get("data", [])

        for url_entry in urls_list:
            try:
                if isinstance(url_entry, dict):
                    item = {
                        "type": "ioc",
                        "ioc_type": "url",
                        "title": f"URL malveillante: {url_entry.get('url', '')[:80]}",
                        "content": f"Threat: {url_entry.get('threat', 'N/A')} | "
                                   f"Status: {url_entry.get('url_status', 'N/A')} | "
                                   f"Tags: {', '.join(url_entry.get('tags', []) or [])}",
                        "url": url_entry.get("urlhaus_reference", ""),
                        "source_name": "urlhaus",
                        "source_category": "threat_intel",
                        "published_at": self._parse_date(url_entry.get("dateadded")),
                        "iocs": [{
                            "type": "url",
                            "value": url_entry.get("url", ""),
                            "threat": url_entry.get("threat"),
                            "status": url_entry.get("url_status"),
                        }],
                        "tags": url_entry.get("tags", []) or [],
                        "raw_data": url_entry,
                    }
                    items.append(item)
            except Exception as e:
                self.logger.warning("Erreur parsing URLhaus: %s", str(e))
                self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# MalwareBazaar (abuse.ch)
# ============================================================================

class MalwareBazaarCollector(BaseCollector):
    """Collecte les échantillons de malware récents depuis MalwareBazaar."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("threat_intel", "malware_bazaar")

        super().__init__(
            name="malware_bazaar",
            category="threat_intel",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 10),
        )
        self.base_url = source_cfg.get("base_url", "https://mb-api.abuse.ch/api/v1")

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les derniers échantillons de malware."""
        items = []

        data = await self.fetch(
            f"{self.base_url}/",
            method="POST",
            json_data={"query": "get_recent", "selector": "100"},
            use_cache=False,
        )

        if not data or not isinstance(data, dict):
            return items

        if data.get("query_status") != "ok":
            self.logger.warning("MalwareBazaar query_status: %s", data.get("query_status"))
            return items

        for sample in data.get("data", []):
            try:
                tags = sample.get("tags", []) or []
                signature = sample.get("signature") or "Unknown"

                item = {
                    "type": "malware",
                    "title": f"Malware: {signature} ({sample.get('file_type', 'N/A')})",
                    "content": (
                        f"Famille: {signature}\n"
                        f"Type: {sample.get('file_type', 'N/A')}\n"
                        f"Taille: {sample.get('file_size', 'N/A')} bytes\n"
                        f"SHA256: {sample.get('sha256_hash', 'N/A')}\n"
                        f"Tags: {', '.join(tags)}\n"
                        f"Delivery: {sample.get('delivery_method', 'N/A')}"
                    ),
                    "url": f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash', '')}/",
                    "source_name": "malware_bazaar",
                    "source_category": "threat_intel",
                    "published_at": self._parse_date(sample.get("first_seen")),
                    "malware_info": {
                        "family": signature,
                        "md5": sample.get("md5_hash"),
                        "sha1": sample.get("sha1_hash"),
                        "sha256": sample.get("sha256_hash"),
                        "ssdeep": sample.get("ssdeep"),
                        "file_type": sample.get("file_type"),
                        "file_size": sample.get("file_size"),
                        "delivery_method": sample.get("delivery_method"),
                    },
                    "iocs": [
                        {"type": "sha256", "value": sample.get("sha256_hash", "")},
                        {"type": "sha1", "value": sample.get("sha1_hash", "")},
                        {"type": "md5", "value": sample.get("md5_hash", "")},
                    ],
                    "tags": tags,
                    "raw_data": sample,
                }
                items.append(item)
            except Exception as e:
                self.logger.warning("Erreur parsing MalwareBazaar: %s", str(e))
                self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    @staticmethod
    def _parse_date(date_str):
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# ThreatFox (abuse.ch)
# ============================================================================

class ThreatFoxCollector(BaseCollector):
    """Collecte les IOCs depuis ThreatFox."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("threat_intel", "threatfox")

        super().__init__(
            name="threatfox",
            category="threat_intel",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 10),
        )
        self.base_url = source_cfg.get("base_url", "https://threatfox-api.abuse.ch/api/v1")

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les IOCs récents depuis ThreatFox."""
        items = []

        data = await self.fetch(
            f"{self.base_url}/",
            method="POST",
            json_data={"query": "get_iocs", "days": 1},
            use_cache=False,
        )

        if not data or not isinstance(data, dict):
            return items

        if data.get("query_status") != "ok":
            return items

        for ioc_entry in data.get("data", []):
            try:
                ioc_type = self._map_threatfox_type(ioc_entry.get("ioc_type", ""))
                if not ioc_type:
                    continue

                malware = ioc_entry.get("malware", "")
                malware_printable = ioc_entry.get("malware_printable", malware)

                item = {
                    "type": "ioc",
                    "title": f"IOC ThreatFox: {malware_printable} ({ioc_entry.get('threat_type', '')})",
                    "content": (
                        f"Malware: {malware_printable}\n"
                        f"Threat Type: {ioc_entry.get('threat_type', 'N/A')}\n"
                        f"IOC: {ioc_entry.get('ioc', '')}\n"
                        f"Confidence: {ioc_entry.get('confidence_level', 'N/A')}%\n"
                        f"Reporter: {ioc_entry.get('reporter', 'N/A')}"
                    ),
                    "url": f"https://threatfox.abuse.ch/ioc/{ioc_entry.get('id', '')}",
                    "source_name": "threatfox",
                    "source_category": "threat_intel",
                    "published_at": self._parse_date(ioc_entry.get("first_seen_utc")),
                    "iocs": [{
                        "type": ioc_type,
                        "value": ioc_entry.get("ioc", ""),
                        "confidence": ioc_entry.get("confidence_level"),
                    }],
                    "tags": ioc_entry.get("tags", []) or [],
                    "malware_family": malware_printable,
                    "raw_data": ioc_entry,
                }
                items.append(item)
            except Exception as e:
                self.logger.warning("Erreur parsing ThreatFox: %s", str(e))
                self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    @staticmethod
    def _map_threatfox_type(tf_type: str) -> Optional[str]:
        mapping = {
            "ip:port": "ipv4",
            "domain": "domain",
            "url": "url",
            "md5_hash": "md5",
            "sha256_hash": "sha256",
        }
        return mapping.get(tf_type)

    @staticmethod
    def _parse_date(date_str):
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# MITRE ATT&CK
# ============================================================================

class MITRECollector(BaseCollector):
    """Collecte les données MITRE ATT&CK (groupes, techniques, malwares)."""

    def __init__(self, config: ConfigLoader = None):
        cfg = config or ConfigLoader()
        source_cfg = cfg.get_source_config("apt_groups", "mitre_attack")

        super().__init__(
            name="mitre_attack",
            category="apt_groups",
            config=cfg,
            rate_limit=source_cfg.get("rate_limit", 10),
        )
        self.base_url = source_cfg.get(
            "base_url",
            "https://raw.githubusercontent.com/mitre/cti/master"
        )

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les données MITRE ATT&CK Enterprise."""
        items = []

        # Récupérer le bundle Enterprise ATT&CK
        url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
        data = await self.fetch(url, use_cache=True)

        if not data or not isinstance(data, dict):
            self.logger.error("Impossible de récupérer le bundle MITRE ATT&CK")
            return items

        objects = data.get("objects", [])
        self.logger.info("📊 MITRE ATT&CK: %d objets trouvés", len(objects))

        for obj in objects:
            obj_type = obj.get("type", "")
            try:
                if obj_type == "intrusion-set":
                    item = self._parse_group(obj)
                elif obj_type == "attack-pattern":
                    item = self._parse_technique(obj)
                elif obj_type == "malware":
                    item = self._parse_malware(obj)
                elif obj_type == "tool":
                    item = self._parse_tool(obj)
                else:
                    continue

                if item:
                    items.append(item)
            except Exception as e:
                self.logger.warning("Erreur parsing MITRE objet: %s", str(e))
                self.stats["errors"] += 1

        self.stats["new"] = len(items)
        return items

    def _parse_group(self, obj: dict) -> Dict[str, Any]:
        """Parse un groupe APT MITRE."""
        external_refs = obj.get("external_references", [])
        mitre_id = ""
        refs = []
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
            if ref.get("url"):
                refs.append(ref["url"])

        aliases = obj.get("aliases", [])

        return {
            "type": "threat_actor",
            "title": obj.get("name", ""),
            "content": obj.get("description", ""),
            "url": f"https://attack.mitre.org/groups/{mitre_id}/",
            "source_name": "mitre_attack",
            "source_category": "apt_groups",
            "published_at": self._parse_date(obj.get("created")),
            "threat_actor": {
                "name": obj.get("name", ""),
                "mitre_id": mitre_id,
                "aliases": aliases,
                "description": obj.get("description", ""),
                "references": refs,
            },
            "raw_data": obj,
        }

    def _parse_technique(self, obj: dict) -> Dict[str, Any]:
        """Parse une technique MITRE ATT&CK."""
        external_refs = obj.get("external_references", [])
        mitre_id = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")

        kill_chain = obj.get("kill_chain_phases", [])
        tactics = [kc.get("phase_name", "") for kc in kill_chain]

        return {
            "type": "ttp",
            "title": f"{mitre_id} - {obj.get('name', '')}",
            "content": obj.get("description", ""),
            "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            "source_name": "mitre_attack",
            "source_category": "apt_groups",
            "ttp": {
                "mitre_id": mitre_id,
                "name": obj.get("name", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
            },
            "raw_data": obj,
        }

    def _parse_malware(self, obj: dict) -> Dict[str, Any]:
        """Parse un malware MITRE ATT&CK."""
        external_refs = obj.get("external_references", [])
        mitre_id = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")

        return {
            "type": "malware",
            "title": f"Malware: {obj.get('name', '')} ({mitre_id})",
            "content": obj.get("description", ""),
            "url": f"https://attack.mitre.org/software/{mitre_id}/",
            "source_name": "mitre_attack",
            "source_category": "apt_groups",
            "malware_info": {
                "name": obj.get("name", ""),
                "mitre_id": mitre_id,
                "aliases": obj.get("x_mitre_aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "type": ", ".join(obj.get("malware_types", [])),
            },
            "raw_data": obj,
        }

    def _parse_tool(self, obj: dict) -> Dict[str, Any]:
        """Parse un tool MITRE ATT&CK."""
        external_refs = obj.get("external_references", [])
        mitre_id = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")

        return {
            "type": "malware",
            "title": f"Tool: {obj.get('name', '')} ({mitre_id})",
            "content": obj.get("description", ""),
            "url": f"https://attack.mitre.org/software/{mitre_id}/",
            "source_name": "mitre_attack",
            "source_category": "apt_groups",
            "malware_info": {
                "name": obj.get("name", ""),
                "mitre_id": mitre_id,
                "aliases": obj.get("x_mitre_aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "type": "tool",
            },
            "raw_data": obj,
        }

    @staticmethod
    def _parse_date(date_str):
        if not date_str:
            return None
        try:
            from dateutil import parser as dateparser
            return dateparser.parse(date_str)
        except (ValueError, TypeError):
            return None


# ============================================================================
# FACTORY - Création de tous les collecteurs API
# ============================================================================

def create_api_collectors(config: ConfigLoader = None) -> List[BaseCollector]:
    """Crée tous les collecteurs API activés."""
    cfg = config or ConfigLoader()
    collectors = []

    # NVD
    nvd_cfg = cfg.get_source_config("vulnerabilities", "nvd")
    if nvd_cfg and nvd_cfg.get("enabled", False):
        collectors.append(NVDCollector(cfg))

    # AlienVault OTX
    otx_cfg = cfg.get_source_config("threat_intel", "alienvault_otx")
    if otx_cfg and otx_cfg.get("enabled", False):
        collectors.append(OTXCollector(cfg))

    # URLhaus
    urlhaus_cfg = cfg.get_source_config("threat_intel", "urlhaus")
    if urlhaus_cfg and urlhaus_cfg.get("enabled", False):
        collectors.append(URLhausCollector(cfg))

    # MalwareBazaar
    mb_cfg = cfg.get_source_config("threat_intel", "malware_bazaar")
    if mb_cfg and mb_cfg.get("enabled", False):
        collectors.append(MalwareBazaarCollector(cfg))

    # ThreatFox
    tf_cfg = cfg.get_source_config("threat_intel", "threatfox")
    if tf_cfg and tf_cfg.get("enabled", False):
        collectors.append(ThreatFoxCollector(cfg))

    # MITRE ATT&CK
    mitre_cfg = cfg.get_source_config("apt_groups", "mitre_attack")
    if mitre_cfg and mitre_cfg.get("enabled", False):
        collectors.append(MITRECollector(cfg))

    logger.info("✅ %d collecteurs API configurés", len(collectors))
    return collectors
