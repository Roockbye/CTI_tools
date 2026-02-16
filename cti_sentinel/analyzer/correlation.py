"""
Correlation Engine - Analyse et corrélation d'entités CTI.
Graphe de relations, détection de patterns, scoring de menaces.
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple

from sqlalchemy import func, desc, and_, or_
from sqlalchemy.orm import Session

from cti_sentinel.config import ConfigLoader
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.database.models import (
    Article, Vulnerability, IOC, ThreatActor, Malware,
    Campaign, TTP, Tag, SeverityLevel,
    article_iocs, article_threat_actors, article_malwares,
    article_cves, threat_actor_malwares, threat_actor_ttps,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Moteur de corrélation et d'analyse CTI.

    Fonctionnalités:
    - Graphe de relations entre entités
    - Détection de tendances
    - Scoring de menaces par secteur/région
    - Recommandations défensives
    - Timeline d'événements corrélés
    """

    def __init__(self, config: ConfigLoader = None, db: DatabaseManager = None):
        self.config = config or ConfigLoader()
        self.db = db or DatabaseManager(self.config)

    # ========================================================================
    # GRAPHE DE RELATIONS
    # ========================================================================

    def build_entity_graph(self, session: Session, entity_type: str = None,
                           entity_id: int = None, depth: int = 2) -> Dict[str, Any]:
        """
        Construit un graphe de relations entre entités.

        Returns:
            {
                "nodes": [{"id": ..., "type": ..., "label": ..., "data": {...}}, ...],
                "edges": [{"source": ..., "target": ..., "type": ..., "weight": ...}, ...]
            }
        """
        nodes = []
        edges = []
        seen_nodes = set()

        if entity_type and entity_id:
            # Graphe centré sur une entité
            self._expand_entity(session, entity_type, entity_id, nodes, edges, seen_nodes, depth)
        else:
            # Graphe global des relations récentes (7 jours)
            self._build_recent_graph(session, nodes, edges, seen_nodes)

        return {"nodes": nodes, "edges": edges}

    def _expand_entity(self, session, entity_type: str, entity_id: int,
                       nodes: list, edges: list, seen: set, depth: int):
        """Expand un nœud du graphe en suivant ses relations."""
        if depth <= 0:
            return

        node_key = f"{entity_type}_{entity_id}"
        if node_key in seen:
            return
        seen.add(node_key)

        if entity_type == "threat_actor":
            ta = session.query(ThreatActor).get(entity_id)
            if not ta:
                return
            nodes.append({
                "id": node_key, "type": "threat_actor",
                "label": ta.name, "data": {
                    "origin": ta.origin_country, "type": str(ta.type),
                    "mitre_id": ta.mitre_id,
                }
            })
            # Relations malwares
            for malware in ta.malwares:
                edge_key = f"ta_malware_{ta.id}_{malware.id}"
                edges.append({
                    "source": node_key, "target": f"malware_{malware.id}",
                    "type": "uses", "id": edge_key,
                })
                self._expand_entity(session, "malware", malware.id, nodes, edges, seen, depth - 1)

            # Relations campagnes
            for campaign in ta.campaigns:
                edge_key = f"ta_campaign_{ta.id}_{campaign.id}"
                edges.append({
                    "source": node_key, "target": f"campaign_{campaign.id}",
                    "type": "attributed_to", "id": edge_key,
                })
                self._expand_entity(session, "campaign", campaign.id, nodes, edges, seen, depth - 1)

        elif entity_type == "malware":
            malware = session.query(Malware).get(entity_id)
            if not malware:
                return
            nodes.append({
                "id": node_key, "type": "malware",
                "label": malware.name, "data": {
                    "family": malware.family, "malware_type": malware.type,
                }
            })
            # Relations IOCs
            for ioc in malware.iocs[:20]:  # Limiter
                edge_key = f"malware_ioc_{malware.id}_{ioc.id}"
                edges.append({
                    "source": node_key, "target": f"ioc_{ioc.id}",
                    "type": "indicates", "id": edge_key,
                })
                if f"ioc_{ioc.id}" not in seen:
                    seen.add(f"ioc_{ioc.id}")
                    nodes.append({
                        "id": f"ioc_{ioc.id}", "type": "ioc",
                        "label": f"{ioc.type.value}: {ioc.value[:40]}",
                        "data": {"ioc_type": ioc.type.value, "value": ioc.value},
                    })

        elif entity_type == "campaign":
            campaign = session.query(Campaign).get(entity_id)
            if not campaign:
                return
            nodes.append({
                "id": node_key, "type": "campaign",
                "label": campaign.name, "data": {
                    "status": campaign.status,
                    "targets": campaign.target_countries,
                }
            })

        elif entity_type == "vulnerability":
            vuln = session.query(Vulnerability).get(entity_id)
            if not vuln:
                return
            nodes.append({
                "id": node_key, "type": "vulnerability",
                "label": vuln.cve_id, "data": {
                    "cvss": vuln.cvss_v3_score,
                    "exploit": vuln.exploit_available,
                }
            })

    def _build_recent_graph(self, session, nodes, edges, seen, days: int = 7):
        """Construit un graphe des relations récentes."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        # Threat Actors récents avec leurs malwares
        recent_articles = (
            session.query(Article)
            .filter(Article.collected_at >= since)
            .filter(Article.severity.in_([SeverityLevel.CRITIQUE, SeverityLevel.HAUTE]))
            .limit(50)
            .all()
        )

        for article in recent_articles:
            for ta in article.threat_actors:
                ta_key = f"threat_actor_{ta.id}"
                if ta_key not in seen:
                    seen.add(ta_key)
                    nodes.append({
                        "id": ta_key, "type": "threat_actor",
                        "label": ta.name,
                        "data": {"origin": ta.origin_country},
                    })

                for malware in ta.malwares:
                    m_key = f"malware_{malware.id}"
                    if m_key not in seen:
                        seen.add(m_key)
                        nodes.append({
                            "id": m_key, "type": "malware",
                            "label": malware.name,
                            "data": {"type": malware.type},
                        })
                    edges.append({
                        "source": ta_key, "target": m_key,
                        "type": "uses",
                        "id": f"edge_{ta_key}_{m_key}",
                    })

    # ========================================================================
    # DÉTECTION DE TENDANCES
    # ========================================================================

    def detect_trends(self, session: Session, days: int = 30) -> Dict[str, Any]:
        """
        Détecte les tendances sur la période donnée.

        Returns:
            - Catégories en hausse/baisse
            - Acteurs les plus actifs
            - TTPs les plus utilisés
            - Technologies les plus ciblées
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)
        midpoint = datetime.now(timezone.utc) - timedelta(days=days // 2)

        # Articles par catégorie (1ère moitié vs 2ème moitié)
        first_half = (
            session.query(Article.source_category, func.count(Article.id))
            .filter(Article.collected_at >= since, Article.collected_at < midpoint)
            .group_by(Article.source_category)
            .all()
        )
        second_half = (
            session.query(Article.source_category, func.count(Article.id))
            .filter(Article.collected_at >= midpoint)
            .group_by(Article.source_category)
            .all()
        )

        first_dict = dict(first_half)
        second_dict = dict(second_half)
        all_cats = set(first_dict.keys()) | set(second_dict.keys())

        category_trends = {}
        for cat in all_cats:
            count1 = first_dict.get(cat, 0)
            count2 = second_dict.get(cat, 0)
            if count1 > 0:
                change = ((count2 - count1) / count1) * 100
            else:
                change = 100 if count2 > 0 else 0
            category_trends[cat] = {
                "previous": count1, "current": count2,
                "change_percent": round(change, 1),
                "trend": "↑" if change > 10 else ("↓" if change < -10 else "→"),
            }

        # Sévérités
        severity_counts = dict(
            session.query(Article.severity, func.count(Article.id))
            .filter(Article.collected_at >= since)
            .group_by(Article.severity)
            .all()
        )

        # Top threat actors
        top_actors = (
            session.query(
                ThreatActor.name,
                func.count(article_threat_actors.c.article_id).label("mentions")
            )
            .join(article_threat_actors, ThreatActor.id == article_threat_actors.c.threat_actor_id)
            .join(Article, Article.id == article_threat_actors.c.article_id)
            .filter(Article.collected_at >= since)
            .group_by(ThreatActor.name)
            .order_by(desc("mentions"))
            .limit(10)
            .all()
        )

        # Top malwares
        top_malwares = (
            session.query(
                Malware.name, Malware.type,
                func.count(article_malwares.c.article_id).label("mentions")
            )
            .join(article_malwares, Malware.id == article_malwares.c.malware_id)
            .join(Article, Article.id == article_malwares.c.article_id)
            .filter(Article.collected_at >= since)
            .group_by(Malware.name, Malware.type)
            .order_by(desc("mentions"))
            .limit(10)
            .all()
        )

        # Vulnérabilités les plus mentionnées
        top_vulns = (
            session.query(Vulnerability)
            .filter(Vulnerability.collected_at >= since)
            .order_by(desc(Vulnerability.cvss_v3_score))
            .limit(10)
            .all()
        )

        return {
            "period_days": days,
            "category_trends": category_trends,
            "severity_distribution": {str(k): v for k, v in severity_counts.items()},
            "top_threat_actors": [
                {"name": name, "mentions": count} for name, count in top_actors
            ],
            "top_malwares": [
                {"name": name, "type": mtype, "mentions": count}
                for name, mtype, count in top_malwares
            ],
            "top_vulnerabilities": [
                {
                    "cve_id": v.cve_id, "cvss": v.cvss_v3_score,
                    "exploit": v.exploit_available, "severity": str(v.severity),
                }
                for v in top_vulns
            ],
        }

    # ========================================================================
    # SCORING DE MENACES
    # ========================================================================

    def compute_threat_score(self, session: Session) -> Dict[str, Any]:
        """
        Calcule un score de menace global basé sur les technologies et zones surveillées.
        """
        watched_tech = self.config.get_watched_technologies()
        watched_regions = self.config.get("watched_regions", [])
        watched_sectors = self.config.get("watched_sectors", [])

        since = datetime.now(timezone.utc) - timedelta(days=7)

        # Vulnérabilités critiques sur technologies surveillées
        critical_vulns = session.query(Vulnerability).filter(
            Vulnerability.collected_at >= since,
            or_(
                Vulnerability.severity == SeverityLevel.CRITIQUE,
                Vulnerability.cvss_v3_score >= 9.0,
            )
        ).all()

        tech_alerts = []
        for vuln in critical_vulns:
            vuln_text = f"{vuln.title or ''} {vuln.description or ''}".lower()
            for tech in watched_tech:
                if tech.lower() in vuln_text:
                    tech_alerts.append({
                        "technology": tech,
                        "cve_id": vuln.cve_id,
                        "cvss": vuln.cvss_v3_score,
                        "exploit": vuln.exploit_available,
                    })

        # Articles critiques ciblant nos zones
        critical_articles = (
            session.query(Article)
            .filter(
                Article.collected_at >= since,
                Article.severity.in_([SeverityLevel.CRITIQUE, SeverityLevel.HAUTE])
            )
            .all()
        )

        region_alerts = []
        for article in critical_articles:
            article_text = f"{article.title} {article.content or ''}".lower()
            for region in watched_regions:
                if region.lower() in article_text:
                    region_alerts.append({
                        "region": region,
                        "article_title": article.title,
                        "severity": str(article.severity),
                    })

        # Score global (0-100)
        score = 0
        score += min(40, len(tech_alerts) * 10)  # Max 40 points pour les vulns tech
        score += min(30, len(region_alerts) * 5)  # Max 30 points pour les alertes régionales

        # Bonus si exploits actifs
        active_exploits = sum(1 for a in tech_alerts if a.get("exploit"))
        score += min(30, active_exploits * 15)

        return {
            "global_score": min(100, score),
            "level": self._score_to_level(score),
            "technology_alerts": tech_alerts[:20],
            "region_alerts": region_alerts[:20],
            "active_exploits": active_exploits,
            "recommendations": self._generate_recommendations(tech_alerts, region_alerts),
        }

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 80:
            return "CRITIQUE"
        if score >= 60:
            return "ÉLEVÉ"
        if score >= 40:
            return "MODÉRÉ"
        if score >= 20:
            return "FAIBLE"
        return "MINIMAL"

    @staticmethod
    def _generate_recommendations(tech_alerts: list, region_alerts: list) -> List[str]:
        """Génère des recommandations défensives basées sur les alertes."""
        recommendations = []

        if tech_alerts:
            techs_affected = set(a["technology"] for a in tech_alerts)
            recommendations.append(
                f"🔴 Patcher en priorité: vulnérabilités critiques détectées sur "
                f"{', '.join(techs_affected)}"
            )

            exploitable = [a for a in tech_alerts if a.get("exploit")]
            if exploitable:
                cves = ", ".join(a["cve_id"] for a in exploitable[:5])
                recommendations.append(
                    f"⚠️ Exploits actifs disponibles: {cves} - Patcher IMMÉDIATEMENT"
                )

        if region_alerts:
            recommendations.append(
                "🌍 Activité de menaces accrue dans vos zones géographiques surveillées. "
                "Renforcer la surveillance réseau."
            )

        if not recommendations:
            recommendations.append(
                "✅ Pas de menace critique détectée sur vos technologies et zones surveillées."
            )

        return recommendations

    # ========================================================================
    # TIMELINE D'ÉVÉNEMENTS
    # ========================================================================

    def get_timeline(self, session: Session, days: int = 7,
                     severity_filter: List[str] = None) -> List[Dict]:
        """Retourne une timeline d'événements corrélés."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        query = session.query(Article).filter(Article.collected_at >= since)

        if severity_filter:
            query = query.filter(Article.severity.in_(severity_filter))

        articles = query.order_by(desc(Article.published_at)).limit(200).all()

        timeline = []
        for article in articles:
            event = {
                "id": article.id,
                "date": (article.published_at or article.collected_at).isoformat(),
                "title": article.title,
                "summary": article.summary_fr or article.summary or "",
                "severity": str(article.severity) if article.severity else "INFO",
                "source": article.source_name,
                "category": article.source_category,
                "url": article.url,
                "tags": [t.name for t in article.tags],
                "ioc_count": len(article.iocs),
                "threat_actors": [ta.name for ta in article.threat_actors],
                "vulnerabilities": [v.cve_id for v in article.vulnerabilities],
            }
            timeline.append(event)

        return timeline

    # ========================================================================
    # HEATMAP MITRE ATT&CK
    # ========================================================================

    def get_mitre_heatmap(self, session: Session, days: int = 30) -> Dict[str, Any]:
        """
        Génère les données pour une heatmap MITRE ATT&CK.

        Returns:
            Matrice tactic x technique avec comptages.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)

        ttps = (
            session.query(TTP)
            .join(threat_actor_ttps, TTP.id == threat_actor_ttps.c.ttp_id)
            .join(ThreatActor, ThreatActor.id == threat_actor_ttps.c.threat_actor_id)
            .all()
        )

        # Grouper par tactic
        tactic_data = defaultdict(list)
        for ttp in ttps:
            tactics = ttp.tactic.split(", ") if ttp.tactic else ["unknown"]
            for tactic in tactics:
                tactic_data[tactic].append({
                    "id": ttp.mitre_id,
                    "name": ttp.name,
                    "count": len(ttp.threat_actors),
                })

        # Organiser les tactiques dans l'ordre MITRE
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]

        heatmap = {}
        for tactic in tactic_order:
            if tactic in tactic_data:
                heatmap[tactic] = sorted(
                    tactic_data[tactic],
                    key=lambda x: x["count"],
                    reverse=True,
                )

        return {
            "period_days": days,
            "heatmap": heatmap,
            "total_techniques": len(ttps),
            "total_tactics": len(heatmap),
        }

    # ========================================================================
    # EXPORT STIX 2.1
    # ========================================================================

    def export_stix_bundle(self, session: Session, days: int = 7) -> Dict:
        """Exporte les données en format STIX 2.1."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        bundle = {
            "type": "bundle",
            "id": f"bundle--cti-sentinel-{datetime.now().strftime('%Y%m%d')}",
            "objects": [],
        }

        # Identity (source)
        identity = {
            "type": "identity",
            "id": "identity--cti-sentinel",
            "name": "CTI Sentinel",
            "identity_class": "system",
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "modified": datetime.now(timezone.utc).isoformat() + "Z",
        }
        bundle["objects"].append(identity)

        # Indicators (IOCs)
        iocs = session.query(IOC).filter(
            IOC.first_seen >= since, IOC.active == True
        ).limit(500).all()

        for ioc in iocs:
            stix_type = self._ioc_to_stix_pattern(ioc)
            if stix_type:
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--ioc-{ioc.id}",
                    "name": f"{ioc.type.value}: {ioc.value}",
                    "pattern": stix_type,
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen.isoformat() + "Z",
                    "created": ioc.first_seen.isoformat() + "Z",
                    "modified": ioc.last_seen.isoformat() + "Z",
                }
                bundle["objects"].append(indicator)

        # Threat Actors
        actors = session.query(ThreatActor).filter(ThreatActor.active == True).all()
        for actor in actors:
            ta_stix = {
                "type": "threat-actor",
                "id": f"threat-actor--{actor.id}",
                "name": actor.name,
                "description": actor.description or "",
                "aliases": actor.aliases or [],
                "created": actor.collected_at.isoformat() + "Z",
                "modified": actor.collected_at.isoformat() + "Z",
            }
            if actor.origin_country:
                ta_stix["country"] = actor.origin_country
            bundle["objects"].append(ta_stix)

        # Vulnerabilities
        vulns = session.query(Vulnerability).filter(
            Vulnerability.collected_at >= since
        ).limit(200).all()

        for vuln in vulns:
            vuln_stix = {
                "type": "vulnerability",
                "id": f"vulnerability--{vuln.cve_id.lower()}",
                "name": vuln.cve_id,
                "description": vuln.description or "",
                "created": (vuln.published_date or vuln.collected_at).isoformat() + "Z",
                "modified": (vuln.modified_date or vuln.collected_at).isoformat() + "Z",
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": vuln.cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
                    }
                ],
            }
            bundle["objects"].append(vuln_stix)

        return bundle

    @staticmethod
    def _ioc_to_stix_pattern(ioc: IOC) -> Optional[str]:
        """Convertit un IOC en pattern STIX."""
        type_mapping = {
            "ipv4": f"[ipv4-addr:value = '{ioc.value}']",
            "ipv6": f"[ipv6-addr:value = '{ioc.value}']",
            "domain": f"[domain-name:value = '{ioc.value}']",
            "url": f"[url:value = '{ioc.value}']",
            "md5": f"[file:hashes.MD5 = '{ioc.value}']",
            "sha1": f"[file:hashes.'SHA-1' = '{ioc.value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{ioc.value}']",
            "email": f"[email-addr:value = '{ioc.value}']",
        }
        return type_mapping.get(ioc.type.value)
