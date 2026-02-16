"""
API REST - Interface FastAPI pour CTI Sentinel.
Permet l'interrogation programmatique de l'outil.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from cti_sentinel.config import ConfigLoader
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.database.models import (
    Article, Vulnerability, IOC, ThreatActor, Malware,
    Campaign, TTP, SeverityLevel, Flashcard, QuizResult,
)
from cti_sentinel.collectors.engine import CollectionEngine
from cti_sentinel.processor.engine import ProcessingEngine
from cti_sentinel.analyzer.correlation import CorrelationEngine

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

config = ConfigLoader()
db = DatabaseManager(config)
db.create_tables()

collection_engine = CollectionEngine(config, db)
processing_engine = ProcessingEngine(config, db)
correlation_engine = CorrelationEngine(config, db)

# ============================================================================
# Application FastAPI
# ============================================================================

app = FastAPI(
    title="CTI Sentinel API",
    description="API REST pour l'outil de veille CTI/Géopolitique",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
cors_origins = config.get("api.cors_origins", ["http://localhost:8501"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Modèles Pydantic
# ============================================================================

class ArticleResponse(BaseModel):
    id: int
    title: str
    summary_fr: Optional[str] = None
    url: str
    source_name: str
    source_category: str
    severity: Optional[str] = None
    published_at: Optional[datetime] = None
    collected_at: datetime
    categories: Optional[list] = None
    tags: List[str] = []
    ioc_count: int = 0
    cve_count: int = 0
    threat_actors: List[str] = []
    read: bool = False
    starred: bool = False


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    epss_score: Optional[float] = None
    exploit_available: bool = False
    exploit_in_wild: bool = False
    cisa_kev: bool = False
    published_date: Optional[datetime] = None


class IOCResponse(BaseModel):
    id: int
    type: str
    value: str
    context: Optional[str] = None
    confidence: Optional[int] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    active: bool = True


class ThreatActorResponse(BaseModel):
    id: int
    name: str
    aliases: Optional[list] = None
    type: Optional[str] = None
    description: Optional[str] = None
    origin_country: Optional[str] = None
    target_sectors: Optional[list] = None
    mitre_id: Optional[str] = None
    active: bool = True


class StatsResponse(BaseModel):
    articles: dict
    vulnerabilities: dict
    iocs: dict
    threat_actors: dict
    malwares: dict
    campaigns: dict


class CollectRequest(BaseModel):
    categories: Optional[List[str]] = None
    source: Optional[str] = None


class SearchRequest(BaseModel):
    query: str
    ioc_type: Optional[str] = None
    limit: int = 50


class FlashcardResponse(BaseModel):
    id: int
    category: str
    question: str
    answer: str
    difficulty: str


# ============================================================================
# ENDPOINTS - Dashboard & Stats
# ============================================================================

@app.get("/api/stats", response_model=StatsResponse, tags=["Dashboard"])
async def get_stats():
    """Statistiques globales pour le dashboard."""
    with db.get_session() as session:
        return db.get_dashboard_stats(session)


@app.get("/api/stats/articles", tags=["Dashboard"])
async def get_article_stats(days: int = Query(default=7, ge=1, le=365)):
    """Statistiques détaillées sur les articles."""
    with db.get_session() as session:
        return db.get_article_stats(session, days=days)


@app.get("/api/threat-score", tags=["Dashboard"])
async def get_threat_score():
    """Score de menace global basé sur les technologies surveillées."""
    with db.get_session() as session:
        return correlation_engine.compute_threat_score(session)


# ============================================================================
# ENDPOINTS - Articles
# ============================================================================

@app.get("/api/articles", response_model=List[ArticleResponse], tags=["Articles"])
async def list_articles(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = None,
    source: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    starred: Optional[bool] = None,
    unread: Optional[bool] = None,
):
    """Liste les articles avec filtres avancés."""
    with db.get_session() as session:
        articles = db.get_articles(
            session,
            limit=limit, offset=offset,
            severity=severity, source=source, category=category,
            search=search, date_from=date_from, date_to=date_to,
            starred=starred, unread_only=unread or False,
        )
        return [_article_to_response(a) for a in articles]


@app.get("/api/articles/{article_id}", tags=["Articles"])
async def get_article(article_id: int):
    """Détail complet d'un article."""
    with db.get_session() as session:
        article = session.query(Article).get(article_id)
        if not article:
            raise HTTPException(404, "Article non trouvé")

        result = _article_to_response(article)
        result_dict = result.model_dump()
        result_dict["content"] = article.content
        result_dict["summary_fr"] = article.summary_fr
        result_dict["iocs"] = [
            {"type": ioc.type.value, "value": ioc.value, "confidence": ioc.confidence}
            for ioc in article.iocs
        ]
        result_dict["vulnerabilities"] = [
            {"cve_id": v.cve_id, "cvss": v.cvss_v3_score}
            for v in article.vulnerabilities
        ]
        result_dict["malwares"] = [
            {"name": m.name, "family": m.family}
            for m in article.malwares
        ]
        return result_dict


@app.patch("/api/articles/{article_id}/read", tags=["Articles"])
async def mark_article_read(article_id: int):
    """Marque un article comme lu."""
    with db.get_session() as session:
        article = session.query(Article).get(article_id)
        if not article:
            raise HTTPException(404, "Article non trouvé")
        article.read = True
        return {"status": "ok"}


@app.patch("/api/articles/{article_id}/star", tags=["Articles"])
async def toggle_star(article_id: int):
    """Toggle le statut favori d'un article."""
    with db.get_session() as session:
        article = session.query(Article).get(article_id)
        if not article:
            raise HTTPException(404, "Article non trouvé")
        article.starred = not article.starred
        return {"starred": article.starred}


# ============================================================================
# ENDPOINTS - Vulnérabilités
# ============================================================================

@app.get("/api/vulnerabilities", response_model=List[VulnerabilityResponse], tags=["Vulnérabilités"])
async def list_vulnerabilities(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[str] = None,
    exploit_only: bool = False,
    days: int = Query(default=30, ge=1, le=365),
):
    """Liste les vulnérabilités."""
    with db.get_session() as session:
        query = session.query(Vulnerability)

        since = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(Vulnerability.collected_at >= since)

        if severity:
            query = query.filter(Vulnerability.severity == severity)
        if exploit_only:
            query = query.filter(Vulnerability.exploit_available == True)

        vulns = query.order_by(Vulnerability.cvss_v3_score.desc()).limit(limit).all()

        return [
            VulnerabilityResponse(
                id=v.id, cve_id=v.cve_id, title=v.title,
                description=v.description,
                severity=str(v.severity) if v.severity else None,
                cvss_v3_score=v.cvss_v3_score,
                cvss_v3_vector=v.cvss_v3_vector,
                epss_score=v.epss_score,
                exploit_available=v.exploit_available,
                exploit_in_wild=v.exploit_in_wild,
                cisa_kev=v.cisa_kev,
                published_date=v.published_date,
            )
            for v in vulns
        ]


@app.get("/api/vulnerabilities/{cve_id}", tags=["Vulnérabilités"])
async def get_vulnerability(cve_id: str):
    """Détail d'une vulnérabilité par CVE ID."""
    with db.get_session() as session:
        vuln = session.query(Vulnerability).filter_by(cve_id=cve_id.upper()).first()
        if not vuln:
            raise HTTPException(404, f"CVE {cve_id} non trouvée")
        return {
            "cve_id": vuln.cve_id, "title": vuln.title,
            "description": vuln.description,
            "description_fr": vuln.description_fr,
            "cvss_v3_score": vuln.cvss_v3_score,
            "cvss_v3_vector": vuln.cvss_v3_vector,
            "epss_score": vuln.epss_score,
            "epss_percentile": vuln.epss_percentile,
            "exploit_available": vuln.exploit_available,
            "exploit_in_wild": vuln.exploit_in_wild,
            "cisa_kev": vuln.cisa_kev,
            "cwe_ids": vuln.cwe_ids,
            "references": vuln.references,
            "products": [
                {"vendor": p.vendor, "product": p.product, "version": p.version}
                for p in vuln.products
            ],
            "related_articles": [
                {"id": a.id, "title": a.title} for a in vuln.articles[:10]
            ],
        }


# ============================================================================
# ENDPOINTS - IOCs
# ============================================================================

@app.get("/api/iocs", response_model=List[IOCResponse], tags=["IOCs"])
async def list_iocs(
    limit: int = Query(default=50, ge=1, le=500),
    ioc_type: Optional[str] = None,
    active_only: bool = True,
    days: int = Query(default=7, ge=1, le=365),
):
    """Liste les IOCs."""
    with db.get_session() as session:
        query = session.query(IOC)

        since = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(IOC.first_seen >= since)

        if ioc_type:
            query = query.filter(IOC.type == ioc_type)
        if active_only:
            query = query.filter(IOC.active == True)

        iocs = query.order_by(IOC.last_seen.desc()).limit(limit).all()

        return [
            IOCResponse(
                id=i.id, type=i.type.value, value=i.value,
                context=i.context, confidence=i.confidence,
                severity=str(i.severity) if i.severity else None,
                source=i.source,
                first_seen=i.first_seen, last_seen=i.last_seen,
                active=i.active,
            )
            for i in iocs
        ]


@app.get("/api/iocs/search", tags=["IOCs"])
async def search_ioc(value: str = Query(min_length=3)):
    """Recherche un IOC par valeur."""
    with db.get_session() as session:
        results = db.search_ioc(session, value)
        return [
            {
                "id": i.id, "type": i.type.value, "value": i.value,
                "context": i.context, "confidence": i.confidence,
                "first_seen": i.first_seen.isoformat(),
                "last_seen": i.last_seen.isoformat(),
                "related_articles": [a.title for a in i.articles[:5]],
            }
            for i in results
        ]


# ============================================================================
# ENDPOINTS - Threat Actors
# ============================================================================

@app.get("/api/threat-actors", response_model=List[ThreatActorResponse], tags=["Threat Actors"])
async def list_threat_actors(
    limit: int = Query(default=50, ge=1, le=200),
    actor_type: Optional[str] = None,
    country: Optional[str] = None,
):
    """Liste les groupes de menaces."""
    with db.get_session() as session:
        query = session.query(ThreatActor)
        if actor_type:
            query = query.filter(ThreatActor.type == actor_type)
        if country:
            query = query.filter(ThreatActor.origin_country.ilike(f"%{country}%"))

        actors = query.order_by(ThreatActor.name).limit(limit).all()
        return [
            ThreatActorResponse(
                id=a.id, name=a.name, aliases=a.aliases,
                type=str(a.type) if a.type else None,
                description=a.description,
                origin_country=a.origin_country,
                target_sectors=a.target_sectors,
                mitre_id=a.mitre_id, active=a.active,
            )
            for a in actors
        ]


@app.get("/api/threat-actors/{actor_id}", tags=["Threat Actors"])
async def get_threat_actor(actor_id: int):
    """Profil complet d'un threat actor."""
    with db.get_session() as session:
        actor = session.query(ThreatActor).get(actor_id)
        if not actor:
            raise HTTPException(404, "Threat actor non trouvé")
        return {
            "id": actor.id, "name": actor.name,
            "aliases": actor.aliases, "type": str(actor.type),
            "description": actor.description,
            "description_fr": actor.description_fr,
            "origin_country": actor.origin_country,
            "target_sectors": actor.target_sectors,
            "target_countries": actor.target_countries,
            "motivation": actor.motivation,
            "mitre_id": actor.mitre_id,
            "malwares": [{"name": m.name, "type": m.type} for m in actor.malwares],
            "ttps": [{"id": t.mitre_id, "name": t.name, "tactic": t.tactic} for t in actor.ttps],
            "campaigns": [{"name": c.name, "status": c.status} for c in actor.campaigns],
            "recent_articles": [
                {"id": a.id, "title": a.title, "date": str(a.published_at)}
                for a in actor.articles[:10]
            ],
        }


# ============================================================================
# ENDPOINTS - Analyse & Corrélation
# ============================================================================

@app.get("/api/timeline", tags=["Analyse"])
async def get_timeline(
    days: int = Query(default=7, ge=1, le=90),
    severity: Optional[str] = None,
):
    """Timeline interactive des événements."""
    severity_filter = [severity] if severity else None
    with db.get_session() as session:
        return correlation_engine.get_timeline(
            session, days=days, severity_filter=severity_filter
        )


@app.get("/api/trends", tags=["Analyse"])
async def get_trends(days: int = Query(default=30, ge=7, le=365)):
    """Tendances et patterns détectés."""
    with db.get_session() as session:
        return correlation_engine.detect_trends(session, days=days)


@app.get("/api/graph", tags=["Analyse"])
async def get_entity_graph(
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    depth: int = Query(default=2, ge=1, le=4),
):
    """Graphe de relations entre entités."""
    with db.get_session() as session:
        return correlation_engine.build_entity_graph(
            session, entity_type=entity_type, entity_id=entity_id, depth=depth
        )


@app.get("/api/mitre-heatmap", tags=["Analyse"])
async def get_mitre_heatmap(days: int = Query(default=30, ge=7, le=365)):
    """Données pour la heatmap MITRE ATT&CK."""
    with db.get_session() as session:
        return correlation_engine.get_mitre_heatmap(session, days=days)


# ============================================================================
# ENDPOINTS - Collecte & Traitement
# ============================================================================

@app.post("/api/collect", tags=["Opérations"])
async def trigger_collection(request: CollectRequest, background_tasks: BackgroundTasks):
    """Lance une collecte manuellement."""
    async def _collect():
        if request.source:
            await collection_engine.collect_source(request.source)
        else:
            await collection_engine.collect_all(categories=request.categories)

    background_tasks.add_task(asyncio.ensure_future, _collect())
    return {"status": "Collection lancée en arrière-plan"}


@app.post("/api/process", tags=["Opérations"])
async def trigger_processing(
    limit: int = Query(default=100, ge=1, le=500),
    background_tasks: BackgroundTasks = None,
):
    """Lance le traitement des articles en attente."""
    async def _process():
        await processing_engine.process_pending_articles(limit=limit)

    background_tasks.add_task(asyncio.ensure_future, _process())
    return {"status": "Traitement lancé en arrière-plan"}


@app.get("/api/sources", tags=["Opérations"])
async def list_sources():
    """Liste toutes les sources de collecte configurées."""
    return collection_engine.list_sources()


# ============================================================================
# ENDPOINTS - Export
# ============================================================================

@app.get("/api/export/stix", tags=["Export"])
async def export_stix(days: int = Query(default=7, ge=1, le=90)):
    """Exporte les données en format STIX 2.1."""
    with db.get_session() as session:
        return correlation_engine.export_stix_bundle(session, days=days)


@app.get("/api/export/iocs", tags=["Export"])
async def export_iocs(
    format: str = Query(default="json", regex="^(json|csv|txt)$"),
    days: int = Query(default=7, ge=1, le=90),
    ioc_type: Optional[str] = None,
):
    """Exporte les IOCs dans le format demandé."""
    with db.get_session() as session:
        query = session.query(IOC).filter(
            IOC.active == True,
            IOC.first_seen >= datetime.now(timezone.utc) - timedelta(days=days),
        )
        if ioc_type:
            query = query.filter(IOC.type == ioc_type)

        iocs = query.all()

        if format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["type", "value", "confidence", "first_seen", "last_seen", "source"])
            for ioc in iocs:
                writer.writerow([
                    ioc.type.value, ioc.value, ioc.confidence,
                    ioc.first_seen.isoformat(), ioc.last_seen.isoformat(), ioc.source,
                ])
            return JSONResponse(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=iocs.csv"},
            )
        elif format == "txt":
            lines = [ioc.value for ioc in iocs]
            return JSONResponse(
                content="\n".join(lines),
                media_type="text/plain",
            )
        else:
            return [
                {
                    "type": i.type.value, "value": i.value,
                    "confidence": i.confidence, "source": i.source,
                    "first_seen": i.first_seen.isoformat(),
                    "last_seen": i.last_seen.isoformat(),
                }
                for i in iocs
            ]


# ============================================================================
# ENDPOINTS - Apprentissage
# ============================================================================

@app.get("/api/flashcards", response_model=List[FlashcardResponse], tags=["Apprentissage"])
async def get_flashcards(
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    limit: int = Query(default=10, ge=1, le=50),
):
    """Récupère des flashcards pour l'apprentissage."""
    with db.get_session() as session:
        query = session.query(Flashcard)
        if category:
            query = query.filter(Flashcard.category == category)
        if difficulty:
            query = query.filter(Flashcard.difficulty == difficulty)

        cards = query.order_by(Flashcard.times_shown.asc()).limit(limit).all()
        return [
            FlashcardResponse(
                id=c.id, category=c.category,
                question=c.question, answer=c.answer,
                difficulty=c.difficulty,
            )
            for c in cards
        ]


@app.post("/api/flashcards/{card_id}/answer", tags=["Apprentissage"])
async def answer_flashcard(card_id: int, correct: bool):
    """Enregistre une réponse à une flashcard."""
    with db.get_session() as session:
        card = session.query(Flashcard).get(card_id)
        if not card:
            raise HTTPException(404, "Flashcard non trouvée")
        card.times_shown += 1
        if correct:
            card.times_correct += 1
        card.last_shown = datetime.now(timezone.utc)
        return {
            "success_rate": round(
                (card.times_correct / card.times_shown * 100) if card.times_shown > 0 else 0, 1
            )
        }


# ============================================================================
# Helpers
# ============================================================================

def _article_to_response(article: Article) -> ArticleResponse:
    """Convertit un article DB en réponse API."""
    return ArticleResponse(
        id=article.id,
        title=article.title,
        summary_fr=article.summary_fr,
        url=article.url,
        source_name=article.source_name,
        source_category=article.source_category,
        severity=str(article.severity) if article.severity else None,
        published_at=article.published_at,
        collected_at=article.collected_at,
        categories=article.categories,
        tags=[t.name for t in article.tags],
        ioc_count=len(article.iocs),
        cve_count=len(article.vulnerabilities),
        threat_actors=[ta.name for ta in article.threat_actors],
        read=article.read,
        starred=article.starred,
    )


# ============================================================================
# Point d'entrée
# ============================================================================

def start_api():
    """Démarre le serveur API."""
    import uvicorn
    host = config.get("api.host", "0.0.0.0")
    port = config.get("api.port", 8000)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
