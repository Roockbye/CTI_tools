"""
Database Manager - Gestion des connexions et opérations sur la base de données.
"""

import shutil
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Type, TypeVar, Any
from contextlib import contextmanager

from sqlalchemy import create_engine, text, func, or_, and_, desc
from sqlalchemy.orm import sessionmaker, Session

from cti_sentinel.database.models import (
    Base, Article, Vulnerability, IOC, ThreatActor, Malware,
    Campaign, TTP, Tag, Product, CollectionLog, AlertLog,
    Flashcard, QuizResult, ArticleStatus, SeverityLevel, IOCType
)
from cti_sentinel.config import ConfigLoader

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=Base)


class DatabaseManager:
    """Gestionnaire central de la base de données."""

    def __init__(self, config: ConfigLoader = None):
        self.config = config or ConfigLoader()
        self._engine = None
        self._session_factory = None
        self._init_engine()

    def _init_engine(self):
        """Initialise le moteur SQLAlchemy."""
        db_type = self.config.get("database.type", "sqlite")

        if db_type == "sqlite":
            db_path = self.config.get("database.sqlite.path", "./data/cti_sentinel.db")
            project_root = Path(__file__).parent.parent.parent
            full_path = project_root / db_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            journal_mode = self.config.get("database.sqlite.journal_mode", "WAL")
            self._engine = create_engine(
                f"sqlite:///{full_path}",
                echo=self.config.get("general.debug", False),
                connect_args={"check_same_thread": False},
                pool_pre_ping=True,
            )
            # Activer WAL mode pour meilleures performances concurrentes
            with self._engine.connect() as conn:
                conn.execute(text(f"PRAGMA journal_mode={journal_mode}"))
                conn.execute(text("PRAGMA foreign_keys=ON"))
                conn.commit()
        else:
            # PostgreSQL
            pg = self.config.get("database.postgresql", {})
            url = f"postgresql://{pg.get('user', 'cti_user')}:{pg.get('password', '')}@" \
                  f"{pg.get('host', 'localhost')}:{pg.get('port', 5432)}/{pg.get('database', 'cti_sentinel')}"
            self._engine = create_engine(url, echo=self.config.get("general.debug", False), pool_pre_ping=True)

        self._session_factory = sessionmaker(bind=self._engine)
        logger.info("Base de données initialisée (%s)", db_type)

    def create_tables(self):
        """Crée toutes les tables si elles n'existent pas."""
        Base.metadata.create_all(self._engine)
        logger.info("Tables créées avec succès")

    def drop_tables(self):
        """Supprime toutes les tables (ATTENTION !)."""
        Base.metadata.drop_all(self._engine)
        logger.warning("Toutes les tables ont été supprimées")

    @contextmanager
    def get_session(self) -> Session:
        """Fournit une session avec gestion automatique des transactions."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ========================================================================
    # ARTICLES
    # ========================================================================

    def add_article(self, session: Session, **kwargs) -> Optional[Article]:
        """Ajoute un article avec déduplication automatique."""
        title = kwargs.get("title", "")
        url = kwargs.get("url", "")
        content = kwargs.get("content", "")

        content_hash = Article.compute_content_hash(title, url, content)

        # Vérifier doublon
        existing = session.query(Article).filter_by(content_hash=content_hash).first()
        if existing:
            logger.debug("Article en double détecté: %s", title[:80])
            return None

        article = Article(
            content_hash=content_hash,
            url_hash=Article.compute_content_hash("", url),
            **kwargs
        )
        session.add(article)
        session.flush()
        return article

    def get_articles(
        self, session: Session,
        limit: int = 50,
        offset: int = 0,
        severity: str = None,
        source: str = None,
        category: str = None,
        search: str = None,
        date_from: datetime = None,
        date_to: datetime = None,
        status: str = None,
        starred: bool = None,
        unread_only: bool = False,
    ) -> List[Article]:
        """Récupère des articles avec filtres avancés."""
        query = session.query(Article)

        if severity:
            query = query.filter(Article.severity == severity)
        if source:
            query = query.filter(Article.source_name == source)
        if category:
            query = query.filter(Article.source_category == category)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Article.title.ilike(search_term),
                    Article.content.ilike(search_term),
                    Article.summary_fr.ilike(search_term),
                )
            )
        if date_from:
            query = query.filter(Article.published_at >= date_from)
        if date_to:
            query = query.filter(Article.published_at <= date_to)
        if status:
            query = query.filter(Article.status == status)
        if starred is not None:
            query = query.filter(Article.starred == starred)
        if unread_only:
            query = query.filter(Article.read == False)

        return query.order_by(desc(Article.published_at)).offset(offset).limit(limit).all()

    def count_articles(self, session: Session, **filters) -> int:
        """Compte le nombre d'articles correspondant aux filtres."""
        query = session.query(func.count(Article.id))
        if filters.get("severity"):
            query = query.filter(Article.severity == filters["severity"])
        if filters.get("date_from"):
            query = query.filter(Article.published_at >= filters["date_from"])
        return query.scalar()

    def get_article_stats(self, session: Session, days: int = 7) -> dict:
        """Statistiques sur les articles des N derniers jours."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        total = session.query(func.count(Article.id)).filter(Article.collected_at >= since).scalar()
        by_severity = dict(
            session.query(Article.severity, func.count(Article.id))
            .filter(Article.collected_at >= since)
            .group_by(Article.severity)
            .all()
        )
        by_source = dict(
            session.query(Article.source_name, func.count(Article.id))
            .filter(Article.collected_at >= since)
            .group_by(Article.source_name)
            .all()
        )
        by_category = dict(
            session.query(Article.source_category, func.count(Article.id))
            .filter(Article.collected_at >= since)
            .group_by(Article.source_category)
            .all()
        )

        return {
            "total": total,
            "by_severity": by_severity,
            "by_source": by_source,
            "by_category": by_category,
            "period_days": days,
        }

    # ========================================================================
    # VULNÉRABILITÉS
    # ========================================================================

    def upsert_vulnerability(self, session: Session, cve_id: str, **kwargs) -> Vulnerability:
        """Insère ou met à jour une vulnérabilité."""
        vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
        if vuln:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(vuln, key, value)
            vuln.modified_date = datetime.now(timezone.utc)
        else:
            vuln = Vulnerability(cve_id=cve_id, **kwargs)
            session.add(vuln)
        session.flush()
        return vuln

    def get_critical_vulns(self, session: Session, days: int = 7) -> List[Vulnerability]:
        """Récupère les vulnérabilités critiques récentes."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        return (
            session.query(Vulnerability)
            .filter(
                Vulnerability.collected_at >= since,
                or_(
                    Vulnerability.severity == SeverityLevel.CRITIQUE,
                    Vulnerability.cvss_v3_score >= 9.0,
                    Vulnerability.exploit_in_wild == True,
                )
            )
            .order_by(desc(Vulnerability.cvss_v3_score))
            .all()
        )

    # ========================================================================
    # IOCs
    # ========================================================================

    def add_ioc(self, session: Session, ioc_type: str, value: str, **kwargs) -> Optional[IOC]:
        """Ajoute ou met à jour un IOC."""
        try:
            ioc_enum = IOCType(ioc_type)
        except ValueError:
            logger.warning("Type IOC inconnu: %s", ioc_type)
            return None

        existing = session.query(IOC).filter_by(type=ioc_enum, value=value).first()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if kwargs.get("context"):
                existing.context = kwargs["context"]
            return existing

        ioc = IOC(type=ioc_enum, value=value, **kwargs)
        session.add(ioc)
        session.flush()
        return ioc

    def search_ioc(self, session: Session, value: str) -> List[IOC]:
        """Recherche un IOC par valeur (partielle)."""
        return session.query(IOC).filter(IOC.value.ilike(f"%{value}%")).all()

    # ========================================================================
    # THREAT ACTORS
    # ========================================================================

    def upsert_threat_actor(self, session: Session, name: str, **kwargs) -> ThreatActor:
        """Insère ou met à jour un threat actor."""
        ta = session.query(ThreatActor).filter_by(name=name).first()
        if ta:
            for key, value in kwargs.items():
                if value is not None:
                    setattr(ta, key, value)
        else:
            ta = ThreatActor(name=name, **kwargs)
            session.add(ta)
        session.flush()
        return ta

    # ========================================================================
    # ARTICLES - Requêtes avancées
    # ========================================================================

    def get_articles(
        self, session: Session, *,
        limit: int = 50, offset: int = 0,
        severity: str = None, source: str = None, category: str = None,
        search: str = None, date_from=None, date_to=None,
        starred: bool = None, unread_only: bool = False,
    ) -> List[Article]:
        """Récupère les articles avec filtres avancés."""
        query = session.query(Article)

        if severity:
            try:
                sev_enum = SeverityLevel(severity.upper()) if severity.upper() in [e.value for e in SeverityLevel] else None
                if sev_enum:
                    query = query.filter(Article.severity == sev_enum)
            except (ValueError, KeyError):
                pass

        if source:
            query = query.filter(Article.source_name.ilike(f"%{source}%"))
        if category:
            query = query.filter(Article.source_category == category)
        if search:
            query = query.filter(
                or_(
                    Article.title.ilike(f"%{search}%"),
                    Article.summary_fr.ilike(f"%{search}%"),
                    Article.content.ilike(f"%{search}%"),
                )
            )
        if date_from:
            query = query.filter(Article.collected_at >= date_from)
        if date_to:
            query = query.filter(Article.collected_at <= date_to)
        if starred is not None:
            query = query.filter(Article.starred == starred)
        if unread_only:
            query = query.filter(Article.read == False)

        return (
            query.order_by(desc(Article.collected_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

    def get_article_stats(self, session: Session, days: int = 7) -> dict:
        """Statistiques détaillées sur les articles."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Articles par source
        by_source = (
            session.query(Article.source_name, func.count(Article.id))
            .filter(Article.collected_at >= cutoff)
            .group_by(Article.source_name)
            .all()
        )

        # Articles par sévérité
        by_severity = (
            session.query(Article.severity, func.count(Article.id))
            .filter(Article.collected_at >= cutoff)
            .group_by(Article.severity)
            .all()
        )

        # Articles par jour
        return {
            "period_days": days,
            "by_source": [{"source": s, "count": c} for s, c in by_source],
            "by_severity": [{"severity": str(s) if s else "unknown", "count": c} for s, c in by_severity],
            "total": session.query(func.count(Article.id)).filter(Article.collected_at >= cutoff).scalar(),
        }

    # ========================================================================
    # TAGS
    # ========================================================================

    def get_or_create_tag(self, session: Session, name: str, **kwargs) -> Tag:
        """Récupère ou crée un tag."""
        tag = session.query(Tag).filter_by(name=name.lower()).first()
        if not tag:
            tag = Tag(name=name.lower(), **kwargs)
            session.add(tag)
            session.flush()
        return tag

    # ========================================================================
    # COLLECTION LOGS
    # ========================================================================

    def log_collection(self, session: Session, **kwargs) -> CollectionLog:
        """Enregistre un log de collecte."""
        log = CollectionLog(**kwargs)
        session.add(log)
        session.flush()
        return log

    # ========================================================================
    # BACKUP & MAINTENANCE
    # ========================================================================

    def backup(self) -> str:
        """Crée une sauvegarde de la base de données."""
        db_type = self.config.get("database.type", "sqlite")
        if db_type != "sqlite":
            logger.warning("Backup automatique disponible uniquement pour SQLite")
            return ""

        db_path = self.config.get("database.sqlite.path", "./data/cti_sentinel.db")
        project_root = Path(__file__).parent.parent.parent
        full_path = project_root / db_path

        backup_dir = project_root / self.config.get("database.backup.path", "./data/backups")
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"cti_sentinel_backup_{timestamp}.db"

        shutil.copy2(full_path, backup_path)
        logger.info("Backup créé: %s", backup_path)
        return str(backup_path)

    def cleanup_old_data(self, retention_days: int = None):
        """Supprime les données plus anciennes que la rétention configurée."""
        if retention_days is None:
            retention_days = self.config.get("scheduler.cleanup.retention_days", 90)

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        with self.get_session() as session:
            # Supprimer les anciens articles non favoris
            deleted = (
                session.query(Article)
                .filter(Article.collected_at < cutoff, Article.starred == False)
                .delete(synchronize_session=False)
            )
            # Supprimer les anciens logs
            session.query(CollectionLog).filter(CollectionLog.started_at < cutoff).delete(
                synchronize_session=False
            )
            session.query(AlertLog).filter(AlertLog.sent_at < cutoff).delete(
                synchronize_session=False
            )
            logger.info("Nettoyage: %d articles supprimés (rétention %d jours)", deleted, retention_days)

    def get_dashboard_stats(self, session: Session) -> dict:
        """Statistiques globales pour le dashboard."""
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        return {
            "articles": {
                "total": session.query(func.count(Article.id)).scalar(),
                "last_24h": session.query(func.count(Article.id)).filter(Article.collected_at >= last_24h).scalar(),
                "last_7d": session.query(func.count(Article.id)).filter(Article.collected_at >= last_7d).scalar(),
                "unread": session.query(func.count(Article.id)).filter(Article.read == False).scalar(),
            },
            "vulnerabilities": {
                "total": session.query(func.count(Vulnerability.id)).scalar(),
                "critical": session.query(func.count(Vulnerability.id)).filter(
                    Vulnerability.severity == SeverityLevel.CRITIQUE
                ).scalar(),
                "with_exploit": session.query(func.count(Vulnerability.id)).filter(
                    Vulnerability.exploit_available == True
                ).scalar(),
            },
            "iocs": {
                "total": session.query(func.count(IOC.id)).scalar(),
                "active": session.query(func.count(IOC.id)).filter(IOC.active == True).scalar(),
                "last_24h": session.query(func.count(IOC.id)).filter(IOC.first_seen >= last_24h).scalar(),
            },
            "threat_actors": {
                "total": session.query(func.count(ThreatActor.id)).scalar(),
                "active": session.query(func.count(ThreatActor.id)).filter(ThreatActor.active == True).scalar(),
            },
            "malwares": {
                "total": session.query(func.count(Malware.id)).scalar(),
            },
            "campaigns": {
                "total": session.query(func.count(Campaign.id)).scalar(),
                "active": session.query(func.count(Campaign.id)).filter(Campaign.status == "active").scalar(),
            },
        }
