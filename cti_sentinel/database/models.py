"""
Modèles SQLAlchemy pour CTI Sentinel.

Structure relationnelle complète pour :
- Articles et actualités
- Vulnérabilités (CVE)
- IOCs (Indicators of Compromise)
- Threat Actors (groupes APT)
- Malwares
- Campagnes
- Tags, catégories, relations
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, Table, Index, JSON, Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy.sql import func
import enum


class Base(DeclarativeBase):
    """Classe de base pour tous les modèles."""
    pass


# ============================================================================
# ENUMS
# ============================================================================

class SeverityLevel(enum.Enum):
    CRITIQUE = "CRITIQUE"
    HAUTE = "HAUTE"
    MOYENNE = "MOYENNE"
    FAIBLE = "FAIBLE"
    INFO = "INFO"


class IOCType(enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA = "yara"
    MUTEX = "mutex"
    REGISTRY = "registry"
    FILEPATH = "filepath"
    USERAGENT = "useragent"
    CIDR = "cidr"
    JA3 = "ja3"
    BITCOIN = "bitcoin"


class ArticleStatus(enum.Enum):
    NEW = "new"
    PROCESSING = "processing"
    PROCESSED = "processed"
    ENRICHED = "enriched"
    ERROR = "error"
    DUPLICATE = "duplicate"


class ThreatActorType(enum.Enum):
    APT = "apt"
    CYBERCRIME = "cybercrime"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    STATE_SPONSORED = "state_sponsored"
    UNKNOWN = "unknown"


# ============================================================================
# TABLES D'ASSOCIATION (Many-to-Many)
# ============================================================================

article_tags = Table(
    "article_tags", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

article_iocs = Table(
    "article_iocs", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", Integer, ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)

article_cves = Table(
    "article_cves", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("cve_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
)

article_threat_actors = Table(
    "article_threat_actors", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("threat_actor_id", Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True),
)

article_malwares = Table(
    "article_malwares", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("malware_id", Integer, ForeignKey("malwares.id", ondelete="CASCADE"), primary_key=True),
)

article_campaigns = Table(
    "article_campaigns", Base.metadata,
    Column("article_id", Integer, ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True),
    Column("campaign_id", Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True),
)

campaign_iocs = Table(
    "campaign_iocs", Base.metadata,
    Column("campaign_id", Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", Integer, ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)

campaign_malwares = Table(
    "campaign_malwares", Base.metadata,
    Column("campaign_id", Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True),
    Column("malware_id", Integer, ForeignKey("malwares.id", ondelete="CASCADE"), primary_key=True),
)

campaign_threat_actors = Table(
    "campaign_threat_actors", Base.metadata,
    Column("campaign_id", Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True),
    Column("threat_actor_id", Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True),
)

threat_actor_malwares = Table(
    "threat_actor_malwares", Base.metadata,
    Column("threat_actor_id", Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True),
    Column("malware_id", Integer, ForeignKey("malwares.id", ondelete="CASCADE"), primary_key=True),
)

threat_actor_ttps = Table(
    "threat_actor_ttps", Base.metadata,
    Column("threat_actor_id", Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), primary_key=True),
    Column("ttp_id", Integer, ForeignKey("ttps.id", ondelete="CASCADE"), primary_key=True),
)

malware_iocs = Table(
    "malware_iocs", Base.metadata,
    Column("malware_id", Integer, ForeignKey("malwares.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", Integer, ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)

vulnerability_products = Table(
    "vulnerability_products", Base.metadata,
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
    Column("product_id", Integer, ForeignKey("products.id", ondelete="CASCADE"), primary_key=True),
)


# ============================================================================
# MODÈLES PRINCIPAUX
# ============================================================================

class Article(Base):
    """Articles collectés depuis les sources RSS/Web/API."""
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[Optional[str]] = mapped_column(Text)
    summary: Mapped[Optional[str]] = mapped_column(Text)  # Résumé généré par LLM
    summary_fr: Mapped[Optional[str]] = mapped_column(Text)  # Résumé en français
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_category: Mapped[str] = mapped_column(String(50), nullable=False)
    author: Mapped[Optional[str]] = mapped_column(String(200))
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    processed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        SQLEnum(ArticleStatus), default=ArticleStatus.NEW
    )
    severity: Mapped[Optional[str]] = mapped_column(SQLEnum(SeverityLevel))
    categories: Mapped[Optional[str]] = mapped_column(JSON)  # ["Ransomware", "APT"]
    language: Mapped[Optional[str]] = mapped_column(String(10))
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    starred: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    raw_data: Mapped[Optional[str]] = mapped_column(JSON)  # Données brutes

    # Relations
    tags = relationship("Tag", secondary=article_tags, back_populates="articles")
    iocs = relationship("IOC", secondary=article_iocs, back_populates="articles")
    vulnerabilities = relationship("Vulnerability", secondary=article_cves, back_populates="articles")
    threat_actors = relationship("ThreatActor", secondary=article_threat_actors, back_populates="articles")
    malwares = relationship("Malware", secondary=article_malwares, back_populates="articles")
    campaigns = relationship("Campaign", secondary=article_campaigns, back_populates="articles")

    # Index
    __table_args__ = (
        Index("idx_article_source", "source_name"),
        Index("idx_article_severity", "severity"),
        Index("idx_article_status", "status"),
        Index("idx_article_published", "published_at"),
        Index("idx_article_collected", "collected_at"),
        Index("idx_article_content_hash", "content_hash"),
    )

    @staticmethod
    def compute_content_hash(title: str, url: str, content: str = "") -> str:
        """Calcule un hash unique pour déduplication."""
        data = f"{title.strip().lower()}|{url.strip().lower()}|{content[:500] if content else ''}"
        return hashlib.sha256(data.encode()).hexdigest()

    def __repr__(self):
        return f"<Article(id={self.id}, title='{self.title[:50]}...', source='{self.source_name}')>"


class Vulnerability(Base):
    """Vulnérabilités CVE avec enrichissement."""
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # CVE-YYYY-NNNNN
    title: Mapped[Optional[str]] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text)
    description_fr: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(SQLEnum(SeverityLevel))

    # Scores
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(100))
    cvss_v2_score: Mapped[Optional[float]] = mapped_column(Float)
    epss_score: Mapped[Optional[float]] = mapped_column(Float)  # 0.0 - 1.0
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)

    # Statut exploitation
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_in_wild: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_references: Mapped[Optional[str]] = mapped_column(JSON)  # URLs des exploits
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False)  # Known Exploited Vulns

    # Informations
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    modified_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    cwe_ids: Mapped[Optional[str]] = mapped_column(JSON)  # ["CWE-79", "CWE-89"]
    references: Mapped[Optional[str]] = mapped_column(JSON)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_urls: Mapped[Optional[str]] = mapped_column(JSON)

    # Métadonnées
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    enriched_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    source: Mapped[Optional[str]] = mapped_column(String(50))  # nvd, cert_fr, etc.

    # Relations
    articles = relationship("Article", secondary=article_cves, back_populates="vulnerabilities")
    products = relationship("Product", secondary=vulnerability_products, back_populates="vulnerabilities")

    __table_args__ = (
        Index("idx_vuln_cve", "cve_id"),
        Index("idx_vuln_severity", "severity"),
        Index("idx_vuln_cvss", "cvss_v3_score"),
        Index("idx_vuln_published", "published_date"),
        Index("idx_vuln_exploit", "exploit_available"),
    )

    def __repr__(self):
        return f"<Vulnerability(cve_id='{self.cve_id}', cvss={self.cvss_v3_score})>"


class IOC(Base):
    """Indicateurs de compromission (IOCs)."""
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(SQLEnum(IOCType), nullable=False)
    value: Mapped[str] = mapped_column(String(2000), nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text)  # Contexte d'apparition
    confidence: Mapped[Optional[int]] = mapped_column(Integer)  # 0-100
    severity: Mapped[Optional[str]] = mapped_column(SQLEnum(SeverityLevel))
    source: Mapped[Optional[str]] = mapped_column(String(100))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    tags_json: Mapped[Optional[str]] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    whitelisted: Mapped[bool] = mapped_column(Boolean, default=False)
    enrichment_data: Mapped[Optional[str]] = mapped_column(JSON)  # VT, Shodan, etc.

    # Relations
    articles = relationship("Article", secondary=article_iocs, back_populates="iocs")
    campaigns = relationship("Campaign", secondary=campaign_iocs, back_populates="iocs")
    malwares = relationship("Malware", secondary=malware_iocs, back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_ioc_type_value"),
        Index("idx_ioc_type", "type"),
        Index("idx_ioc_value", "value"),
        Index("idx_ioc_first_seen", "first_seen"),
        Index("idx_ioc_active", "active"),
    )

    def __repr__(self):
        return f"<IOC(type='{self.type}', value='{self.value[:50]}')>"


class ThreatActor(Base):
    """Groupes de menaces / APT."""
    __tablename__ = "threat_actors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    aliases: Mapped[Optional[str]] = mapped_column(JSON)  # ["Fancy Bear", "APT28"]
    type: Mapped[Optional[str]] = mapped_column(SQLEnum(ThreatActorType))
    description: Mapped[Optional[str]] = mapped_column(Text)
    description_fr: Mapped[Optional[str]] = mapped_column(Text)
    origin_country: Mapped[Optional[str]] = mapped_column(String(100))
    origin_region: Mapped[Optional[str]] = mapped_column(String(100))
    target_sectors: Mapped[Optional[str]] = mapped_column(JSON)  # ["finance", "défense"]
    target_countries: Mapped[Optional[str]] = mapped_column(JSON)
    motivation: Mapped[Optional[str]] = mapped_column(String(200))  # espionnage, financier, etc.
    sophistication: Mapped[Optional[str]] = mapped_column(String(50))  # low, medium, high, expert
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    mitre_id: Mapped[Optional[str]] = mapped_column(String(20))  # G0xxx
    external_references: Mapped[Optional[str]] = mapped_column(JSON)
    profile_image: Mapped[Optional[str]] = mapped_column(String(500))
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relations
    articles = relationship("Article", secondary=article_threat_actors, back_populates="threat_actors")
    malwares = relationship("Malware", secondary=threat_actor_malwares, back_populates="threat_actors")
    ttps = relationship("TTP", secondary=threat_actor_ttps, back_populates="threat_actors")
    campaigns = relationship("Campaign", secondary=campaign_threat_actors, back_populates="threat_actors")

    __table_args__ = (
        Index("idx_ta_name", "name"),
        Index("idx_ta_origin", "origin_country"),
        Index("idx_ta_type", "type"),
    )

    def __repr__(self):
        return f"<ThreatActor(name='{self.name}', type='{self.type}')>"


class Malware(Base):
    """Familles et échantillons de malwares."""
    __tablename__ = "malwares"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    family: Mapped[Optional[str]] = mapped_column(String(200))
    aliases: Mapped[Optional[str]] = mapped_column(JSON)
    type: Mapped[Optional[str]] = mapped_column(String(100))  # ransomware, RAT, stealer, etc.
    description: Mapped[Optional[str]] = mapped_column(Text)
    description_fr: Mapped[Optional[str]] = mapped_column(Text)
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    sha1: Mapped[Optional[str]] = mapped_column(String(40))
    sha256: Mapped[Optional[str]] = mapped_column(String(64))
    ssdeep: Mapped[Optional[str]] = mapped_column(String(200))
    file_type: Mapped[Optional[str]] = mapped_column(String(50))
    file_size: Mapped[Optional[int]] = mapped_column(Integer)
    c2_servers: Mapped[Optional[str]] = mapped_column(JSON)  # Liste des C2
    techniques: Mapped[Optional[str]] = mapped_column(JSON)  # TTPs MITRE
    platforms: Mapped[Optional[str]] = mapped_column(JSON)  # ["Windows", "Linux"]
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    yara_rule: Mapped[Optional[str]] = mapped_column(Text)
    sigma_rule: Mapped[Optional[str]] = mapped_column(Text)
    external_references: Mapped[Optional[str]] = mapped_column(JSON)
    mitre_id: Mapped[Optional[str]] = mapped_column(String(20))  # S0xxx
    malpedia_url: Mapped[Optional[str]] = mapped_column(String(500))
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relations
    articles = relationship("Article", secondary=article_malwares, back_populates="malwares")
    threat_actors = relationship("ThreatActor", secondary=threat_actor_malwares, back_populates="malwares")
    iocs = relationship("IOC", secondary=malware_iocs, back_populates="malwares")
    campaigns = relationship("Campaign", secondary=campaign_malwares, back_populates="malwares")

    __table_args__ = (
        Index("idx_malware_name", "name"),
        Index("idx_malware_family", "family"),
        Index("idx_malware_type", "type"),
        Index("idx_malware_sha256", "sha256"),
    )

    def __repr__(self):
        return f"<Malware(name='{self.name}', type='{self.type}')>"


class Campaign(Base):
    """Campagnes d'attaque identifiées."""
    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    description_fr: Mapped[Optional[str]] = mapped_column(Text)
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[Optional[str]] = mapped_column(String(50))  # active, concluded, suspected
    target_sectors: Mapped[Optional[str]] = mapped_column(JSON)
    target_countries: Mapped[Optional[str]] = mapped_column(JSON)
    attack_vectors: Mapped[Optional[str]] = mapped_column(JSON)
    impact: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(SQLEnum(SeverityLevel))
    external_references: Mapped[Optional[str]] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relations
    articles = relationship("Article", secondary=article_campaigns, back_populates="campaigns")
    iocs = relationship("IOC", secondary=campaign_iocs, back_populates="campaigns")
    malwares = relationship("Malware", secondary=campaign_malwares, back_populates="campaigns")
    threat_actors = relationship("ThreatActor", secondary=campaign_threat_actors, back_populates="campaigns")

    __table_args__ = (
        Index("idx_campaign_name", "name"),
        Index("idx_campaign_status", "status"),
        Index("idx_campaign_start", "start_date"),
    )

    def __repr__(self):
        return f"<Campaign(name='{self.name}', status='{self.status}')>"


class TTP(Base):
    """Tactiques, Techniques et Procédures (MITRE ATT&CK)."""
    __tablename__ = "ttps"

    id: Mapped[int] = mapped_column(primary_key=True)
    mitre_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # T1059.001
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    tactic: Mapped[Optional[str]] = mapped_column(String(100))  # initial-access, execution, etc.
    description: Mapped[Optional[str]] = mapped_column(Text)
    description_fr: Mapped[Optional[str]] = mapped_column(Text)
    platforms: Mapped[Optional[str]] = mapped_column(JSON)
    data_sources: Mapped[Optional[str]] = mapped_column(JSON)
    detection: Mapped[Optional[str]] = mapped_column(Text)
    mitigation: Mapped[Optional[str]] = mapped_column(Text)
    external_references: Mapped[Optional[str]] = mapped_column(JSON)
    sigma_rules: Mapped[Optional[str]] = mapped_column(JSON)  # Règles Sigma associées
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relations
    threat_actors = relationship("ThreatActor", secondary=threat_actor_ttps, back_populates="ttps")

    __table_args__ = (
        Index("idx_ttp_mitre_id", "mitre_id"),
        Index("idx_ttp_tactic", "tactic"),
    )

    def __repr__(self):
        return f"<TTP(mitre_id='{self.mitre_id}', name='{self.name}')>"


class Tag(Base):
    """Tags pour catégorisation libre."""
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    color: Mapped[Optional[str]] = mapped_column(String(7))  # #FFFFFF
    category: Mapped[Optional[str]] = mapped_column(String(50))  # type, sector, region, etc.

    # Relations
    articles = relationship("Article", secondary=article_tags, back_populates="tags")

    def __repr__(self):
        return f"<Tag(name='{self.name}')>"


class Product(Base):
    """Produits/technologies affectés par les vulnérabilités."""
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100))
    cpe: Mapped[Optional[str]] = mapped_column(String(500))  # CPE string

    # Relations
    vulnerabilities = relationship("Vulnerability", secondary=vulnerability_products, back_populates="products")

    __table_args__ = (
        UniqueConstraint("vendor", "product", "version", name="uq_product"),
        Index("idx_product_vendor", "vendor"),
        Index("idx_product_name", "product"),
    )

    def __repr__(self):
        return f"<Product(vendor='{self.vendor}', product='{self.product}')>"


class CollectionLog(Base):
    """Logs de collecte pour suivi et debugging."""
    __tablename__ = "collection_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_category: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running, success, error
    items_collected: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    items_duplicate: Mapped[int] = mapped_column(Integer, default=0)
    items_error: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)

    __table_args__ = (
        Index("idx_log_source", "source_name"),
        Index("idx_log_started", "started_at"),
        Index("idx_log_status", "status"),
    )


class AlertLog(Base):
    """Historique des alertes envoyées."""
    __tablename__ = "alert_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    article_id: Mapped[Optional[int]] = mapped_column(ForeignKey("articles.id"))
    vulnerability_id: Mapped[Optional[int]] = mapped_column(ForeignKey("vulnerabilities.id"))
    severity: Mapped[Optional[str]] = mapped_column(SQLEnum(SeverityLevel))
    message: Mapped[str] = mapped_column(Text, nullable=False)
    channels_sent: Mapped[Optional[str]] = mapped_column(JSON)  # ["desktop", "discord"]
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        Index("idx_alert_rule", "rule_name"),
        Index("idx_alert_sent", "sent_at"),
    )


class Flashcard(Base):
    """Flashcards pour l'apprentissage CTI."""
    __tablename__ = "flashcards"

    id: Mapped[int] = mapped_column(primary_key=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # apt, cve, technique, concept
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    difficulty: Mapped[str] = mapped_column(String(20), default="intermédiaire")
    source_article_id: Mapped[Optional[int]] = mapped_column(ForeignKey("articles.id"))
    times_shown: Mapped[int] = mapped_column(Integer, default=0)
    times_correct: Mapped[int] = mapped_column(Integer, default=0)
    last_shown: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_flashcard_category", "category"),
    )


class QuizResult(Base):
    """Résultats des quiz quotidiens."""
    __tablename__ = "quiz_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    quiz_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    total_questions: Mapped[int] = mapped_column(Integer, nullable=False)
    correct_answers: Mapped[int] = mapped_column(Integer, nullable=False)
    score_percent: Mapped[float] = mapped_column(Float, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
