"""
Alert Manager - Système de notifications multi-canal.
Desktop, Discord, Telegram, Slack, Email.
"""

import asyncio
import json
import logging
import smtplib
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Any

import aiohttp

from cti_sentinel.config import ConfigLoader
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.database.models import (
    Article, AlertLog, SeverityLevel, Vulnerability,
)

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Gestionnaire d'alertes multi-canal avec cooldown et règles configurables.
    """

    def __init__(self, config: ConfigLoader = None, db: DatabaseManager = None):
        self.config = config or ConfigLoader()
        self.db = db or DatabaseManager(self.config)
        self._cooldowns: Dict[str, datetime] = {}

    async def evaluate_article(self, article: Article) -> List[Dict]:
        """
        Évalue un article contre les règles d'alerte configurées.
        Envoie les notifications si les conditions sont remplies.
        """
        if not self.config.get("alerts.enabled", False):
            return []

        triggered = []
        rules = self.config.get_alert_rules()

        for rule in rules:
            rule_name = rule.get("name", "unknown")

            # Vérifier le cooldown
            cooldown = rule.get("cooldown", 3600)
            if self._is_in_cooldown(rule_name, cooldown):
                continue

            # Évaluer la condition
            if self._evaluate_condition(rule, article):
                channels = rule.get("channels", ["desktop"])
                message = self._format_alert_message(article, rule_name)

                # Envoyer sur chaque canal
                sent_channels = []
                for channel in channels:
                    try:
                        success = await self._send_notification(channel, message, article)
                        if success:
                            sent_channels.append(channel)
                    except Exception as e:
                        logger.error(
                            "Erreur envoi alerte %s sur %s: %s",
                            rule_name, channel, str(e)
                        )

                if sent_channels:
                    self._set_cooldown(rule_name)
                    triggered.append({
                        "rule": rule_name,
                        "channels": sent_channels,
                        "article_title": article.title,
                    })

                    # Logger en DB
                    self._log_alert(article, rule_name, message, sent_channels)

        return triggered

    def _evaluate_condition(self, rule: dict, article: Article) -> bool:
        """Évalue la condition d'une règle d'alerte."""
        condition = rule.get("condition", "")
        if not condition:
            return False

        # Construire un contexte d'évaluation sécurisé
        title = (article.title or "").lower()
        content = (article.content or "").lower()
        summary = (article.summary_fr or "").lower()
        full_text = f"{title} {content} {summary}"
        severity = str(article.severity) if article.severity else "INFO"
        categories = article.categories or []
        tags = [t.name for t in article.tags] if article.tags else []
        source_category = article.source_category or ""
        article_type = source_category

        # Technologies surveillées
        watched_technologies = [t.lower() for t in self.config.get_watched_technologies()]

        try:
            # Évaluation sécurisée des conditions
            if "severity == 'CRITIQUE'" in condition and severity == "SeverityLevel.CRITIQUE":
                return True
            if "severity == 'CRITIQUE'" in condition and "CRITIQUE" in severity:
                return True

            if "'0-day' in tags or 'zero-day' in tags" in condition:
                return "0-day" in tags or "zero-day" in tags or \
                       "0-day" in full_text or "zero-day" in full_text

            if "'france' in targets or 'europe' in targets" in condition:
                return "france" in full_text or "europe" in full_text or \
                       "french" in full_text

            if "'ransomware' in categories" in condition:
                return "ransomware" in [c.lower() for c in categories] or \
                       "ransomware" in full_text

            if "watched_technologies" in condition:
                return any(tech in full_text for tech in watched_technologies)

            if "type == 'vulnerability'" in condition:
                return source_category == "vulnerabilities"

        except Exception as e:
            logger.warning("Erreur évaluation règle '%s': %s", rule.get("name"), str(e))

        return False

    async def _send_notification(self, channel: str, message: str,
                                  article: Article) -> bool:
        """Envoie une notification sur un canal spécifique."""
        if channel == "desktop":
            return self._send_desktop_notification(message, article)
        elif channel == "discord":
            return await self._send_discord(message, article)
        elif channel == "telegram":
            return await self._send_telegram(message, article)
        elif channel == "slack":
            return await self._send_slack(message, article)
        elif channel == "email":
            return self._send_email(message, article)
        else:
            logger.warning("Canal d'alerte inconnu: %s", channel)
            return False

    def _send_desktop_notification(self, message: str, article: Article) -> bool:
        """Envoie une notification desktop (Linux/Mac/Windows)."""
        title = "🚨 CTI Sentinel - Alerte"
        body = message[:250]

        try:
            if sys.platform == "linux":
                subprocess.run(
                    ["notify-send", "-u", "critical", title, body],
                    timeout=5, check=False,
                )
            elif sys.platform == "darwin":
                subprocess.run(
                    ["osascript", "-e",
                     f'display notification "{body}" with title "{title}"'],
                    timeout=5, check=False,
                )
            elif sys.platform == "win32":
                # Windows 10+ toast notification via PowerShell
                ps_script = (
                    f'[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, '
                    f'ContentType = WindowsRuntime] > $null; '
                    f'$template = [Windows.UI.Notifications.ToastNotificationManager]::'
                    f'GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); '
                    f'$template.GetElementsByTagName("text")[0].AppendChild($template.CreateTextNode("{title}")); '
                    f'$template.GetElementsByTagName("text")[1].AppendChild($template.CreateTextNode("{body}")); '
                    f'[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("CTI Sentinel")'
                    f'.Show($template)'
                )
                subprocess.run(
                    ["powershell", "-Command", ps_script],
                    timeout=10, check=False,
                )
            logger.info("📢 Notification desktop envoyée")
            return True
        except Exception as e:
            logger.warning("Erreur notification desktop: %s", str(e))
            return False

    async def _send_discord(self, message: str, article: Article) -> bool:
        """Envoie une alerte sur Discord via webhook."""
        webhook_url = self.config.get("alerts.discord.webhook_url", "")
        if not webhook_url:
            return False

        severity_colors = {
            "CRITIQUE": 0xFF0000,  # Rouge
            "HAUTE": 0xFF8C00,     # Orange
            "MOYENNE": 0xFFD700,   # Jaune
            "FAIBLE": 0x32CD32,    # Vert
            "INFO": 0x4169E1,      # Bleu
        }

        severity = str(article.severity) if article.severity else "INFO"
        color = severity_colors.get(severity.split(".")[-1], 0x808080)

        embed = {
            "title": f"🚨 {article.title[:250]}",
            "description": message[:2000],
            "color": color,
            "url": article.url,
            "fields": [
                {"name": "Sévérité", "value": severity, "inline": True},
                {"name": "Source", "value": article.source_name, "inline": True},
                {"name": "Catégorie", "value": article.source_category, "inline": True},
            ],
            "footer": {"text": "CTI Sentinel"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        payload = {
            "username": "CTI Sentinel",
            "embeds": [embed],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as resp:
                    if resp.status in (200, 204):
                        logger.info("📢 Alerte Discord envoyée")
                        return True
                    else:
                        logger.warning("Erreur Discord (%d)", resp.status)
                        return False
        except Exception as e:
            logger.error("Erreur Discord: %s", str(e))
            return False

    async def _send_telegram(self, message: str, article: Article) -> bool:
        """Envoie une alerte sur Telegram."""
        bot_token = self.config.get("alerts.telegram.bot_token", "")
        chat_id = self.config.get("alerts.telegram.chat_id", "")
        if not bot_token or not chat_id:
            return False

        severity = str(article.severity) if article.severity else "INFO"
        text = (
            f"🚨 *CTI Sentinel - {severity}*\n\n"
            f"*{article.title[:200]}*\n\n"
            f"{message[:500]}\n\n"
            f"📎 [Lien]({article.url})\n"
            f"📰 Source: {article.source_name}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        logger.info("📢 Alerte Telegram envoyée")
                        return True
                    return False
        except Exception as e:
            logger.error("Erreur Telegram: %s", str(e))
            return False

    async def _send_slack(self, message: str, article: Article) -> bool:
        """Envoie une alerte sur Slack via webhook."""
        webhook_url = self.config.get("alerts.slack.webhook_url", "")
        if not webhook_url:
            return False

        severity = str(article.severity) if article.severity else "INFO"
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 CTI Sentinel - {severity}"}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{article.title[:200]}*\n{message[:500]}"}
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Source: {article.source_name} | <{article.url}|Lien>"}
                    ]
                }
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as resp:
                    if resp.status == 200:
                        logger.info("📢 Alerte Slack envoyée")
                        return True
                    return False
        except Exception as e:
            logger.error("Erreur Slack: %s", str(e))
            return False

    def _send_email(self, message: str, article: Article) -> bool:
        """Envoie une alerte par email."""
        smtp_server = self.config.get("alerts.email.smtp_server")
        smtp_port = self.config.get("alerts.email.smtp_port", 587)
        username = self.config.get("alerts.email.username")
        password = self.config.get("alerts.email.password")
        recipients = self.config.get("alerts.email.recipients", [])

        if not all([smtp_server, username, password, recipients]):
            return False

        severity = str(article.severity) if article.severity else "INFO"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CTI Sentinel] {severity} - {article.title[:100]}"
        msg["From"] = username
        msg["To"] = ", ".join(recipients)

        html = f"""
        <html><body>
        <h2>🚨 Alerte CTI Sentinel</h2>
        <p><strong>Sévérité:</strong> {severity}</p>
        <p><strong>Titre:</strong> {article.title}</p>
        <p><strong>Source:</strong> {article.source_name}</p>
        <p>{message}</p>
        <p><a href="{article.url}">Voir l'article complet</a></p>
        <hr><p><em>CTI Sentinel - Veille CTI automatisée</em></p>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
            logger.info("📧 Alerte email envoyée")
            return True
        except Exception as e:
            logger.error("Erreur email: %s", str(e))
            return False

    def _format_alert_message(self, article: Article, rule_name: str) -> str:
        """Formate le message d'alerte."""
        summary = article.summary_fr or article.summary or article.content or ""
        severity = str(article.severity) if article.severity else "INFO"

        iocs = [f"{ioc.type.value}: {ioc.value}" for ioc in article.iocs[:5]]
        ioc_text = "\n".join(iocs) if iocs else "Aucun"

        cves = [v.cve_id for v in article.vulnerabilities[:5]]
        cve_text = ", ".join(cves) if cves else "Aucune"

        return (
            f"Règle: {rule_name}\n"
            f"Sévérité: {severity}\n"
            f"Source: {article.source_name}\n\n"
            f"{summary[:500]}\n\n"
            f"CVE: {cve_text}\n"
            f"IOCs:\n{ioc_text}"
        )

    def _is_in_cooldown(self, rule_name: str, cooldown_seconds: int) -> bool:
        """Vérifie si une règle est en cooldown."""
        last_fired = self._cooldowns.get(rule_name)
        if not last_fired:
            return False
        elapsed = (datetime.now(timezone.utc) - last_fired).total_seconds()
        return elapsed < cooldown_seconds

    def _set_cooldown(self, rule_name: str):
        """Définit le cooldown pour une règle."""
        self._cooldowns[rule_name] = datetime.now(timezone.utc)

    def _log_alert(self, article: Article, rule_name: str,
                   message: str, channels: list):
        """Enregistre l'alerte en DB."""
        try:
            with self.db.get_session() as session:
                alert_log = AlertLog(
                    rule_name=rule_name,
                    article_id=article.id,
                    severity=article.severity,
                    message=message[:2000],
                    channels_sent=channels,
                )
                session.add(alert_log)
        except Exception as e:
            logger.warning("Erreur log alerte: %s", str(e))

    async def send_daily_digest(self):
        """Envoie le digest quotidien par email."""
        if not self.config.get("alerts.email.daily_digest", False):
            return

        with self.db.get_session() as session:
            stats = self.db.get_dashboard_stats(session)

            # Articles critiques des 24h
            from sqlalchemy import desc
            critical_articles = (
                session.query(Article)
                .filter(
                    Article.collected_at >= datetime.now(timezone.utc) - timedelta(hours=24),
                    Article.severity.in_([SeverityLevel.CRITIQUE, SeverityLevel.HAUTE])
                )
                .order_by(desc(Article.collected_at))
                .limit(20)
                .all()
            )

            if not critical_articles:
                logger.info("Pas d'alerte critique pour le digest quotidien")
                return

            # Construire le digest
            articles_html = ""
            for a in critical_articles:
                severity = str(a.severity).split(".")[-1] if a.severity else "INFO"
                articles_html += f"""
                <tr>
                    <td>{severity}</td>
                    <td><a href="{a.url}">{a.title[:100]}</a></td>
                    <td>{a.source_name}</td>
                    <td>{a.summary_fr[:150] if a.summary_fr else ''}</td>
                </tr>
                """

            html = f"""
            <html><body>
            <h1>📊 CTI Sentinel - Digest Quotidien</h1>
            <p>Date: {datetime.now().strftime('%d/%m/%Y')}</p>

            <h2>Statistiques (24h)</h2>
            <ul>
                <li>Articles collectés: {stats['articles']['last_24h']}</li>
                <li>Vulnérabilités critiques: {stats['vulnerabilities']['critical']}</li>
                <li>IOCs actifs: {stats['iocs']['active']}</li>
            </ul>

            <h2>Alertes critiques et hautes</h2>
            <table border="1" cellpadding="5">
                <tr><th>Sévérité</th><th>Titre</th><th>Source</th><th>Résumé</th></tr>
                {articles_html}
            </table>

            <hr>
            <p><em>CTI Sentinel - Veille CTI automatisée</em></p>
            </body></html>
            """

            # Créer un article factice pour le digest
            class DigestArticle:
                title = f"Digest CTI du {datetime.now().strftime('%d/%m/%Y')}"
                url = ""
                source_name = "CTI Sentinel"
                severity = SeverityLevel.INFO
                content = html
                iocs = []
                vulnerabilities = []
                summary_fr = ""
                source_category = "digest"

            self._send_email(html, DigestArticle())
