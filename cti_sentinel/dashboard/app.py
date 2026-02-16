"""
Dashboard Streamlit - Interface de visualisation CTI Sentinel.
Interface web complète pour la veille cyber et géopolitique.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
import json
import requests

# ============================================================================
# Configuration
# ============================================================================

API_BASE = "http://localhost:8000/api"

st.set_page_config(
    page_title="🛡️ CTI Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# Style CSS personnalisé
# ============================================================================

st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #0f3460;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        color: #e0e0e0;
    }
    .metric-card h2 { color: #00d4ff; margin: 0; font-size: 2em; }
    .metric-card p { color: #a0a0a0; margin: 5px 0 0 0; }
    .severity-critical { color: #ff4444; font-weight: bold; }
    .severity-high { color: #ff8c00; font-weight: bold; }
    .severity-medium { color: #ffd700; }
    .severity-low { color: #00cc66; }
    .severity-info { color: #00bfff; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 16px;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Fonctions API
# ============================================================================

def api_get(endpoint: str, params: dict = None):
    """Appel GET à l'API."""
    try:
        resp = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ API non disponible. Lancez le serveur: `uvicorn cti_sentinel.api.server:app`")
        return None
    except Exception as e:
        st.error(f"Erreur API: {e}")
        return None


def api_post(endpoint: str, data: dict = None):
    """Appel POST à l'API."""
    try:
        resp = requests.post(f"{API_BASE}{endpoint}", json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Erreur API: {e}")
        return None


def api_patch(endpoint: str):
    """Appel PATCH à l'API."""
    try:
        resp = requests.patch(f"{API_BASE}{endpoint}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Erreur API: {e}")
        return None


# ============================================================================
# Barre latérale
# ============================================================================

def sidebar():
    """Menu de navigation."""
    with st.sidebar:
        st.image("https://img.icons8.com/nolan/96/shield.png", width=80)
        st.title("CTI Sentinel")
        st.markdown("---")

        page = st.radio(
            "🗂️ Navigation",
            [
                "📊 Vue d'ensemble",
                "📰 Articles",
                "🔓 Vulnérabilités",
                "🔍 IOCs",
                "👤 Threat Actors",
                "📈 Tendances",
                "🗺️ MITRE ATT&CK",
                "🕸️ Graphe",
                "🎓 Apprentissage",
                "⚙️ Opérations",
            ],
            label_visibility="collapsed",
        )

        st.markdown("---")

        # Collecte rapide
        if st.button("🔄 Lancer une collecte", use_container_width=True):
            with st.spinner("Collecte en cours..."):
                result = api_post("/collect", {})
                if result:
                    st.success("Collecte lancée !")

        if st.button("🤖 Traiter les articles", use_container_width=True):
            with st.spinner("Traitement en cours..."):
                result = api_post("/process")
                if result:
                    st.success("Traitement lancé !")

        st.markdown("---")
        st.caption(f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M')}")

    return page


# ============================================================================
# Page - Vue d'ensemble
# ============================================================================

def page_overview():
    """Dashboard principal avec KPIs."""
    st.header("📊 Vue d'ensemble")

    stats = api_get("/stats")
    if not stats:
        return

    # KPIs principaux
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        st.metric("📰 Articles", stats.get("articles", {}).get("total", 0))
    with col2:
        st.metric("🔓 CVEs", stats.get("vulnerabilities", {}).get("total", 0))
    with col3:
        st.metric("🔍 IOCs", stats.get("iocs", {}).get("total", 0))
    with col4:
        st.metric("👤 Acteurs", stats.get("threat_actors", {}).get("total", 0))
    with col5:
        st.metric("🦠 Malwares", stats.get("malwares", {}).get("total", 0))
    with col6:
        st.metric("📋 Campagnes", stats.get("campaigns", {}).get("total", 0))

    st.markdown("---")

    # Score de menace
    score_data = api_get("/threat-score")
    if score_data and isinstance(score_data, dict):
        score = score_data.get("global_score", 0)
        col_s1, col_s2 = st.columns([1, 3])
        with col_s1:
            color = "#ff4444" if score >= 70 else "#ff8c00" if score >= 40 else "#00cc66"
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": "Score de menace"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": color},
                    "steps": [
                        {"range": [0, 30], "color": "#1a3a1a"},
                        {"range": [30, 60], "color": "#3a3a1a"},
                        {"range": [60, 100], "color": "#3a1a1a"},
                    ],
                },
            ))
            fig.update_layout(height=300, margin=dict(t=40, b=20, l=30, r=30))
            st.plotly_chart(fig, use_container_width=True)

        with col_s2:
            # Tendances récentes
            trends = api_get("/trends", {"days": 7})
            if trends and "category_trends" in trends:
                cats = trends["category_trends"]
                if cats:
                    df_trends = pd.DataFrame(cats)
                    if not df_trends.empty and "category" in df_trends.columns and "count" in df_trends.columns:
                        fig2 = px.bar(
                            df_trends, x="category", y="count",
                            title="Articles par catégorie (7 jours)",
                            color="count", color_continuous_scale="Blues",
                        )
                        fig2.update_layout(height=300, showlegend=False)
                        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Derniers articles critiques
    st.subheader("🚨 Derniers articles critiques")
    articles = api_get("/articles", {"limit": 10, "severity": "critical"})
    if articles:
        for a in articles:
            with st.expander(f"🔴 {a['title']} — {a['source_name']}"):
                st.write(a.get("summary_fr", a.get("title", "")))
                st.caption(f"📅 {a.get('published_at', 'N/A')} | 🔍 IOCs: {a.get('ioc_count', 0)} | CVEs: {a.get('cve_count', 0)}")
                st.link_button("🔗 Source", a["url"])
    else:
        st.info("Aucun article critique récent.")


# ============================================================================
# Page - Articles
# ============================================================================

def page_articles():
    """Liste et recherche d'articles."""
    st.header("📰 Articles de veille")

    # Filtres
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        severity = st.selectbox("Sévérité", ["Toutes", "critical", "high", "medium", "low", "info"])
    with col_f2:
        search = st.text_input("🔎 Recherche", placeholder="mot-clé...")
    with col_f3:
        days = st.slider("Jours", 1, 90, 7)
    with col_f4:
        limit = st.selectbox("Résultats", [25, 50, 100, 200])

    params = {"limit": limit}
    if severity != "Toutes":
        params["severity"] = severity
    if search:
        params["search"] = search

    date_from = datetime.now(timezone.utc) - timedelta(days=days)
    params["date_from"] = date_from.isoformat()

    articles = api_get("/articles", params)
    if not articles:
        st.info("Aucun article trouvé.")
        return

    st.caption(f"📊 {len(articles)} articles trouvés")

    for a in articles:
        sev = a.get("severity", "info") or "info"
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(sev, "⚪")

        col_a, col_b = st.columns([0.95, 0.05])
        with col_a:
            with st.expander(f"{sev_emoji} {a['title']}"):
                if a.get("summary_fr"):
                    st.write(a["summary_fr"])

                tags_str = ", ".join(a.get("tags", [])[:5])
                actors_str = ", ".join(a.get("threat_actors", [])[:3])

                mcol1, mcol2, mcol3 = st.columns(3)
                with mcol1:
                    st.caption(f"📡 {a['source_name']} ({a.get('source_category', '')})")
                with mcol2:
                    st.caption(f"🔍 IOCs: {a.get('ioc_count', 0)} | CVEs: {a.get('cve_count', 0)}")
                with mcol3:
                    st.caption(f"📅 {a.get('published_at', 'N/A')}")

                if tags_str:
                    st.caption(f"🏷️ {tags_str}")
                if actors_str:
                    st.caption(f"👤 {actors_str}")

                bcol1, bcol2, bcol3 = st.columns(3)
                with bcol1:
                    st.link_button("🔗 Source", a["url"])
                with bcol2:
                    if st.button("✅ Lu", key=f"read_{a['id']}"):
                        api_patch(f"/articles/{a['id']}/read")
                        st.rerun()
                with bcol3:
                    star_label = "⭐ Retirer" if a.get("starred") else "⭐ Favori"
                    if st.button(star_label, key=f"star_{a['id']}"):
                        api_patch(f"/articles/{a['id']}/star")
                        st.rerun()


# ============================================================================
# Page - Vulnérabilités
# ============================================================================

def page_vulnerabilities():
    """Liste des vulnérabilités."""
    st.header("🔓 Vulnérabilités")

    col1, col2, col3 = st.columns(3)
    with col1:
        severity = st.selectbox("Sévérité", ["Toutes", "critical", "high", "medium", "low"])
    with col2:
        days = st.slider("Période (jours)", 1, 90, 30)
    with col3:
        exploit_only = st.checkbox("Exploit disponible uniquement")

    params = {"days": days, "limit": 100}
    if severity != "Toutes":
        params["severity"] = severity
    if exploit_only:
        params["exploit_only"] = True

    vulns = api_get("/vulnerabilities", params)
    if not vulns:
        st.info("Aucune vulnérabilité trouvée.")
        return

    # Tableau synthétique
    df = pd.DataFrame(vulns)
    if not df.empty:
        # Graphique sévérité
        if "severity" in df.columns:
            fig = px.histogram(df, x="severity", title="Répartition par sévérité",
                             color="severity",
                             color_discrete_map={
                                 "critical": "#ff4444", "high": "#ff8c00",
                                 "medium": "#ffd700", "low": "#00cc66",
                             })
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)

        # Tableau détaillé
        display_cols = ["cve_id", "severity", "cvss_v3_score", "exploit_available", "cisa_kev"]
        available_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(
            df[available_cols].sort_values("cvss_v3_score", ascending=False)
            if "cvss_v3_score" in df.columns else df[available_cols],
            use_container_width=True,
            height=500,
        )

    # Détail CVE
    st.markdown("---")
    cve_search = st.text_input("🔎 Rechercher une CVE", placeholder="CVE-2024-XXXXX")
    if cve_search:
        detail = api_get(f"/vulnerabilities/{cve_search}")
        if detail:
            st.subheader(f"📋 {detail['cve_id']}")
            st.write(detail.get("description", "Pas de description"))
            if detail.get("description_fr"):
                st.info(f"🇫🇷 {detail['description_fr']}")

            mcol1, mcol2, mcol3, mcol4 = st.columns(4)
            with mcol1:
                st.metric("CVSS v3", detail.get("cvss_v3_score", "N/A"))
            with mcol2:
                st.metric("EPSS", f"{(detail.get('epss_score', 0) or 0)*100:.1f}%")
            with mcol3:
                st.metric("Exploit", "✅" if detail.get("exploit_available") else "❌")
            with mcol4:
                st.metric("CISA KEV", "✅" if detail.get("cisa_kev") else "❌")


# ============================================================================
# Page - IOCs
# ============================================================================

def page_iocs():
    """Recherche et listing d'IOCs."""
    st.header("🔍 Indicateurs de compromission (IOCs)")

    col1, col2, col3 = st.columns(3)
    with col1:
        ioc_type = st.selectbox("Type", ["Tous", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve"])
    with col2:
        days = st.slider("Période (jours)", 1, 90, 7, key="ioc_days")
    with col3:
        search_val = st.text_input("🔎 Rechercher un IOC", placeholder="IP, hash, domain...")

    if search_val:
        results = api_get("/iocs/search", {"value": search_val})
        if results:
            st.success(f"✅ {len(results)} résultat(s) trouvé(s)")
            for r in results:
                with st.expander(f"🎯 [{r['type']}] {r['value']}"):
                    st.write(f"**Confiance**: {r.get('confidence', 'N/A')}%")
                    st.write(f"**Première vue**: {r['first_seen']}")
                    st.write(f"**Dernière vue**: {r['last_seen']}")
                    if r.get("related_articles"):
                        st.write("**Articles liés:**")
                        for title in r["related_articles"]:
                            st.write(f"  - {title}")
        else:
            st.warning("Aucun IOC trouvé pour cette recherche.")
    else:
        params = {"days": days, "limit": 100}
        if ioc_type != "Tous":
            params["ioc_type"] = ioc_type

        iocs = api_get("/iocs", params)
        if iocs:
            df = pd.DataFrame(iocs)
            if not df.empty:
                # Distribution par type
                if "type" in df.columns:
                    fig = px.pie(df, names="type", title="Répartition par type d'IOC")
                    fig.update_layout(height=350)
                    st.plotly_chart(fig, use_container_width=True)

                st.dataframe(
                    df[["type", "value", "confidence", "source", "first_seen"]],
                    use_container_width=True,
                    height=500,
                )


# ============================================================================
# Page - Threat Actors
# ============================================================================

def page_threat_actors():
    """Profils des groupes de menaces."""
    st.header("👤 Groupes de menaces")

    col1, col2 = st.columns(2)
    with col1:
        actor_type = st.selectbox("Type", ["Tous", "apt", "cybercriminal", "hacktivist", "insider"])
    with col2:
        country = st.text_input("Pays d'origine", placeholder="russia, china, iran...")

    params = {"limit": 100}
    if actor_type != "Tous":
        params["actor_type"] = actor_type
    if country:
        params["country"] = country

    actors = api_get("/threat-actors", params)
    if not actors:
        st.info("Aucun threat actor trouvé.")
        return

    for actor in actors:
        with st.expander(f"🎯 {actor['name']} {'(' + actor.get('origin_country', '') + ')' if actor.get('origin_country') else ''}"):
            if actor.get("description"):
                st.write(actor["description"][:500])
            if actor.get("aliases"):
                st.caption(f"🏷️ Alias: {', '.join(actor['aliases'][:5])}")
            if actor.get("target_sectors"):
                st.caption(f"🎯 Secteurs: {', '.join(actor['target_sectors'][:5])}")

            if st.button(f"📋 Profil complet", key=f"actor_{actor['id']}"):
                detail = api_get(f"/threat-actors/{actor['id']}")
                if detail:
                    st.json(detail)


# ============================================================================
# Page - Tendances
# ============================================================================

def page_trends():
    """Analyse des tendances."""
    st.header("📈 Tendances et patterns")

    days = st.slider("Période d'analyse (jours)", 7, 90, 30, key="trend_days")
    trends = api_get("/trends", {"days": days})
    if not trends:
        return

    col1, col2 = st.columns(2)

    with col1:
        # Top threat actors
        top_actors = trends.get("top_actors", [])
        if top_actors:
            df = pd.DataFrame(top_actors)
            fig = px.bar(df, x="name", y="count",
                        title="🎯 Threat Actors les plus actifs",
                        color="count", color_continuous_scale="Reds")
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Top malwares
        top_malwares = trends.get("top_malwares", [])
        if top_malwares:
            df = pd.DataFrame(top_malwares)
            fig = px.bar(df, x="name", y="count",
                        title="🦠 Malwares les plus mentionnés",
                        color="count", color_continuous_scale="Oranges")
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    # Top vulnérabilités
    top_vulns = trends.get("top_vulnerabilities", [])
    if top_vulns:
        df = pd.DataFrame(top_vulns)
        fig = px.bar(df, x="cve_id", y="mention_count",
                    title="🔓 Vulnérabilités les plus référencées",
                    color="cvss_score", color_continuous_scale="YlOrRd")
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)


# ============================================================================
# Page - MITRE ATT&CK
# ============================================================================

def page_mitre():
    """Heatmap MITRE ATT&CK."""
    st.header("🗺️ MITRE ATT&CK Heatmap")

    days = st.slider("Période (jours)", 7, 90, 30, key="mitre_days")
    data = api_get("/mitre-heatmap", {"days": days})
    if not data:
        return

    heatmap_data = data.get("heatmap", {})
    if not heatmap_data:
        st.info("Pas assez de données TTP pour générer la heatmap.")
        return

    # Construire la matrice
    tactics = sorted(set(
        tactic
        for techniques in heatmap_data.values()
        for tactic in (heatmap_data.keys() if isinstance(heatmap_data, dict) else [])
    ))

    if isinstance(heatmap_data, dict):
        tactics_list = list(heatmap_data.keys())
        all_techniques = []
        z_data = []

        for tactic in tactics_list:
            techniques = heatmap_data[tactic]
            if isinstance(techniques, dict):
                for tech_name, count in techniques.items():
                    all_techniques.append(tech_name)

        all_techniques = list(set(all_techniques))

        z_matrix = []
        for tactic in tactics_list:
            row = []
            techniques = heatmap_data[tactic]
            for tech in all_techniques:
                row.append(techniques.get(tech, 0) if isinstance(techniques, dict) else 0)
            z_matrix.append(row)

        if all_techniques and tactics_list:
            fig = go.Figure(data=go.Heatmap(
                z=z_matrix,
                x=all_techniques,
                y=tactics_list,
                colorscale="YlOrRd",
                hoverongaps=False,
            ))
            fig.update_layout(
                title="Matrice MITRE ATT&CK",
                height=600,
                xaxis_title="Techniques",
                yaxis_title="Tactiques",
            )
            st.plotly_chart(fig, use_container_width=True)


# ============================================================================
# Page - Graphe
# ============================================================================

def page_graph():
    """Graphe de relations entre entités."""
    st.header("🕸️ Graphe de corrélation")

    graph = api_get("/graph")
    if not graph:
        return

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    if not nodes:
        st.info("Pas assez de données pour construire le graphe.")
        return

    st.caption(f"📊 {len(nodes)} nœuds, {len(edges)} relations")

    # Visualisation avec Plotly (réseau simplifié)
    import random

    node_positions = {}
    type_colors = {
        "article": "#00bfff", "vulnerability": "#ff4444",
        "ioc": "#ffd700", "threat_actor": "#ff8c00",
        "malware": "#ff00ff", "campaign": "#00ff00",
    }

    for node in nodes:
        node_positions[node["id"]] = (random.uniform(-1, 1), random.uniform(-1, 1))

    edge_x, edge_y = [], []
    for edge in edges:
        src = edge.get("source", edge.get("from"))
        tgt = edge.get("target", edge.get("to"))
        if src in node_positions and tgt in node_positions:
            x0, y0 = node_positions[src]
            x1, y1 = node_positions[tgt]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=0.5, color="#444"),
        hoverinfo="none",
    ))

    for node_type, color in type_colors.items():
        filtered = [n for n in nodes if n.get("type") == node_type]
        if filtered:
            fig.add_trace(go.Scatter(
                x=[node_positions[n["id"]][0] for n in filtered],
                y=[node_positions[n["id"]][1] for n in filtered],
                mode="markers+text",
                marker=dict(size=12, color=color),
                text=[n.get("label", n["id"]) for n in filtered],
                textposition="top center",
                name=node_type,
            ))

    fig.update_layout(
        title="Graphe de relations",
        height=700,
        showlegend=True,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    st.plotly_chart(fig, use_container_width=True)


# ============================================================================
# Page - Apprentissage
# ============================================================================

def page_learning():
    """Module d'apprentissage avec flashcards."""
    st.header("🎓 Apprentissage CTI")

    tab1, tab2 = st.tabs(["🃏 Flashcards", "📊 Statistiques"])

    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            category = st.selectbox("Catégorie", ["Toutes", "vulnerability", "malware", "threat_actor", "technique"])
        with col2:
            difficulty = st.selectbox("Difficulté", ["Toutes", "easy", "medium", "hard"])

        params = {"limit": 10}
        if category != "Toutes":
            params["category"] = category
        if difficulty != "Toutes":
            params["difficulty"] = difficulty

        cards = api_get("/flashcards", params)
        if not cards:
            st.info("Aucune flashcard disponible. Lancez le traitement des articles pour en générer.")
            return

        if "card_index" not in st.session_state:
            st.session_state.card_index = 0
        if "show_answer" not in st.session_state:
            st.session_state.show_answer = False

        idx = st.session_state.card_index % len(cards)
        card = cards[idx]

        st.subheader(f"📝 Question ({idx + 1}/{len(cards)})")
        st.info(card["question"])

        if st.session_state.show_answer:
            st.success(card["answer"])

            bcol1, bcol2, bcol3 = st.columns(3)
            with bcol1:
                if st.button("✅ Correct", use_container_width=True):
                    api_post(f"/flashcards/{card['id']}/answer", {"correct": True})
                    st.session_state.card_index += 1
                    st.session_state.show_answer = False
                    st.rerun()
            with bcol2:
                if st.button("❌ Incorrect", use_container_width=True):
                    api_post(f"/flashcards/{card['id']}/answer", {"correct": False})
                    st.session_state.card_index += 1
                    st.session_state.show_answer = False
                    st.rerun()
            with bcol3:
                if st.button("⏭️ Passer", use_container_width=True):
                    st.session_state.card_index += 1
                    st.session_state.show_answer = False
                    st.rerun()
        else:
            if st.button("💡 Voir la réponse", use_container_width=True):
                st.session_state.show_answer = True
                st.rerun()

    with tab2:
        st.subheader("📊 Vos statistiques d'apprentissage")
        st.info("Les statistiques détaillées seront disponibles après plusieurs sessions de révision.")


# ============================================================================
# Page - Opérations
# ============================================================================

def page_operations():
    """Gestion des sources et opérations."""
    st.header("⚙️ Opérations & Configuration")

    tab1, tab2, tab3 = st.tabs(["📡 Sources", "📤 Export", "🔧 Maintenance"])

    with tab1:
        sources = api_get("/sources")
        if sources:
            st.subheader("Sources de collecte configurées")
            df = pd.DataFrame(sources) if isinstance(sources, list) else pd.DataFrame()
            if not df.empty:
                st.dataframe(df, use_container_width=True)
            else:
                st.json(sources)

    with tab2:
        st.subheader("📤 Export de données")

        col1, col2 = st.columns(2)
        with col1:
            export_days = st.slider("Période (jours)", 1, 90, 7, key="export_days")
        with col2:
            export_format = st.selectbox("Format IOC", ["json", "csv", "txt"])

        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button("📦 Export STIX 2.1", use_container_width=True):
                data = api_get("/export/stix", {"days": export_days})
                if data:
                    st.download_button(
                        "📥 Télécharger le bundle STIX",
                        json.dumps(data, indent=2),
                        "cti_sentinel_stix.json",
                        "application/json",
                    )
        with bcol2:
            if st.button("🔍 Export IOCs", use_container_width=True):
                data = api_get("/export/iocs", {"days": export_days, "format": export_format})
                if data:
                    st.download_button(
                        f"📥 Télécharger les IOCs ({export_format})",
                        json.dumps(data, indent=2) if isinstance(data, list) else str(data),
                        f"iocs.{export_format}",
                    )

    with tab3:
        st.subheader("🔧 Maintenance")
        st.warning("⚠️ Les opérations de maintenance sont irréversibles.")
        st.info("Utilisez les commandes CLI pour les opérations de backup et nettoyage.")


# ============================================================================
# Point d'entrée
# ============================================================================

def main():
    """Point d'entrée principal du dashboard."""
    page = sidebar()

    page_map = {
        "📊 Vue d'ensemble": page_overview,
        "📰 Articles": page_articles,
        "🔓 Vulnérabilités": page_vulnerabilities,
        "🔍 IOCs": page_iocs,
        "👤 Threat Actors": page_threat_actors,
        "📈 Tendances": page_trends,
        "🗺️ MITRE ATT&CK": page_mitre,
        "🕸️ Graphe": page_graph,
        "🎓 Apprentissage": page_learning,
        "⚙️ Opérations": page_operations,
    }

    handler = page_map.get(page, page_overview)
    handler()


if __name__ == "__main__":
    main()
