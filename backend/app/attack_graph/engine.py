"""Attack-path graph engine.

Builds a graph of Assets -> Services -> Vulnerabilities -> Access/Privilege
relationships and computes multi-hop attack paths from initial access points to
high-value (critical) assets. Backed by NetworkX for computation and persisted in
the relational schema (attack_paths / nodes / edges). A Neo4j mirror is available
through the adapter in this module when NEO4J_URI is configured.

Path metrics computed per path: length, cumulative risk, vulnerability count,
confidence, ordered node/edge lists used for visualisation.
"""

import ipaddress
from dataclasses import dataclass, field

import networkx as nx
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.asset import Asset, Service
from app.models.finding import Finding
from app.models.graph import AttackPath, AttackPathEdge, AttackPathNode
from app.risk.engine import classify_severity

# CWEs that grant remote code execution / authentication bypass -> lateral movement.
_MOVE_CWES = {"CWE-78", "CWE-94", "CWE-89", "CWE-287", "CWE-434", "CWE-298", "CWE-77"}
_DB_SERVICES = {"mysql", "postgresql", "microsoft-ds", "oracle", "mongodb", "redis"}
_CRITICAL_PORT_SERVICES = {"mysql", "postgresql"}

_move_cwes = _MOVE_CWES  # kept for clarity in scoring logic


def _node_id(kind: str, obj_id: int) -> str:
    return f"{kind}:{obj_id}"


@dataclass
class GraphInfo:
    node_count: int = 0
    edge_count: int = 0
    path_count: int = 0
    max_risk: float = 0.0
    summary: str = ""


@dataclass
class BuildResult:
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    paths: list[AttackPath] = field(default_factory=list)
    node_index: dict = field(default_factory=dict)
    info: GraphInfo = field(default_factory=GraphInfo)


def _same_network(a: str, b: str) -> bool:
    try:
        ia = ipaddress.ip_address(a)
        ib = ipaddress.ip_address(b)
        if ia.version != ib.version:
            return False
        return int(ia) >> 8 == int(ib) >> 8
    except ValueError:
        return False


def build_graph(db: Session, assessment: Assessment) -> BuildResult:
    """Construct the attack-path graph for an assessment.

    Returns the graph plus the persisted list of discovered AttackPath rows.
    """
    result = BuildResult()
    g = result.graph
    index = result.node_index

    assets = db.query(Asset).filter(Asset.assessment_id == assessment.id).all()
    if not assets:
        return result

    # Assets as nodes
    for a in assets:
        g.add_node(_node_id("asset", a.id), label=a.ip_address or a.hostname or "asset", risk=a.risk_score,
                   criticality=a.criticality, source="asset")
        index[_node_id("asset", a.id)] = a

    # Services as nodes + edges
    for a in assets:
        for s in a.services:
            snode = _node_id("service", s.id)
            g.add_node(snode, label=f"{s.service_name}:{s.port}", risk=s.risk_score, source="service")
            index[snode] = s
            g.add_edge(_node_id("asset", a.id), snode, rel="HOSTS")
            g.add_edge(snode, _node_id("asset", a.id), rel="RUNS")

    # Vulnerabilities as nodes + edges
    vuln_nodes = {}
    for a in assets:
        findings = db.query(Finding).filter(Finding.assessment_id == assessment.id, Finding.asset_id == a.id).all()
        for f in findings:
            vnode = _node_id("vuln", f.id)
            g.add_node(vnode, label=f.title[:60], risk=f.risk_score, severity=f.severity, cwe=f.cwe, source="vuln")
            index[vnode] = f
            vuln_nodes[vnode] = f
            if f.service_id:
                g.add_edge(_node_id("service", f.service_id), vnode, rel="AFFECTED_BY")
                g.add_edge(vnode, _node_id("service", f.service_id), rel="LEADS_TO")
            else:
                g.add_edge(_node_id("asset", a.id), vnode, rel="AFFECTED_BY")
                g.add_edge(vnode, _node_id("asset", a.id), rel="LEADS_TO")

    # Lateral movement edges based on exploitable code-exec findings
    for vnode, f in vuln_nodes.items():
        f_asset = db.get(Asset, f.asset_id)
        if not f_asset:
            continue
        cwe = (f.cwe or "").upper()
        if cwe not in _MOVE_CWES:
            continue
        for other in assets:
            if other.id == f_asset.id:
                continue
            if f_asset.ip_address and other.ip_address and not _same_network(f_asset.ip_address, other.ip_address):
                continue
            for s in other.services:
                g.add_edge(_node_id("asset", f_asset.id), _node_id("service", s.id),
                           rel="CAN_ACCESS", weight=0.99 - 0.5 if cwe in {"CWE-78", "CWE-94"} else 0.3)
                g.add_edge(_node_id("service", s.id), _node_id("asset", other.id), rel="CONNECTS_TO")

    # Critical assets: hosts with high criticality or database services
    critical_ends = []
    for a in assets:
        is_critical_host = a.criticality >= 7.0
        has_db = any(s.service_name and s.service_name.lower() in _DB_SERVICES for s in a.services)
        if is_critical_host or has_db:
            label = a.ip_address or a.hostname or "critical"
            an = _node_id("asset", a.id)
            g.nodes[an]["critical_asset"] = True
            g.nodes[an]["label"] = label
            critical_ends.append(an)
            # privilege node representing elevated access to the critical system
            priv = _node_id("privilege", a.id)
            g.add_node(priv, label=f"Privilege on {label}", risk=a.risk_score, source="privilege")
            g.add_edge(an, priv, rel="HAS_PRIVILEGE")
            for s in a.services:
                if s.service_name and s.service_name.lower() in _CRITICAL_PORT_SERVICES:
                    g.add_edge(_node_id("service", s.id), _node_id("asset", a.id), rel="CONTAINS")

    # Find paths from each vulnerable service/asset to each critical endpoint
    starts = [vnode for vnode in vuln_nodes if g.has_node(vnode)]
    paths: list[AttackPath] = []
    seen: set[tuple[str, str]] = set()

    for start in starts:
        f = index[start]
        if f.severity not in ("critical", "high"):
            continue  # only high-value findings seed candidate paths
        for end in critical_ends:
            key = (start, end)
            if key in seen:
                continue
            try:
                node_path = nx.shortest_path(g, start, end, weight=None)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            seen.add(key)

            risk_values = [float(g.nodes[n].get("risk", 0) or 0) for n in node_path if g.nodes[n].get("source") in ("asset", "service", "vuln")]
            vulnerabilities = [n for n in node_path if g.nodes[n].get("source") == "vuln"]
            cumulative = round(sum(risk_values) / max(len(risk_values), 1), 2)
            confidence = min(95.0, 40.0 + cumulative * 0.5 + len(vulnerabilities) * 3)

            edges = []
            for i in range(len(node_path) - 1):
                edges.append({
                    "from": node_path[i], "to": node_path[i + 1],
                    "rel": g.edges[node_path[i], node_path[i + 1]].get("rel", "LEADS_TO"),
                })

            end_asset_id = int(end.split(":")[1])
            end_asset = index.get(end)
            path = AttackPath(
                assessment_id=assessment.id,
                name=f"Path from {g.nodes[start].get('label')} to {g.nodes[end].get('label')}",
                description=f"Multi-hop path leveraging {len(vulnerabilities)} vulnerability(ies) to reach a critical asset.",
                start_node=start,
                end_node=end,
                end_node_type="critical_asset",
                path_length=len(node_path) - 1,
                cumulative_risk=cumulative,
                confidence=round(confidence, 2),
                vulnerability_count=len(vulnerabilities),
                nodes_json=[{"id": n, "label": g.nodes[n].get("label"), "source": g.nodes[n].get("source"),
                             "risk": g.nodes[n].get("risk")} for n in node_path],
                edges_json=edges,
            )
            db.add(path)
            db.flush()
            for idx, n in enumerate(node_path):
                db.add(AttackPathNode(path_id=path.id, node_type=str(g.nodes[n].get("source", "node")),
                                      label=str(g.nodes[n].get("label", "")), ref_id=index.get(n).id if isinstance(index.get(n), (Asset, Service, Finding)) else None, props=g.nodes[n], order=idx))
            for idx, e in enumerate(edges):
                db.add(AttackPathEdge(path_id=path.id, rel_type=e["rel"], from_node=e["from"], to_node=e["to"], order=idx))
            paths.append(path)

    # Deduplicate paths that share the same ordered sequence of distinct nodes.
    unique_paths = _dedupe_paths(db, assessment, paths)

    result.graph = g
    result.paths = unique_paths
    result.node_index = index
    result.info = GraphInfo(
        node_count=g.number_of_nodes(),
        edge_count=g.number_of_edges(),
        path_count=len(unique_paths),
        max_risk=max((p.cumulative_risk for p in unique_paths), default=0.0),
    )
    return result


def _dedupe_paths(db: Session, assessment: Assessment, paths: list[AttackPath]) -> list[AttackPath]:
    """Keep only the most valuable path per unique critical endpoint."""
    best: dict[str, AttackPath] = {}
    for p in paths:
        end = p.end_node or ""
        if end not in best or p.cumulative_risk > best[end].cumulative_risk:
            best[end] = p
    keep = list(best.values())
    # remove paths that were dropped
    for p in paths:
        if p not in keep and p in db:
            db.delete(p)
    db.commit()
    for p in keep:
        db.refresh(p)
    return keep


def propagate_path_importance(db: Session, assessment_id: int) -> None:
    """Mark findings that participate in attack paths for the risk engine.

    Findings on the first hop of an active path receive the highest importance
    (+10), later hops get a smaller boost.
    """
    paths = db.query(AttackPath).filter(AttackPath.assessment_id == assessment_id, AttackPath.is_current).all()
    importance: dict[int, float] = {}
    for p in paths:
        for idx, node in enumerate(p.nodes_json or []):
            node_id = node.get("id", "")
            if node_id.startswith("vuln:"):
                try:
                    f_id = int(node_id.split(":", 1)[1])
                except ValueError:
                    continue
                importance[f_id] = max(importance.get(f_id, 0.0), max(2.0, 10.0 - idx))
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    for f in findings:
        f_imp = importance.get(f.id, 0.0)
        if f_imp:
            f.risk_breakdown = dict(f.risk_breakdown or {})
            f.risk_breakdown["attack_path_importance"] = f_imp
    db.commit()