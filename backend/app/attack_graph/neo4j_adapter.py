"""Optional Neo4j graph database adapter.

When NEO4J_URI is set, the attack graph is mirrored into Neo4j so advanced
Cypher queries and graph visualization tools can be used. The relational engine
remains the source of truth so the platform runs fully without Neo4j.
"""

from typing import Any

from app.config import settings
from app.models.graph import AttackPath


class Neo4jAdapter:
    @property
    def enabled(self) -> bool:
        return bool(settings.NEO4J_URI)

    def _driver(self):
        from neo4j import GraphDatabase  # imported lazily

        return GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USERNAME or "neo4j", settings.NEO4J_PASSWORD or ""),
        )

    def health_check(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "NEO4J_URI not configured"
        try:
            with self._driver() as driver:
                driver.verify_connectivity()
            return True, "Neo4j reachable"
        except Exception as exc:  # noqa: BLE001
            return False, f"Neo4j unreachable: {exc}"

    def sync_path(self, path: AttackPath) -> None:
        if not self.enabled:
            return
        with self._driver() as driver, driver.session() as session:
            session.run(
                "MATCH (p:AttackPath) WHERE p.path_id = $pid DELETE p", pid=str(path.id)
            )
            for node in path.nodes_json or []:
                session.run(
                    "MERGE (n:Node { id: $id }) SET n.label = $label, n.source = $source, n.risk = $risk",
                    id=node.get("id"), label=node.get("label"), source=node.get("source"), risk=node.get("risk"),
                )
            for edge in path.edges_json or []:
                session.run(
                    "MATCH (a:Node {id:$from}), (b:Node {id:$to}) "
                    "MERGE (a)-[r:REL {rel:$rel, path_id:$pid}]->(b) "
                    "SET r.rel = $rel, r.path_id = $pid",
                    from_=edge.get("from"), to=edge.get("to"), rel=edge.get("rel"), pid=str(path.id),
                ) if False else None
            # slightly safer keyword handling
            for edge in path.edges_json or []:
                cypher = (
                    "MATCH (a:Node {id:$from}), (b:Node {id:$to}) "
                    "MERGE (a)-[:REL {rel:$rel, path_id:$pid}]->(b)"
                )
                session.run(cypher, from_=edge.get("from"), to=edge.get("to"), rel=edge.get("rel"), pid=str(path.id))


neo4j_adapter = Neo4jAdapter()