import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import ReactFlow, {
  Background, Controls, MiniMap, MarkerType, useNodesState, useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";
import { api } from "../lib/api";
import { PageHeader, StatusBadge, EmptyState, PageSpinner } from "../components/badges";
import { StatCard, Spinner } from "../components/ui";
import { Network, RefreshCw } from "lucide-react";
import type { AttackPath } from "../lib/types";
import { useState, useMemo } from "react";

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  asset: { bg: "#ffffff", border: "#0ea5e9", text: "#0369a1" },
  service: { bg: "#ffffff", border: "#818cf8", text: "#4338ca" },
  vuln: { bg: "#fff1f2", border: "#dc2626", text: "#b91c1c" },
  privilege: { bg: "#fffbeb", border: "#f59e0b", text: "#b45309" },
  critical: { bg: "#ecfeff", border: "#06b6d4", text: "#0e7490" },
};

function buildFlattener(nodesJson: any[]) {
  return function flatten(): any[] {
    const out: any[] = [];
    const walk = (arr: any[]) => {
      for (const n of arr) {
        if (Array.isArray(n) && n.length && typeof n[0] === "object") {
          walk(n);
        } else if (n && typeof n === "object" && n.label) {
          out.push(n);
        } else if (typeof n === "string") {
          out.push({ label: n, node_type: "node" });
        }
      }
    };
    walk(nodesJson);
    return out;
  };
}

function PathCard({ path }: { path: AttackPath }) {
  const nodes = useMemo(() => {
    return buildFlattener(path.nodes_json ?? [])().filter(Boolean);
  }, [path.nodes_json]);

  if (nodes.length === 0) {
    return (
      <div className="card p-5">
        <div className="flex items-center justify-between">
          <span className="font-bold text-ink">{path.name}</span>
          <span className="text-sm font-bold text-violet-700">{path.cumulative_risk.toFixed(1)} risk</span>
        </div>
        <p className="mt-2 text-xs text-ink-faint">Steps unavailable.</p>
      </div>
    );
  }

  const colorFor = (t: string) => NODE_COLORS[t] ?? { bg: "#fff", border: "#64748b", text: "#334155" };

  return (
    <div className="card overflow-hidden">
      <div className="border-b border-slate-100 px-5 py-3.5">
        <div className="flex items-center justify-between">
          <div>
            <span className="font-bold text-ink">{path.name}</span>
            <div className="mt-1 flex items-center gap-2 text-[11px] text-ink-faint">
              <StatusBadge status={path.path_length >= 4 ? "critical" : "verified"} />
              <span>path length {path.path_length}</span>
              <span>confidence {path.confidence}%</span>
              <span>{path.vulnerability_count} vulnerability(ies)</span>
            </div>
          </div>
          <div className="text-right">
            <p className="text-2xl font-extrabold text-violet-700">{path.cumulative_risk.toFixed(1)}</p>
            <p className="text-[10px] uppercase tracking-wide text-ink-faint">cumulative risk</p>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1.5 p-5">
        {nodes.map((n, i) => {
          const c = colorFor(n.node_type);
          return (
            <React.Fragment key={i}>
              {i > 0 && <span className="text-ink-faint">→</span>}
              <span
                className="rounded-lg border px-2.5 py-1.5 text-xs font-semibold"
                style={{ borderColor: c.border, backgroundColor: c.bg, color: c.text }}
              >
                {String(n.label).split(":").length > 1 ? String(n.label).split(":").slice(-1)[0] : n.label}
              </span>
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

function GraphView({ paths }: { paths: AttackPath[] }) {
  const [rfNodes, setNodes, onNodesChange] = useNodesState([]);
  const [rfEdges, setEdges, onEdgesChange] = useEdgesState([]);

  React.useEffect(() => {
    const nodes: any[] = [];
    const edges: any[] = [];
    const nodeIds = new Set<string>();
    let x = 60;
    let y = 80;

    const ensureNode = (id: string, label: string, type: string) => {
      if (nodeIds.has(id)) return;
      nodeIds.add(id);
      const c = NODE_COLORS[type] ?? { bg: "#fff", border: "#64748b", text: "#334155" };
      nodes.push({
        id,
        position: { x, y },
        data: { label },
        style: {
          border: `2px solid ${c.border}`,
          background: c.bg,
          color: c.text,
          borderRadius: 10,
          padding: "8px 12px",
          fontSize: 12,
          fontWeight: 600,
        },
      });
      y += 90;
      if (y > 380) {
        y = 80;
        x += 250;
      }
    };

    for (const p of paths) {
      const raw: any[] = buildFlattener(p.nodes_json ?? [])().filter(Boolean);
      let prevId: string | null = null;
      raw.forEach((n, i) => {
        const label = String(n.label ?? `node-${i}`);
        const id = `${p.id}-${label}`;
        ensureNode(id, label, n.node_type);
        if (prevId) {
          edges.push({
            id: `${prevId}-${id}`,
            source: prevId,
            target: id,
            type: "smoothstep",
            animated: true,
            style: { stroke: "#818cf8", strokeWidth: 1.5 },
            markerEnd: { type: MarkerType.ArrowClosed, color: "#818cf8" },
          });
        }
        prevId = id;
      });
    }

    setNodes(nodes);
    setEdges(edges);
  }, [paths]);

  return (
    <div className="card h-[560px] overflow-hidden">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        attributionPosition="bottom-right"
      >
        <Background gap={18} size={1} color="#e2e8f0" />
        <MiniMap nodeColor="#0284c7" maskColor="rgba(255,255,255,0.7)" pannable zoomable />
        <Controls />
      </ReactFlow>
    </div>
  );
}

export default function AttackPathsPage() {
  const { id } = useParams();
  const aid = Number(id);
  const [near, setNear] = useState(true);
  const [approved, setApproved] = useState<boolean>(false);

  const { data: paths, isLoading, refetch } = useQuery({
    queryKey: ["attack-paths", aid],
    queryFn: async () => (await api.get<AttackPath[]>("/attack-paths", { params: { assessment_id: aid } })).data,
  });

  const { data: summaryData } = useQuery({
    queryKey: ["graph-summary", aid],
    queryFn: async () => (await api.get<any>("/attack-paths/graph/summary", { params: { assessment_id: aid } })).data,
  });

  const rebuild = async () => {
    setNear(true);
    try {
      await api.post("/attack-paths/build", null, { params: { assessment_id: aid } });
      setApproved(true);
      setTimeout(() => refetch(), 2000);
    } catch {
      setApproved(false);
    } finally {
      setNear(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="Attack Paths"
        subtitle="Logical chains from exposure to critical assets — how an attacker chains findings."
        actions={
          <button className="btn-secondary" onClick={rebuild} disabled={near}>
            {near ? <Spinner className="h-4 w-4" /> : <RefreshCw size={15} />} Rebuild paths
          </button>
        }
      />

      {summaryData && (
        <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Paths" value={summaryData.path_count} icon={<Network size={18} />} tone="violet" />
          <StatCard label="Graph Nodes" value={summaryData.node_count} icon={<Network size={18} />} />
          <StatCard label="Graph Edges" value={summaryData.edge_count} icon={<Network size={18} />} />
          <StatCard label="Max Path Risk" value={summaryData.max_risk ?? 0} icon={<Network size={18} />} tone="amber" />
        </div>
      )}

      {isLoading ? (
        <PageSpinner />
      ) : !paths?.length ? (
        <EmptyState
          icon={<Network size={40} />}
          title="No attack paths yet"
          subtitle="Run attack path analysis to build exploitation chains across the assessment."
        />
      ) : (
        <div className="space-y-6">
          <GraphView paths={paths} />
          <div className="space-y-3">
            {paths.map((p) => (
              <PathCard key={p.id} path={p} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}