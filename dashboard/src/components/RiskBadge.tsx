type Level = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH';
const MAP: Record<Level, { cls: string; label: string }> = {
  CLEAN:  { cls: 'badge-clean',  label: 'CLEAN'  },
  LOW:    { cls: 'badge-low',    label: 'LOW'    },
  MEDIUM: { cls: 'badge-medium', label: 'MEDIUM' },
  HIGH:   { cls: 'badge-high',   label: 'HIGH'   },
};

export default function RiskBadge({ level }: { level: string }) {
  const cfg = MAP[level as Level] ?? MAP.CLEAN;
  return <span className={`risk-badge ${cfg.cls}`}>{cfg.label}</span>;
}
