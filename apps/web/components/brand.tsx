import { ShieldCheck } from "lucide-react";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand" aria-label="Sentinel Edge">
      <span className="brand-mark" aria-hidden="true"><ShieldCheck size={19} strokeWidth={2.2} /></span>
      {compact ? null : (
        <span className="brand-copy">
          <strong>Sentinel</strong>
          <span>Edge</span>
        </span>
      )}
    </div>
  );
}
