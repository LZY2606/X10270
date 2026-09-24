import React from "react";

export function Hex({ children }: { children: string }) {
  return <code className="hex">{children}</code>;
}

export function Range({ start, end }: { start: number; end: number }) {
  return (
    <span className="range" title="单位 byte · 基准 container-offset">
      [{start}, {end})
    </span>
  );
}

export function Badge({ kind, children }: { kind: string; children: React.ReactNode }) {
  return <span className={`badge badge-${kind}`}>{children}</span>;
}

const RESULT_STYLE: Record<string, string> = {
  ok: "ok",
  partial: "warn",
  "budget-exhausted": "budget",
  corrupt: "bad",
  "semantically-unsolvable": "bad",
};

export function ResultBadge({ resultClass }: { resultClass: string }) {
  const labels: Record<string, string> = {
    ok: "OK",
    partial: "部分通过",
    "budget-exhausted": "预算耗尽",
    corrupt: "格式损坏",
    "semantically-unsolvable": "语义无解",
  };
  return <Badge kind={RESULT_STYLE[resultClass] ?? "warn"}>{labels[resultClass] ?? resultClass}</Badge>;
}

export function Evidence({ evidence }: { evidence: any }) {
  if (!evidence) return <span className="muted">无失败字节</span>;
  const toHex = (a?: number[]) => (a ?? []).map((x) => x.toString(16).padStart(2, "0")).join(" ");
  return (
    <div className="evidence" data-testid="failure-bytes">
      <div>
        <span className="muted">实际字节：</span>
        <Hex>{toHex(evidence.actual) || "(空)"}</Hex>
      </div>
      {evidence.expected ? (
        <div>
          <span className="muted">期望字节：</span>
          <Hex>{toHex(evidence.expected)}</Hex>
        </div>
      ) : null}
      <div className="muted">
        证据区间 <Range start={evidence.range.start} end={evidence.range.end} />（单位 byte）
      </div>
    </div>
  );
}

const BAND_COLORS: Record<string, string> = {
  "code-covered": "band-covered",
  "signature-blob": "band-signature",
  uncovered: "band-uncovered",
  "tail-gap": "band-tail",
};

export function SliceMap({ parse }: { parse: any }) {
  const size = Math.max(1, parse.containerSize);
  return (
    <div className="slice-map">
      <div className="map-ruler muted">
        容器坐标：0 … {parse.containerSize} byte（{parse.fat ? `${parse.fat.flavor} / ${parse.fat.declaredEndian}-endian` : "thin Mach-O"}）
      </div>
      <div className="map-track">
        {parse.slices.map((s: any) => (
          <div
            key={s.id}
            className="map-slice"
            style={{
              left: `${(s.descriptor.range.start / size) * 100}%`,
              width: `${Math.max(2, ((s.descriptor.range.end - s.descriptor.range.start) / size) * 100)}%`,
            }}
            title={`${s.id} ${s.descriptor.archName} [${s.descriptor.range.start},${s.descriptor.range.end})`}
          >
            <span className="map-slice-label">
              {s.id} · {s.descriptor.archName}
            </span>
          </div>
        ))}
      </div>
      {parse.slices.map((s: any) => (
        <CoverageStrip key={`cov-${s.id}`} slice={s} />
      ))}
    </div>
  );
}

function CoverageStrip({ slice }: { slice: any }) {
  const span = Math.max(1, slice.descriptor.range.end - slice.descriptor.range.start);
  const base = slice.descriptor.range.start;
  return (
    <div className="coverage-block">
      <div className="coverage-title">
        {slice.id} · {slice.descriptor.archName} · 签名覆盖带
      </div>
      <div className="coverage-track">
        {slice.signature?.coverage.map((b: any) => (
          <div
            key={b.id}
            className={`coverage-seg ${BAND_COLORS[b.kind]}`}
            style={{
              marginLeft: `${((b.range.start - base) / span) * 100}%`,
              width: `${Math.max(0.5, ((b.range.end - b.range.start) / span) * 100)}%`,
            }}
            title={`${b.label} [${b.range.start},${b.range.end})`}
          />
        )) ?? <span className="muted">无签名</span>}
      </div>
      <div className="coverage-legend muted">
        <i className="dot band-covered" /> 代码页已覆盖
        <i className="dot band-signature" /> 签名 blob
        <i className="dot band-uncovered" /> 覆盖缺口
        <i className="dot band-tail" /> 未覆盖尾部
      </div>
    </div>
  );
}
