import React from 'react';

type MiniTimelineProps = {
  data: any[];
  selectedTimestamp?: number | null;
  sourceEvents?: any[];
  onSelectBucket?: (timestamp: number | null, eventIds?: number[]) => void;
  helpers: {
    normalizeEventRow: (event: any) => any;
    classNames: (...parts: Array<string | false | null | undefined>) => string;
    fmtTs: (ts?: number) => string;
    fmtNum: (value?: number | null, digits?: number) => string;
  };
};

export function MiniTimeline({ data, selectedTimestamp, sourceEvents, onSelectBucket, helpers }: MiniTimelineProps) {
  const { normalizeEventRow, classNames, fmtTs, fmtNum } = helpers;
  const events = (sourceEvents || []).map(normalizeEventRow);
  const maxSeverity = Math.max(...(data || []).map((d) => ((d.blocked || 0) * 1) + ((d.warned || 0) * 0.65) + ((d.monitor || 0) * 0.45) + ((d.allowed || 0) * 0.3)), 1);
  const maxLatency = Math.max(...(data || []).map((d) => Number(d.avg_latency_ms || 0)), 1);
  return (
    <div className="timelineChart timelineChart--interactive">
      {(data || []).map((point, idx) => {
        const blocked = Number(point.blocked || 0);
        const warned = Number(point.warned || 0);
        const monitor = Number(point.monitor || 0);
        const allowed = Number(point.allowed || 0);
        const severity = (blocked * 1) + (warned * 0.65) + (monitor * 0.45) + (allowed * 0.3);
        const height = Math.max(16, (severity / maxSeverity) * 100);
        const total = blocked + warned + monitor + allowed || 1;
        const bucketStart = Math.floor(Number(point.timestamp || 0) / 60) * 60;
        const eventIds = events.filter((event) => Math.floor(Number(event.timestamp || 0) / 60) * 60 === bucketStart).map((event) => event.id);
        const latency = Number(point.avg_latency_ms || 0);
        const latencyOffset = latency > 0 ? Math.max(8, Math.min(98, (latency / maxLatency) * 100)) : 0;
        return (
          <button
            type="button"
            key={idx}
            className={classNames('timelineChart__barWrap', selectedTimestamp === point.timestamp && 'is-active')}
            title={`${fmtTs(point.timestamp)} · blocked ${blocked} · warned ${warned} · monitor ${monitor} · allowed ${allowed} · linked ${eventIds.length}${latency ? ` · avg latency ${fmtNum(latency, 1)} ms` : ''}`}
            onClick={() => onSelectBucket?.(point.timestamp, eventIds)}
          >
            <div className="timelineChart__plot">
              {latency > 0 ? <div className="timelineChart__latencyMarker" style={{ bottom: `${latencyOffset}%` }}><span className="timelineChart__latencyDot" /></div> : null}
              <div className="timelineChart__bar timelineChart__bar--stacked" style={{ height: `${height}%` }}>
                <span className="timelineChart__segment timelineChart__segment--danger" style={{ height: `${Math.max(12, (blocked / total) * 100)}%` }} />
                <span className="timelineChart__segment timelineChart__segment--warn" style={{ height: `${Math.max(10, (warned / total) * 100)}%` }} />
                <span className="timelineChart__segment timelineChart__segment--monitor" style={{ height: `${Math.max(9, (monitor / total) * 100)}%` }} />
                <span className="timelineChart__segment timelineChart__segment--ok" style={{ height: `${Math.max(8, (allowed / total) * 100)}%` }} />
              </div>
            </div>
            <span className="timelineChart__count">{eventIds.length}</span>
            <span className="timelineChart__label">{new Date(point.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            <span className="timelineChart__latencyValue">{latency ? `${fmtNum(latency, 0)} ms` : '—'}</span>
          </button>
        );
      })}
    </div>
  );
}
