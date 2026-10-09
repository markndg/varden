import React from 'react';

type MetricCardProps = {
  title: string;
  value: any;
  subtitle: string;
  tone?: string;
  trend?: string;
  onClick?: () => void;
};

function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ');
}

export function MetricCard({ title, value, subtitle, tone, trend, onClick }: MetricCardProps) {
  const Tag: any = onClick ? 'button' : 'div';
  return (
    <Tag
      className={classNames('metricCard', tone && `metricCard--${tone}`, onClick && 'metricCard--interactive')}
      onClick={onClick}
      type={onClick ? 'button' : undefined}
    >
      <div className="metricCard__title">{title}</div>
      <div className="metricCard__value">{value}</div>
      <div className="metricCard__subtitle">{subtitle}</div>
      {trend ? <div className="metricCard__trend">{trend}</div> : null}
    </Tag>
  );
}

export function Stat({ label, value }: { label: string; value: any }) {
  return <div className="stat"><span>{label}</span><strong>{value}</strong></div>;
}

export function KeyValue({ label, value, displayValue }: { label: string; value: any; displayValue: (value: any) => string }) {
  return <div className="kv"><span>{label}</span><strong>{displayValue(value)}</strong></div>;
}

export function CodeCard({ title, value, displayValue }: { title: string; value: any; displayValue: (value: any) => string }) {
  return (
    <div className="codeCard">
      <div className="subheading">{title}</div>
      <pre>{displayValue(value)}</pre>
    </div>
  );
}
