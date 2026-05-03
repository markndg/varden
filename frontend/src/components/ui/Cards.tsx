import React from 'react';

type MetricCardProps = {
  title: string;
  value: any;
  subtitle: string;
  tone?: string;
  onClick?: () => void;
};

function classNames(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ');
}

export function MetricCard({ title, value, subtitle, tone, onClick }: MetricCardProps) {
  const Tag: any = onClick ? 'button' : 'div';
  return (
    <Tag className={classNames('metricCard', tone && `metricCard--${tone}`, onClick && 'metricCard--interactive')} onClick={onClick}>
      <div className="metricCard__title">{title}</div>
      <div className="metricCard__value">{value}</div>
      <div className="metricCard__subtitle">{subtitle}</div>
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
