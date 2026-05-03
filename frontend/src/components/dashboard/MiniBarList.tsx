import React from 'react';

type MiniBarListProps = {
  title: string;
  items: Array<{ label: string; value: number }>;
};

export function MiniBarList({ title, items }: MiniBarListProps) {
  const max = Math.max(...items.map((item) => item.value), 1);
  return (
    <div>
      <div className="subheading">{title}</div>
      <div className="barList">
        {items.map((item) => (
          <div key={item.label} className="barList__row">
            <span>{item.label}</span>
            <div className="barList__track"><div className="barList__fill" style={{ width: `${(item.value / max) * 100}%` }} /></div>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
