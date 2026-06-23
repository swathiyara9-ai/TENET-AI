import type { ReactNode } from 'react';

interface ChartCardProps {
  title: string;
  description: string;
  children: ReactNode;
  headerExtra?: ReactNode;
  className?: string;
}

export function ChartCard({ title, description, children, headerExtra, className = '' }: ChartCardProps) {
  return (
    <section
      className={`chart-container ${className}`}
      aria-label={title}
      role="img"
      aria-describedby={`chart-desc-${title.replace(/\s+/g, '-').toLowerCase()}`}
    >
      <div className="chart-header">
        <div>
          <h3>{title}</h3>
          <p id={`chart-desc-${title.replace(/\s+/g, '-').toLowerCase()}`} className="chart-sr-summary">
            {description}
          </p>
        </div>
        {headerExtra}
      </div>
      {children}
    </section>
  );
}
