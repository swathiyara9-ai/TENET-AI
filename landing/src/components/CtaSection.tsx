import React, { useState, useEffect, useRef } from 'react';

function FadeUp({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setVisible(true);
        observer.disconnect();
      }
    }, { threshold: 0.05 });

    if (ref.current) {
      observer.observe(ref.current);
    }
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'none' : 'translateY(16px)',
        transition: `opacity 0.5s ${delay}s ease-out, transform 0.5s ${delay}s ease-out`
      }}
    >
      {children}
    </div>
  );
}

export default function CtaSection() {
  const handleScrollToDownload = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const el = document.getElementById('download');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section className="cta" aria-label="Call to Action">
      <div className="cta-glow" />
      <div className="container">
        <FadeUp>
          <h2 className="cta-title">
            Start protecting your<br /><span className="grad">AI applications today</span>
          </h2>
          <p className="cta-sub">Self-hosted. Open source. Zero vendor lock-in.</p>
          
          <div className="cta-btns">
            <a href="#download" className="btn btn-primary btn-xl" onClick={handleScrollToDownload}>
              Download SDK
            </a>
            <a 
              href="https://github.com/TENET-DEV-AI/TENET-AI" 
              target="_blank" 
              rel="noreferrer" 
              className="btn btn-outline btn-xl"
            >
              View on GitHub
            </a>
          </div>

          <div className="cta-chips">
            {["MIT Licensed", "Self-hosted option", "Any LLM provider", "No usage telemetry"].map((chip, i) => (
              <span key={i} className="cta-chip">
                {chip}
              </span>
            ))}
          </div>
        </FadeUp>
      </div>
    </section>
  );
}
