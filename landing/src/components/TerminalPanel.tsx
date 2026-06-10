import React, { useState, useEffect } from 'react';

interface LogEntry {
  id?: string;
  tag: string;
  tc: string; // text color
  tb: string; // background color
  msg: string;
  src: string;
}

const LOGS: LogEntry[] = [
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'prompt_injection · ignore_instructions', src: 'api.prod' },
  { tag: 'ALLOWED', tc: 'var(--green)', tb: 'var(--green-dim)', msg: 'normal_query · risk_score:0.02', src: 'chat.app' },
  { tag: 'LEARNING', tc: 'var(--text2)', tb: 'var(--surface3)', msg: 'threat database synchronized · version:2.4.1', src: 'daemon.sys' },
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'jailbreak · DAN_mode variant', src: 'agt.01' },
  { tag: 'FLAGGED', tc: 'var(--amber)', tb: 'var(--amber-dim)', msg: 'data_extraction · system_prompt probe', src: 'api.dev' },
  { tag: 'LEARNING', tc: 'var(--text2)', tb: 'var(--surface3)', msg: 'ML model updated · anomaly vectors weights computed', src: 'model.sys' },
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'role_manipulation · persona_override', src: 'embed.01' },
  { tag: 'ALLOWED', tc: 'var(--green)', tb: 'var(--green-dim)', msg: 'normal_query · risk_score:0.01', src: 'chat.app' }
];

export default function TerminalPanel() {
  const [lines, setLines] = useState<LogEntry[]>(() =>
    LOGS.slice(0, 4).map((log, i) => ({ ...log, id: `log-init-${i}` }))
  );
  const [idx, setIdx] = useState(4);
  const [flashRed, setFlashRed] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [bars, setBars] = useState([78, 14, 6, 2]); // distribution percentages

  useEffect(() => {
    const interval = setInterval(() => {
      // 1. Start processing animation for 300ms
      setIsProcessing(true);
      
      setTimeout(() => {
        setIsProcessing(false);
        const nextLog: LogEntry = {
          ...LOGS[idx % LOGS.length],
          id: `log-append-${idx}`
        };
        
        // 2. Add next log line
        setLines(prev => [...prev.slice(-3), nextLog]);
        setIdx(i => i + 1);

        // 3. Flash border if blocked
        if (nextLog.tag === 'BLOCKED') {
          setFlashRed(true);
          setTimeout(() => setFlashRed(false), 600);
        }

        // 4. Slightly randomize threat distribution bars on new entries to simulate activity
        setBars(prev => {
          const shift = Math.floor(Math.random() * 3) - 1; // -1, 0, 1
          const newPrompt = Math.max(70, Math.min(90, prev[0] + shift));
          const newJailbreak = Math.max(5, Math.min(20, prev[1] - shift));
          return [newPrompt, newJailbreak, prev[2], prev[3]];
        });

      }, 300);

    }, 1400); // 1.4s feed interval

    return () => clearInterval(interval);
  }, [idx]);

  const now = new Date();
  const formatTime = (offsetSeconds: number) => {
    const d = new Date(now.getTime() - offsetSeconds * 1000);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  };

  return (
    <div className="hero-enter-terminal">
      <div className={`preview ${flashRed ? 'flash-red' : ''}`} style={{ width: '100%' }}>
        <div className="preview-bar">
          <div className="preview-dot" style={{ background: 'var(--red)' }} />
          <div className="preview-dot" style={{ background: 'var(--amber)' }} />
          <div className="preview-dot" style={{ background: 'var(--green)' }} />
          <span className="preview-title">tenet‑ai — live‑security‑log</span>
          
          {isProcessing && (
            <span className="preview-processing">
              ANALYZING
            </span>
          )}

          <div className="preview-live">
            <div className="dot" style={{ background: 'var(--green)' }} />
            LIVE
          </div>
        </div>

        <div className="preview-body">
          {/* Dashboard Summary stats */}
          <div className="p-stats">
            <div className="p-stat">
              <div className="p-stat-v" style={{ color: 'var(--red)' }}>2,847</div>
              <div className="p-stat-l">Blocked</div>
            </div>
            <div className="p-stat">
              <div className="p-stat-v" style={{ color: 'var(--amber)' }}>341</div>
              <div className="p-stat-l">Flagged</div>
            </div>
            <div className="p-stat">
              <div className="p-stat-v" style={{ color: 'var(--green)' }}>98.7k</div>
              <div className="p-stat-l">Allowed</div>
            </div>
          </div>

          {/* Terminal log window */}
          <div className="p-log" aria-live="log">
            {lines.map((line, i) => (
              <div 
                key={line.id || i} 
                className="p-log-row" 
                style={{ opacity: 0.45 + i * 0.18 }}
              >
                <span className="p-log-time">{formatTime((lines.length - 1 - i) * 2)}</span>
                <span 
                  className="p-log-tag" 
                  style={{ 
                    color: line.tc, 
                    background: line.tb,
border: `1px solid color-mix(in srgb, ${line.tc} 12%, transparent)`,
                  }}
                >
                  {line.tag}
                </span>
                <span className="p-log-msg">{line.msg}</span>
                <span style={{ color: 'var(--text3)', fontSize: '9.5px', fontFamily: 'var(--mono)' }}>
                  {line.src}
                </span>
              </div>
            ))}
          </div>

          {/* Attack Type Distribution bars */}
          <div className="p-bars">
            <div className="p-bar-head">Attack Type Distribution</div>
            {[
              { label: 'Prompt Injection', val: bars[0], color: 'var(--red)' },
              { label: 'Jailbreak', val: bars[1], color: 'var(--amber)' },
              { label: 'Data Extraction', val: bars[2], color: 'var(--purple)' },
              { label: 'Role Manipulation', val: bars[3], color: 'var(--green)' }
            ].map((bar, i) => (
              <div key={i} className="p-bar-row">
                <span className="p-bar-lbl">{bar.label}</span>
                <div className="p-bar-track">
                  <div 
                    className="p-bar-fill" 
                    style={{ width: `${bar.val}%`, background: bar.color }} 
                  />
                </div>
                <span className="p-bar-val">{bar.val}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
