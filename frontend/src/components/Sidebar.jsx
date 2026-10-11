const LEVEL = { low: "Low risk", suspicious: "Suspicious", dangerous: "Dangerous" };

export default function Sidebar({ history, stats, onOpen }) {
  const t = stats?.total || 0;
  const pct = (n) => (t ? Math.round((n / t) * 100) : 0);
  const votes = stats ? stats.feedback.helpful + stats.feedback.not_helpful : 0;
  return (
    <aside className="side">
      <section className="panel">
        <h2>Community scans</h2>
        {stats ? (
          <>
            <p className="big">{t} <small>codes checked</small></p>
            <div className="bar" aria-hidden="true">
              <i className="low" style={{ width: `${pct(stats.levels.low)}%` }} />
              <i className="suspicious" style={{ width: `${pct(stats.levels.suspicious)}%` }} />
              <i className="dangerous" style={{ width: `${pct(stats.levels.dangerous)}%` }} />
            </div>
            <p className="legend">{stats.levels.low} low risk, {stats.levels.suspicious} suspicious, {stats.levels.dangerous} dangerous</p>
            {votes > 0 && <p className="legend">{Math.round((stats.feedback.helpful / votes) * 100)}% rated the report helpful ({votes} votes)</p>}
            {stats.top_reasons.length > 0 && (
              <>
                <h3>Most common warning signs</h3>
                <ul className="toplist">{stats.top_reasons.map((r) => <li key={r.title}>{r.title}<b>{r.count}</b></li>)}</ul>
              </>
            )}
          </>
        ) : <p className="hint">Stats appear after the first scan.</p>}
      </section>

      <section className="panel">
        <h2>Recent checks</h2>
        {history.length === 0 && <p className="hint">Nothing checked yet. Your first scan will show up here.</p>}
        <ul className="hist">
          {history.map((h) => (
            <li key={h.id}>
              <button onClick={() => onOpen(h.id)}>
                <i className={`dot ${h.level}`} aria-label={LEVEL[h.level]} />
                <span>{h.target}</span>
                <b>{h.score}</b>
              </button>
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );
}
