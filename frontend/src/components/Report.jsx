import { useState } from "react";
import { sendFeedback } from "../api";

const SEV = { high: "Serious", medium: "Warning", low: "Minor", info: "Note" };

function Viewfinder({ score, level, verdict }) {
  return (
    <div className={`finder ${level}`} role="img" aria-label={`${verdict}, risk score ${score} out of 100`}>
      <span className="c tl" /><span className="c tr" /><span className="c bl" /><span className="c br" />
      <div className="score">{score}</div>
      <div className="of">risk score out of 100</div>
    </div>
  );
}

function Chain({ hops }) {
  if (!hops?.length) return null;
  return (
    <ol className="chain">
      {hops.map((h, i) => (
        <li key={i}>
          <code>{h.url}</code>
          <span>{h.status ? `HTTP ${h.status}` : h.note}</span>
        </li>
      ))}
    </ol>
  );
}

export default function Report({ report }) {
  const [vote, setVote] = useState(report.helpful ?? null);
  const d = report.details || {};
  const showReasons = report.reasons.filter((r) => r.points > 0 || r.severity === "info");

  const rate = async (helpful) => {
    setVote(helpful ? 1 : 0);
    try { await sendFeedback(report.id, helpful); } catch { /* non-critical */ }
  };

  return (
    <section className="report" aria-live="polite">
      <div className="head">
        <Viewfinder score={report.score} level={report.level} verdict={report.verdict} />
        <div>
          <h2 className={`verdict ${report.level}`}>{report.verdict}</h2>
          <p>{report.summary}</p>
          <p className="target"><span>Decoded content</span><code>{report.input.value}</code></p>
          {report.codes_found > 1 && <p className="note">{report.codes_found} codes were in the image. Showing the first.</p>}
        </div>
      </div>

      {report.confidence === "limited" && (
        <p className="banner">Online checks are turned off, so this result uses the link text only.</p>
      )}

      <h3>Why we say this</h3>
      <ul className="reasons">
        {showReasons.map((r, i) => (
          <li key={i} className={r.severity}>
            <b className="badge">{SEV[r.severity]}</b>
            <div><strong>{r.title}</strong><p>{r.detail}</p></div>
          </li>
        ))}
        {!showReasons.length && <li className="info"><b className="badge">Note</b><div><strong>No warning signs found</strong></div></li>}
      </ul>

      {(d.redirect_chain?.length > 1 || d.upi || d.domain_age_days != null || d.ssl) && (
        <details className="more">
          <summary>Technical details</summary>
          {d.host && <p><span>Domain</span> {d.registered_domain}</p>}
          {d.domain_age_days != null && <p><span>Domain age</span> {d.domain_age_days} days</p>}
          {d.ssl?.valid && <p><span>Certificate</span> issued by {d.ssl.issuer}, expires in {d.ssl.expires_in_days} days</p>}
          {d.upi && <p><span>Payee</span> {d.upi.payee_name || "unnamed"} ({d.upi.payee_vpa || "none"})</p>}
          {d.threat_intel && Object.entries(d.threat_intel).map(([k, v]) => (
            <p key={k}><span>{k.replaceAll("_", " ")}</span> {v}</p>
          ))}
          {d.redirect_chain?.length > 1 && <><p><span>Redirect trace</span></p><Chain hops={d.redirect_chain} /></>}
        </details>
      )}

      <h3>What to do</h3>
      <ul className="advice">{report.advice.map((a, i) => <li key={i}>{a}</li>)}</ul>

      <div className="feedback">
        <span>Was this report helpful?</span>
        <button className={vote === 1 ? "pill on" : "pill"} onClick={() => rate(true)}>Yes</button>
        <button className={vote === 0 ? "pill on" : "pill"} onClick={() => rate(false)}>No</button>
        {vote !== null && <em>Thanks, saved.</em>}
      </div>
      <p className="fine">No tool is perfect. This report shows risk indicators, not proof that a site is safe or fraudulent.</p>
    </section>
  );
}
