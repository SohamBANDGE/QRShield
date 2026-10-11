import { useCallback, useEffect, useState } from "react";
import { analyzeImage, analyzeUrl, getHistory, getScan, getStats } from "./api";
import CheckPanel from "./components/CheckPanel.jsx";
import Report from "./components/Report.jsx";
import Sidebar from "./components/Sidebar.jsx";

export default function App() {
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([getHistory(), getStats()]);
      setHistory(h);
      setStats(s);
    } catch { /* sidebar is non-critical */ }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const run = async (fn) => {
    setBusy(true); setError("");
    try { setReport(await fn()); refresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <header className="top">
        <h1>QRShield</h1>
        <p>See where a QR code really leads before you open it.</p>
      </header>
      <main className="layout">
        <div className="main-col">
          <CheckPanel busy={busy} onUrl={(u) => run(() => analyzeUrl(u))} onImage={(f) => run(() => analyzeImage(f))} />
          {busy && <p className="status">Checking the code. Following redirects and looking up the domain can take a few seconds.</p>}
          {error && <p className="error" role="alert">{error}</p>}
          {report && !busy && <Report key={report.id} report={report} />}
        </div>
        <Sidebar history={history} stats={stats} onOpen={(id) => run(() => getScan(id))} />
      </main>
      <footer>QRShield is an educational project. Never rely on a single tool for payments or passwords.</footer>
    </>
  );
}
