import { useRef, useState } from "react";

export default function CheckPanel({ busy, onUrl, onImage }) {
  const [mode, setMode] = useState("image");
  const [url, setUrl] = useState("");
  const [preview, setPreview] = useState(null);
  const [drag, setDrag] = useState(false);
  const fileRef = useRef(null);

  const pick = (file) => {
    if (!file) return;
    setPreview(URL.createObjectURL(file));
    onImage(file);
  };

  return (
    <section className="panel" aria-labelledby="check-title">
      <h2 id="check-title">Check a code</h2>
      <div className="tabs" role="tablist">
        {[["image", "Upload or scan"], ["url", "Paste a link"]].map(([key, label]) => (
          <button key={key} role="tab" aria-selected={mode === key}
            className={mode === key ? "tab on" : "tab"} onClick={() => setMode(key)}>
            {label}
          </button>
        ))}
      </div>

      {mode === "image" ? (
        <>
          <div
            className={`drop ${drag ? "drag" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
          >
            {preview ? <img src={preview} alt="Selected QR code" /> : (
              <div className="frame" aria-hidden="true"><i /><i /><i /><i /></div>
            )}
            <p>{preview ? "Check another image" : "Drop a QR image here"}</p>
            <div className="row">
              <button className="btn" disabled={busy} onClick={() => fileRef.current.click()}>Choose image</button>
              <button className="btn ghost" disabled={busy}
                onClick={() => { fileRef.current.setAttribute("capture", "environment"); fileRef.current.click(); fileRef.current.removeAttribute("capture"); }}>
                Use camera
              </button>
            </div>
            <input ref={fileRef} type="file" accept="image/*" hidden
              onChange={(e) => { pick(e.target.files[0]); e.target.value = ""; }} />
          </div>
          <p className="hint">Photos are read on our server and not kept. Only the decoded link and the report are saved.</p>
        </>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); url.trim() && onUrl(url.trim()); }}>
          <label htmlFor="url">Link, UPI address or text from the code</label>
          <textarea id="url" rows={3} value={url} placeholder="https://example.com/offer"
            onChange={(e) => setUrl(e.target.value)} />
          <button className="btn" disabled={busy || !url.trim()}>Check this link</button>
          <p className="hint">The link is analysed, not opened by you. Safe to paste suspicious links here.</p>
        </form>
      )}
    </section>
  );
}
