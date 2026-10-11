"""Tiny SQLite layer: scan history, feedback, and an API-response cache."""
import json
import sqlite3
import time
from collections import Counter
from contextlib import contextmanager

from .config import settings


@contextmanager
def conn():
    c = sqlite3.connect(settings.db_path)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                report TEXT NOT NULL,
                helpful INTEGER
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS cache (
                k TEXT PRIMARY KEY, v TEXT NOT NULL, ts REAL NOT NULL
            )"""
        )


def save_scan(source: str, report: dict) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO scans (created_at, source, kind, target, score, level, report) VALUES (?,?,?,?,?,?,?)",
            (time.time(), source, report["input"]["kind"], report["input"]["value"][:500],
             report["score"], report["level"], json.dumps(report)),
        )
        return cur.lastrowid


def get_scan(scan_id: int):
    with conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    report = json.loads(row["report"])
    report["id"] = row["id"]
    report["helpful"] = row["helpful"]
    return report


def list_scans(limit: int = 20):
    with conn() as c:
        rows = c.execute(
            "SELECT id, created_at, kind, target, score, level FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def set_feedback(scan_id: int, helpful: bool) -> bool:
    with conn() as c:
        cur = c.execute("UPDATE scans SET helpful=? WHERE id=?", (1 if helpful else 0, scan_id))
        return cur.rowcount > 0


def stats():
    with conn() as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        levels = {r["level"]: r["n"] for r in c.execute("SELECT level, COUNT(*) n FROM scans GROUP BY level")}
        fb = c.execute(
            "SELECT SUM(helpful=1) up, SUM(helpful=0) down FROM scans WHERE helpful IS NOT NULL"
        ).fetchone()
        recent = c.execute("SELECT report FROM scans ORDER BY id DESC LIMIT 500").fetchall()
    reasons = Counter()
    for r in recent:
        for item in json.loads(r["report"]).get("reasons", []):
            if item["points"] > 0:
                reasons[item["title"]] += 1
    up, down = (fb["up"] or 0), (fb["down"] or 0)
    return {
        "total": total,
        "levels": {"low": levels.get("low", 0), "suspicious": levels.get("suspicious", 0),
                   "dangerous": levels.get("dangerous", 0)},
        "feedback": {"helpful": up, "not_helpful": down},
        "top_reasons": [{"title": t, "count": n} for t, n in reasons.most_common(5)],
    }


def cache_get(key: str):
    with conn() as c:
        row = c.execute("SELECT v, ts FROM cache WHERE k=?", (key,)).fetchone()
    if row and time.time() - row["ts"] < settings.cache_ttl_seconds:
        return json.loads(row["v"])
    return None


def cache_set(key: str, value) -> None:
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?,?,?)", (key, json.dumps(value), time.time()))
