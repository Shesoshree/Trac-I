"""Persistence Layer for Trac-I Scan Triage History.

Provides local SQLite database storage for historical email, URL, and text threat scans,
allowing SOC analysts to review past incident triage records and indicators of compromise (IOCs).
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = os.path.join("data", "scan_history.db")


class ScanDatabase:
    """Manages scan triage history and persistent telemetry records."""

    _db_path: str = DEFAULT_DB_PATH

    @classmethod
    def set_db_path(cls, path: str) -> None:
        cls._db_path = path
        cls._init_db()

    @classmethod
    def _init_db(cls) -> None:
        os.makedirs(os.path.dirname(cls._db_path), exist_ok=True)
        try:
            with sqlite3.connect(cls._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        target_name TEXT,
                        threat_score REAL NOT NULL,
                        severity TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        category TEXT NOT NULL,
                        soc_action TEXT,
                        ioc_domains TEXT,
                        ioc_ips TEXT,
                        ioc_urls TEXT,
                        summary TEXT,
                        features_json TEXT
                    )
                """)
                conn.commit()
        except Exception:
            pass

    @classmethod
    def save_scan(
        cls,
        scan_type: str,
        target_name: str,
        prediction: Dict[str, Any],
        extracted_features: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a completed scan into persistent SQLite storage."""
        cls._init_db()
        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.datetime.utcnow().isoformat() + "Z"

        # Extract IOCs if available
        ioc_domains: List[str] = []
        ioc_ips: List[str] = []
        ioc_urls: List[str] = []

        if extracted_features:
            headers = extracted_features.get("headers", {})
            urls_data = extracted_features.get("urls", {})

            from_d = headers.get("from_domain")
            if from_d: ioc_domains.append(from_d)
            ret_d = headers.get("return_path_domain")
            if ret_d: ioc_domains.append(ret_d)

            spf_ip = headers.get("spf", {}).get("client_ip")
            if spf_ip: ioc_ips.append(spf_ip)
            orig_ip = headers.get("relay", {}).get("originating_ip")
            if orig_ip: ioc_ips.append(orig_ip)

            for u in urls_data.get("urls", []):
                u_str = u.get("url")
                if u_str: ioc_urls.append(u_str)
                h = u.get("hostname")
                if h: ioc_domains.append(h)
                if u.get("is_ip_address") and h:
                    ioc_ips.append(h)

        ioc_domains = list(dict.fromkeys(ioc_domains))
        ioc_ips = list(dict.fromkeys(ioc_ips))
        ioc_urls = list(dict.fromkeys(ioc_urls))

        record = {
            "id": scan_id,
            "created_at": now_iso,
            "scan_type": scan_type,
            "target_name": target_name[:200] if target_name else "Unnamed Target",
            "threat_score": float(prediction.get("threat_score", 0.0)),
            "severity": str(prediction.get("severity", "LOW")),
            "confidence_score": float(prediction.get("confidence_score", prediction.get("confidence_percentage", 95.0))),
            "category": str(prediction.get("category", "General")),
            "soc_action": str(prediction.get("soc_action", "")),
            "ioc_domains": json.dumps(ioc_domains),
            "ioc_ips": json.dumps(ioc_ips),
            "ioc_urls": json.dumps(ioc_urls),
            "summary": f"{prediction.get('severity')} risk detected ({prediction.get('threat_score')}%) for {scan_type} scan.",
            "features_json": json.dumps(extracted_features) if extracted_features else "{}",
        }

        try:
            with sqlite3.connect(cls._db_path) as conn:
                conn.execute("""
                    INSERT INTO scan_history (
                        id, created_at, scan_type, target_name, threat_score,
                        severity, confidence_score, category, soc_action,
                        ioc_domains, ioc_ips, ioc_urls, summary, features_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record["id"], record["created_at"], record["scan_type"],
                    record["target_name"], record["threat_score"], record["severity"],
                    record["confidence_score"], record["category"], record["soc_action"],
                    record["ioc_domains"], record["ioc_ips"], record["ioc_urls"],
                    record["summary"], record["features_json"]
                ))
                conn.commit()
        except Exception:
            pass

        return {
            "id": record["id"],
            "created_at": record["created_at"],
            "scan_type": record["scan_type"],
            "target_name": record["target_name"],
            "threat_score": record["threat_score"],
            "severity": record["severity"],
            "confidence_score": record["confidence_score"],
            "category": record["category"],
            "soc_action": record["soc_action"],
            "ioc_domains": ioc_domains,
            "ioc_ips": ioc_ips,
            "ioc_urls": ioc_urls,
        }

    @classmethod
    def get_recent_scans(cls, limit: int = 25) -> List[Dict[str, Any]]:
        """Retrieve latest triage scans sorted descending by timestamp."""
        cls._init_db()
        results = []
        try:
            with sqlite3.connect(cls._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, created_at, scan_type, target_name, threat_score,
                           severity, confidence_score, category, soc_action,
                           ioc_domains, ioc_ips, ioc_urls, summary
                    FROM scan_history
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
                for row in cursor.fetchall():
                    results.append({
                        "id": row[0],
                        "created_at": row[1],
                        "scan_type": row[2],
                        "target_name": row[3],
                        "threat_score": row[4],
                        "severity": row[5],
                        "confidence_score": row[6],
                        "category": row[7],
                        "soc_action": row[8],
                        "ioc_domains": json.loads(row[9] or "[]"),
                        "ioc_ips": json.loads(row[10] or "[]"),
                        "ioc_urls": json.loads(row[11] or "[]"),
                        "summary": row[12],
                    })
        except Exception:
            pass
        return results

    @classmethod
    def get_scan_by_id(cls, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details and features for a specific scan ID."""
        cls._init_db()
        try:
            with sqlite3.connect(cls._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, created_at, scan_type, target_name, threat_score,
                           severity, confidence_score, category, soc_action,
                           ioc_domains, ioc_ips, ioc_urls, summary, features_json
                    FROM scan_history
                    WHERE id = ?
                """, (scan_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "created_at": row[1],
                        "scan_type": row[2],
                        "target_name": row[3],
                        "threat_score": row[4],
                        "severity": row[5],
                        "confidence_score": row[6],
                        "category": row[7],
                        "soc_action": row[8],
                        "ioc_domains": json.loads(row[9] or "[]"),
                        "ioc_ips": json.loads(row[10] or "[]"),
                        "ioc_urls": json.loads(row[11] or "[]"),
                        "summary": row[12],
                        "features": json.loads(row[13] or "{}"),
                    }
        except Exception:
            pass
        return None

    @classmethod
    def delete_scan(cls, scan_id: str) -> bool:
        """Delete a single scan record."""
        cls._init_db()
        try:
            with sqlite3.connect(cls._db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False

    @classmethod
    def clear_all(cls) -> None:
        """Clear all historical scans."""
        cls._init_db()
        try:
            with sqlite3.connect(cls._db_path) as conn:
                conn.execute("DELETE FROM scan_history")
                conn.commit()
        except Exception:
            pass
