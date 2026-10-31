import sqlite3
import uuid
from typing import List, Dict, Any, Optional
from tensorguard.rules import Vulnerability


def init_db(db_path: str = "tensorguard_audit.db"):
    """Initialize SQLite database tables for scan auditing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            scan_id TEXT PRIMARY KEY,
            target_path TEXT,
            status TEXT,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_path TEXT,
            rule_id TEXT,
            severity TEXT,
            message TEXT,
            evidence TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_runs (scan_id)
        )
        """
    )

    conn.commit()
    conn.close()


def log_scan_results(
    target_path: str,
    status: str,
    findings: List[Vulnerability],
    db_path: str = "tensorguard_audit.db",
) -> str:
    """Record scan results, findings breakdown, and metadata into SQLite."""
    init_db(db_path)

    scan_id = str(uuid.uuid4())
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scan_runs (
            scan_id, target_path, status,
            critical_count, high_count, medium_count, low_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            target_path,
            status,
            counts["CRITICAL"],
            counts["HIGH"],
            counts["MEDIUM"],
            counts["LOW"],
        ),
    )

    for f in findings:
        cursor.execute(
            """
            INSERT INTO vulnerabilities (
                scan_id, file_path, rule_id, severity, message, evidence
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                f.file_path,
                f.rule_id,
                f.severity,
                f.message,
                getattr(f, "evidence", ""),
            ),
        )

    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit: int = 20, db_path: str = "tensorguard_audit.db") -> List[Dict[str, Any]]:
    """Retrieve the most recent scan audit entries from SQLite."""
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT 
            scan_id, 
            timestamp, 
            target_path, 
            status, 
            (critical_count + high_count + medium_count + low_count) AS total_findings
        FROM scan_runs
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()

    history = []
    for row in rows:
        history.append({
            "scan_id": row[0],
            "timestamp": row[1],
            "target_path": row[2],
            "status": row[3],
            "findings_count": row[4],
        })
    return history


def get_scan_details(scan_id: Optional[str] = None, db_path: str = "tensorguard_audit.db") -> Optional[Dict[str, Any]]:
    """Retrieve full scan metadata and all associated vulnerability entries."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if not scan_id:
        cursor.execute("SELECT scan_id FROM scan_runs ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None
        scan_id = row[0]

    cursor.execute(
        """
        SELECT scan_id, target_path, status, critical_count, high_count, medium_count, low_count, timestamp
        FROM scan_runs
        WHERE scan_id = ?
        """,
        (scan_id,),
    )
    meta = cursor.fetchone()
    if not meta:
        conn.close()
        return None

    cursor.execute(
        """
        SELECT file_path, rule_id, severity, message, evidence
        FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    )
    vuln_rows = cursor.fetchall()
    conn.close()

    findings = [
        {
            "file_path": r[0],
            "rule_id": r[1],
            "severity": r[2],
            "message": r[3],
            "evidence": r[4],
        }
        for r in vuln_rows
    ]

    return {
        "scan_id": meta[0],
        "target_path": meta[1],
        "status": meta[2],
        "critical_count": meta[3],
        "high_count": meta[4],
        "medium_count": meta[5],
        "low_count": meta[6],
        "timestamp": meta[7],
        "findings": findings,
    }