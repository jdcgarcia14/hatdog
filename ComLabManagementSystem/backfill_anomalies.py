import sqlite3

DB_FILE = "database.db"

with sqlite3.connect(DB_FILE) as conn:
    cur = conn.cursor()
    cur.execute("""
          SELECT a.anomaly_type,a.details, a.detected_at, a.pc_tag, a.id
            FROM anomalies a JOIN devices d ON a.device_id = d.id
            WHERE a.student_id = 'K1234567' AND a.cleared = 0
            AND (a.details NOT LIKE '%HIDClass%' OR a.details IS NULL)
            AND (a.details NOT LIKE '%USB Input Device ((Standard system devices))%' OR a.details IS NULL)
            ORDER BY a.detected_at DESC
            """)

    rows = cur.fetchall()
    for r in rows:
        print(r)
