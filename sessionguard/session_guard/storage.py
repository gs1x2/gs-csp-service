import sqlite3
import os
from datetime import datetime

class SessionStorage:
    """
    Управляет хранением данных о сессиях,
    например, user_id, IP, user-agent, время последней активности, подозрительность и т.д.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        # Создаём таблицы, если не существуют
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                suspicious_score INTEGER,
                created_at TEXT,
                updated_at TEXT
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                log_type TEXT,
                message TEXT,
                ip_address TEXT
            );
        """)
        # Таблица для логирования админ-действий:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                details TEXT
            );
        """)
        conn.commit()
        conn.close()

    def create_session(self, session_id, user_id, ip, user_agent):
        conn = self.get_connection()
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO sessions (session_id, user_id, ip_address, user_agent, suspicious_score, created_at, updated_at)
            VALUES (?, ?, ?, ?, 0, ?, ?)
        """, (session_id, user_id, ip, user_agent, now, now))
        conn.commit()
        conn.close()

    def get_session(self, session_id):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id=? LIMIT 1", (session_id,))
        row = cur.fetchone()
        conn.close()
        return row

    def update_session_score(self, session_id, new_score):
        conn = self.get_connection()
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            UPDATE sessions
            SET suspicious_score = ?, updated_at = ?
            WHERE session_id = ?
        """, (new_score, now, session_id))
        conn.commit()
        conn.close()

    def delete_session(self, session_id):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        conn.close()

    def get_all_sessions(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions")
        rows = cur.fetchall()
        conn.close()
        return rows

    def log(self, log_type, message, ip_address=None):
        """
        Общий метод для записи логов
        log_type: INFO, BLOCK, ADMIN и т.д.
        """
        conn = self.get_connection()
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO logs (timestamp, log_type, message, ip_address)
            VALUES (?, ?, ?, ?)
        """, (now, log_type, message, ip_address))
        conn.commit()
        conn.close()

    def get_logs(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM logs ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        return rows

    def admin_log(self, action, details=""):
        """
        Логи действий админа
        """
        conn = self.get_connection()
        cur = conn.cursor()
        now = datetime.now().isoformat()
        cur.execute("""
            INSERT INTO admin_logs (timestamp, action, details)
            VALUES (?, ?, ?)
        """, (now, action, details))
        conn.commit()
        conn.close()

    def get_admin_logs(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM admin_logs ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        return rows
