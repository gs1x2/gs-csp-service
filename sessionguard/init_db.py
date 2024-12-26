"""
Скрипт, который можно запустить один раз, чтобы инициализировать базу.
Хотя в storage.py уже есть init_db(), но бывает удобно отдельным скриптом.
"""

from session_guard.storage import SessionStorage
from session_guard.config import GuardConfig

if __name__ == "__main__":
    config = GuardConfig()
    storage = SessionStorage(config.DB_PATH)
    print("Database initialized at", config.DB_PATH)
