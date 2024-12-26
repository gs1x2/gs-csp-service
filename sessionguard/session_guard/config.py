import os

class GuardConfig:
    """
    Отвечает за загрузку конфигураций, 
    в том числе ключей, путей к БД, адреса защищаемого сервиса и т.д.
    """
    def __init__(self):
        # Можно грузить из переменных окружения или ini-файлов
        self.SECRET_KEY = os.environ.get("GUARD_SECRET_KEY", "SUPER_SECRET_KEY_123")
        self.DB_PATH = os.environ.get("GUARD_DB_PATH", os.path.join(os.path.dirname(__file__), "guard.db"))
        # Адрес уязвимого сервиса, на который будем проксировать запросы
        self.UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:5000")
        # Допустим, порог "подозрительности" (пока не реализуем сложную систему, просто пример)
        self.SUSPICIOUS_THRESHOLD = 70
        # Настройки для логирования
        self.LOG_EVERYTHING = True  # Логировать все запросы
        # и т.д. – можно добавлять любые конфиги
