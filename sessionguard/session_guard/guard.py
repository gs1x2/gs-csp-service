import uuid
import hmac
import hashlib
import time
from flask import request, make_response, redirect
import requests  # будем пересылать запрос к уязвимому сервису
from .storage import SessionStorage
from .config import GuardConfig


class SessionGuard:
    """
    Основная логика проверки входящих запросов,
    решения о пропуске/блокировке, 
    генерации/проверки подписанного токена,
    и т.д.
    """

    def __init__(self):
        self.config = GuardConfig()
        self.storage = SessionStorage(self.config.DB_PATH)

    def _sign_data(self, data):
        """
        С помощью секретного ключа создаём подпись (HMAC).
        data: bytes
        """
        return hmac.new(
            key=self.config.SECRET_KEY.encode('utf-8'),
            msg=data,
            digestmod=hashlib.sha256
        ).hexdigest()

    def create_or_get_session(self):
        """
        Если у пользователя нет session_id в куках прокси — создать.
        Если есть — вернуть существующий.
        """
        session_id = request.cookies.get('PROXY_SESSION_ID')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'unknown')

        if not session_id:
            # создаём новый
            session_id = str(uuid.uuid4())
            self.storage.create_session(session_id, user_id="", ip=ip, user_agent=user_agent)
            self.storage.log("INFO", f"New session created: {session_id}", ip_address=ip)
        else:
            # session_id уже есть, проверить/обновить
            session = self.storage.get_session(session_id)
            if session is None:
                # если в БД нет, то тоже создаём заново
                session_id = str(uuid.uuid4())
                self.storage.create_session(session_id, user_id="", ip=ip, user_agent=user_agent)
                self.storage.log("INFO", f"Session not found, new created: {session_id}", ip_address=ip)
            else:
                # можно обновить время, user-agent, ip и т.д., если хотим
                pass
        return session_id

    def calculate_suspicious_score(self, session_id):
        """
        Пример простого подсчёта "подозрительности".
        В реальности может быть сложнее (геолокация, резкая смена IP и т.д.)
        """
        session = self.storage.get_session(session_id)
        if not session:
            return 0

        score = session['suspicious_score']

        # Пример: если IP поменялся, можно увеличить score, 
        # но для упрощения оставим так или добавим любую логику
        return score

    def process_request(self, path):
        """
        Главный метод:
        1. Создаёт/получает session_id
        2. Проверяет уровень suspicious_score
        3. Если всё ок, проксирует запрос к уязвимому сервису
        4. Возвращает ответ пользователю
        """
        session_id = self.create_or_get_session()
        suspicious_score = self.calculate_suspicious_score(session_id)

        # Если score выше порога — блочим
        if suspicious_score >= self.config.SUSPICIOUS_THRESHOLD:
            self.storage.log("BLOCK", f"Blocked session {session_id}, score={suspicious_score}", request.remote_addr)
            # Можно убить сессию
            self.storage.delete_session(session_id)
            return make_response("Access denied (suspicious activity).", 403)

        # Иначе проксируем
        upstream_url = f"{self.config.UPSTREAM_URL}/{path}"
        method = request.method

        # Соберём заголовки, но можем исключить Host и пр.
        headers = {}
        for k, v in request.headers:
            # Исключим некоторые ненужные или конфликтующие заголовки
            if k.lower() not in ["host", "content-length"]:
                headers[k] = v

        # Пробросим тело запроса
        data = request.get_data() if method in ("POST", "PUT", "PATCH") else None

        # Выполним запрос к уязвимому сервису
        try:
            resp = requests.request(method, upstream_url, headers=headers, data=data, allow_redirects=False)
        except Exception as e:
            self.storage.log("ERROR", f"Error proxying to upstream: {e}", request.remote_addr)
            return make_response("Upstream service unreachable.", 502)

        # Логируем запрос
        if self.config.LOG_EVERYTHING:
            self.storage.log("INFO", f"Proxied {method} {upstream_url} => {resp.status_code}", request.remote_addr)

        # Пересылаем ответ обратно
        response = make_response(resp.content, resp.status_code)
        # Копируем заголовки
        for k, v in resp.headers.items():
            if k.lower() not in ["content-length", "transfer-encoding", "content-encoding", "connection"]:
                response.headers[k] = v

        # Устанавливаем PROXY_SESSION_ID (если нужен)
        response.set_cookie("PROXY_SESSION_ID", session_id, httponly=True, samesite='Strict')
        return response
