from flask import Flask, request
from session_guard.guard import SessionGuard
from session_guard.admin import admin_bp

app = Flask(__name__)
guard = SessionGuard()

# Подключаем Blueprint админки
app.register_blueprint(admin_bp)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    """
    Универсальный роут.
    Любой запрос (GET/POST/...) попадёт сюда, 
    и мы отдадим его на обработку SessionGuard
    """
    return guard.process_request(path)

if __name__ == "__main__":
    # Запускаем прокси на 8080, например
    app.run(port=8080, debug=True)
