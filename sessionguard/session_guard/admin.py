from flask import Blueprint, render_template, request, redirect, url_for
from .storage import SessionStorage
from .config import GuardConfig

admin_bp = Blueprint('admin_bp', __name__, template_folder='../templates', url_prefix='/manage')

@admin_bp.route('/')
def admin_index():
    """
    Главная страница админки
    """
    return render_template('admin_index.html')

@admin_bp.route('/sessions')
def admin_sessions():
    """
    Просмотр всех текущих сессий
    """
    storage = SessionStorage(GuardConfig().DB_PATH)
    sessions = storage.get_all_sessions()
    return render_template('admin_sessions.html', sessions=sessions)

@admin_bp.route('/logs')
def admin_logs():
    """
    Просмотр логов
    """
    storage = SessionStorage(GuardConfig().DB_PATH)
    logs = storage.get_logs()
    return render_template('admin_logs.html', logs=logs)

@admin_bp.route('/delete_session/<session_id>', methods=['POST'])
def delete_session(session_id):
    """
    Удалить (заблокировать) конкретную сессию
    """
    storage = SessionStorage(GuardConfig().DB_PATH)
    storage.delete_session(session_id)
    storage.admin_log("DELETE_SESSION", f"Session {session_id} deleted by admin")
    return redirect(url_for('admin_bp.admin_sessions'))
