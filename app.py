import os
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template

app = Flask(__name__)
app.secret_key = "SuperSecretSessionKey"  
app.permanent_session_lifetime = 100000  # Нет времени жизни сессии
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'database.db')

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(os.path.dirname(__file__), 'schema.sql'), 'r') as f:
            db.executescript(f.read())
        db.commit()

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?,?)', (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Пользователь уже существует"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE username=? AND password=?', (username, password)).fetchone()
        if user:
            session['user_id'] = user['id']
            session.permanent = True
            return redirect(url_for('notes'))
        else:
            return "Неверное имя пользователя или пароль"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        content = request.form.get('content')
        db.execute('INSERT INTO notes (user_id, content) VALUES (?,?)', (session['user_id'], content))
        db.commit()
    user_notes = db.execute('SELECT id, content FROM notes WHERE user_id=?', (session['user_id'],)).fetchall()
    return render_template('notes.html', notes=user_notes)

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(debug=True)