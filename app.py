import os
import html
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt

app = Flask(__name__)

# КОНФИГУРАЦИЯ
# В реальном проекте секретные ключи берутся из os.environ, не храните их в коде!
app.config['SECRET_KEY'] = 'super-secret-key-change-me' 
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # SQLite для простоты
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# МОДЕЛЬ БАЗЫ ДАННЫХ
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# ИНИЦИАЛИЗАЦИЯ БД (Создаем таблицы и тестового пользователя при запуске)
with app.app_context():
    db.create_all()
    # Создадим тестового юзера, если его нет
    if not User.query.filter_by(username='admin').first():
        # Хэширование пароля (Защита паролей)
        pw_hash = bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username='admin', password_hash=pw_hash.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()

# --- ЭНДПОИНТЫ ---

# 1. POST /auth/login (Аутентификация)
@app.route('/auth/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    # Защита от SQLi: Использование ORM (User.query.filter_by) автоматически экранирует параметры
    user = User.query.filter_by(username=username).first()

    # Проверка хэша пароля
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        # Генерация JWT
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

# 2. GET /api/data (Защищенный эндпоинт)
@app.route('/api/data', methods=['GET'])
@jwt_required() # Middleware проверки токена
def get_data():
    current_user = get_jwt_identity()
    return jsonify({
        "status": "success",
        "data": [
            {"id": 1, "item": "Secret Report 1"},
            {"id": 2, "item": "Secret Report 2"}
        ],
        "user": current_user
    }), 200

# 3. POST /api/echo (Кастомный метод + демонстрация защиты от XSS)
@app.route('/api/echo', methods=['POST'])
@jwt_required()
def echo_message():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON"}), 400
    
    user_input = request.json.get('message', '')
    
    # Защита от XSS: Санитизация входных данных перед возвратом
    # Даже если пользователь пришлет "<script>alert(1)</script>", мы вернем безопасный текст
    safe_input = html.escape(user_input)
    
    return jsonify({
        "original_received": safe_input, 
        "note": "Input was sanitized to prevent XSS"
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)