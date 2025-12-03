# app.py
import os
import html
from datetime import timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import bcrypt
from flask_restx import Api, Resource, fields

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-dev-secret-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Swagger authorizations 
authorizations = {
    'bearerAuth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
    }
}

api = Api(
    app,
    version='1.0',
    title='Secure REST API',
    description='API с базовыми мерами защиты: SQLi, XSS, Broken Authentication (JWT).',
    doc='/swagger/',
    authorizations=authorizations,
    security=None  # по умолчанию не применяем глобально; указываем per-endpoint
)

auth_ns = api.namespace('auth', description='Authentication')
api_ns = api.namespace('api', description='Protected resources')

# Модели для Swagger
user_model = auth_ns.model('User', {
    'username': fields.String(required=True, description='User name'),
    'password': fields.String(required=True, description='Password (plain text for signup/login)')
})

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

token_model = auth_ns.model('TokenResponse', {
    'access_token': fields.String(description='JWT access token')
})

echo_model = api_ns.model('Echo', {
    'message': fields.String(required=True, description='Message to echo (will be escaped)')
})

data_model = api_ns.model('DataResponse', {
    'status': fields.String,
    'data': fields.List(fields.Nested(api_ns.model('Item', {
        'id': fields.Integer,
        'item': fields.String
    }))),
    'user': fields.String
})

# Модель БД
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


# Инициализация БД и тестовый пользователь (локально)
with app.app_context():
    db.create_all()

    # Создадим тестового пользователя только если его нет
    if not User.query.filter_by(username='admin').first():
        pw_hash = bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt())
        admin = User(username='admin', password_hash=pw_hash.decode('utf-8'))
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Создан тестовый пользователь: admin / password123")


def sanitize_for_output(s: str) -> str:
    """
    Санитизация пользовательского ввода перед включением в ответы API.
    Возвращаем экранированную строку, чтобы предотвратить XSS в клиентах,
    которые рендерят полученные строки как HTML.
    """
    if s is None:
        return s
    return html.escape(str(s))


@auth_ns.route('/signup')
class Signup(Resource):
    @auth_ns.expect(user_model, validate=True)
    def post(self):
        """
        Регистрация нового пользователя.
        Пароль хэшируется bcrypt и сохраняется в БД (никогда не сохраняем plain text).
        Защита от SQLi обеспечивается использованием ORM (SQLAlchemy).
        """
        payload = request.get_json() or {}
        username = payload.get('username')
        password = payload.get('password')

        if not username or not password:
            return {'msg': 'Missing username or password'}, 400

        # Проверка уникальности (ORM — безопасно против SQLi)
        if User.query.filter_by(username=username).first():
            return {'msg': 'User already exists'}, 409

        # Хэширование пароля
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password_hash=pw_hash.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()

        # В ответ возвращаем только санитизированное имя пользователя
        return {'msg': 'User created', 'username': sanitize_for_output(username)}, 201


@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.marshal_with(token_model, code=200)
    def post(self):
        """
        Аутентификация: при успешном логине возвращаем JWT.
        """
        payload = request.get_json() or {}
        username = payload.get('username')
        password = payload.get('password')

        if not username or not password:
            auth_ns.abort(400, 'Missing username or password')

        # ORM-поиск (защита от SQLi)
        user = User.query.filter_by(username=username).first()
        if not user:
            auth_ns.abort(401, 'Bad username or password')

        # Сравнение хэша пароля
        if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            auth_ns.abort(401, 'Bad username or password')

        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200


@api_ns.route('/data')
class ProtectedData(Resource):
    @api_ns.doc(security='bearerAuth')  # покажет замочек в Swagger и потребует авторизацию
    @jwt_required()
    @api_ns.marshal_with(data_model)
    def get(self):
        """
        Пример защищённого эндпоинта. JWT проверяется декоратором @jwt_required().
        Возвращаем только безопасные (экранированные) строки.
        """
        current_user = get_jwt_identity()
        safe_user = sanitize_for_output(current_user)

        data = [
            {'id': 1, 'item': sanitize_for_output("Secret Report <1>")},
            {'id': 2, 'item': sanitize_for_output("Secret Report <2>")}
        ]
        return {
            'status': 'success',
            'data': data,
            'user': safe_user
        }, 200


@api_ns.route('/echo')
class Echo(Resource):
    @api_ns.expect(echo_model, validate=True)
    @api_ns.doc(security='bearerAuth')
    @jwt_required()
    def post(self):
        """
        Возвращаем пользователю его сообщение, предварительно экранировав его — защита от XSS.
        """
        payload = request.get_json() or {}
        message = payload.get('message', '')
        safe = sanitize_for_output(message)
        return {
            'original_received': safe,
            'note': 'Input sanitized to prevent XSS'
        }, 200

@api.route('/health')
class Health(Resource):
    def get(self):
        return {'status': 'ok'}, 200

IS_PROD = os.environ.get('FLASK_ENV', 'development') == 'production'

if __name__ == '__main__':
    # debug=True только для локальной разработки
    app.run(debug=False, port=int(os.environ.get('PORT', 5001)))
