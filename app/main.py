from flask import Flask, jsonify, request
import datetime
import jwt
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = "GIZLI ANAHTAR CIA BIZI IZLIYOR"


def auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            token = kwargs['token']
        except:
            token = request.args.get('token') or request.form.get('token')
        if not token:
            return jsonify({"message": "Token required"}), 403
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms="HS256")
        except:
            return jsonify({"message": "Token expired!"}), 403
        return f(*args, **kwargs)
    return wrapper


@app.route('/api/v1/user/<token>/<id>', methods=['GET'])
@auth
def users(token, id):
    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
    return jsonify({"decoded": decoded})


@app.route('/api/v1/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    return jsonify({"message": "You registered successfully!"})


@app.route('/api/v1/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    token = ''
    if username == 'admin' and password == 'admin':
        token = jwt.encode({
            'user': username,
            'password': password,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
    else:
        token = 'Invalid username or password'

    return jsonify({'token': token})


@app.route('/api/v1/user/update', methods=['POST'])
@auth
def update_user():
    token = request.form.get('token')
    user_id = request.form.get('id')
    return jsonify({"token": token})


if __name__ == '__main__':
    app.run(debug=True)
