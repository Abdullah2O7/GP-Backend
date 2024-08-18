from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime, timedelta
import jwt
import random
from werkzeug.security import generate_password_hash, check_password_hash
from validatoin import validate_registration_data, validate_login_data, validate_reset_password
from functools import wraps

app = Flask(__name__)
app.config.from_object('config.Config')
app.config['SECRET_KEY'] = '3da675e0576d436eb0a695855d1a7430'

client = MongoClient(app.config['MONGO_URI'])
db = client['users']
users_collection = db['users']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Expect the token in the Authorization header
        if not token:
            return jsonify({'Alert': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'username': data['user']})
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/api/register", methods=['POST'])
def register_api():
    data = request.get_json()
    error_message, valid = validate_registration_data(data, users_collection)
    if not valid:
        return jsonify({'error': error_message}), 400

    hashed_password = generate_password_hash(data['password'])
    user_data = {
        'username': data['username'],
        'email': data['email'],
        'password': hashed_password
    }
    users_collection.insert_one(user_data)
    # Generate token
    token = jwt.encode({
        'user': data["username"],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    # Return user data with token
    return jsonify({
        'message': f'Account created for {data["username"]}!',
        'user': {
            'username': data['username'],
            'email': data['email']
        },
        'token': token
    }), 201

@app.route("/api/login", methods=['POST'])
def login_api():
    data = request.get_json()
    error_message, valid = validate_login_data(data, users_collection)
    if not valid:
        return jsonify({'error': error_message}), 401

    # Find the user by email
    user = users_collection.find_one({'email': data['email']})

    if user and check_password_hash(user['password'], data['password']):
        # Generate token using the username
        token = jwt.encode({
            'user': user["username"],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Return user data with token
        return jsonify({
            'message': 'Login successful!',
            'user': {
                'username': user['username'],
                'email': user['email']
            },
            'token': token
        }), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401


@app.route("/api/verify", methods=['POST'])
@token_required
def verify(current_user):
    data = request.get_json()
    contact = data.get('email') or data.get('phone')
    
    if not contact:
        return jsonify({'error': 'Email or phone number is required'}), 400
    # Check if the contact exists in the database
    user = users_collection.find_one({'$or': [{'email': contact}, {'phone': contact}]})

    if user:
        verification_code = str(random.randint(100000, 999999))  # Generate a 6-digit code
        return jsonify({'Verification code': verification_code }), 200
    else:
        return jsonify({'error': 'Contact not found'}), 404
    


@app.route("/api/resetPassword", methods=['POST'])
def resetPassword():
    data = request.get_json()
    error_message, valid = validate_reset_password(data)
    if not valid:
        return jsonify({'error': error_message}), 401
    # Check if the user exists in the database
    user = users_collection.find_one({'email': data['email']})
    if not user:
        return jsonify({'error': 'User with this email does not exist'}), 404

    hashed_password = generate_password_hash(data['password'])

    users_collection.update_one({'email': data['email']}, {'$set': {'password': hashed_password}})# Update the user's password in the database
    return jsonify({
        'message': 'Password reset successfully!',
        'email': data['email'],
    }), 200
    


@app.route("/api/home", methods=['GET'])
@token_required
def home(current_user):
    return jsonify({'message': f'Welcome, {current_user["username"]}!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
