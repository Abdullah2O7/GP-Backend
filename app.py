from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from validatoin import validate_registration_data, validate_login_data

app = Flask(__name__)
app.config.from_object('config.Config')

client = MongoClient(app.config['MONGO_URI'])
db = client['users']
users_collection = db['users']



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
    return jsonify({'message': f'Account created for {data["username"]}!'}), 201



@app.route("/api/login", methods=['POST'])
def login_api():
    data = request.get_json()
    error_message, valid = validate_login_data(data, users_collection)
    if not valid:
        return jsonify({'error': error_message}), 401

    return jsonify({'message': 'Login successful'}), 200



@app.route("/api/home", methods=['GET'])
def home():
    return jsonify({'message': 'Home Page'}), 200

if __name__ == '__main__':
    app.run(debug=True)
