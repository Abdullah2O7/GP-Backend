from flask import Flask, request, jsonify, session
from pymongo import MongoClient
from datetime import datetime, timedelta
import jwt
import random
from werkzeug.security import generate_password_hash, check_password_hash
from validatoin import validate_registration_data, validate_login_data, validate_reset_password,validate_editProfile,validate_Change_password
from functools import wraps
from dotenv import load_dotenv
from config import Config
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



load_dotenv()
app = Flask(__name__)


app.config.from_object(Config)
app.config['SECRET_KEY']
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

client = MongoClient(app.config['MONGO_URI'])
db = client['users']
users_collection = db['users']

diseases_db = client['Diseases']
diseases_collection = diseases_db['diseases']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Expect the token in the Authorization header
        if not token:
            return jsonify({'Alert': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'username': data['user']})
            if not current_user:
                return jsonify({'Alert': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


# ---------------------------- Endpoints -----------------------------

@app.route("/api/home", methods=['GET'])
@token_required
def home(current_user):
    return jsonify({'message': f'Welcome, {current_user["username"]}!'}), 200

#  ------------------- Register ---------------------------

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

#  ------------------- Login ---------------------------

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

#  ---------------------- Verification ---------------------------------
@app.route("/api/verify", methods=['POST'])
def verify():
    data = request.get_json()
    contact = data.get('email')

    if not contact:
        return jsonify({'error': 'Email is required'}), 400

    # Check if the contact exists in the database
    user = users_collection.find_one({'email': contact})

    if user:
        verification_code = str(random.randint(1000, 9999))  # Generate a 4-digit code
        expiration_time = datetime.utcnow() + timedelta(minutes=5)  # Set expiration time to 5 minutes from now

        # Store the verification code and expiration time in the database
        users_collection.update_one(
            {'email': contact},
            {'$set': {
                'verification_code': verification_code,
                'code_expires_at': expiration_time
            }}
        )

        # Send verification code to user's email
        try:
            sender_email = app.config['SENDER_EMAIL']
            sender_password = app.config['SENDER_PASSWORD']
            subject = "Your Verification Code"
            body = f"Your verification code is {verification_code}"

            # Create the email
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = contact
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # Setup the server
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)

            # Send the email
            text = msg.as_string()
            server.sendmail(sender_email, contact, text)
            server.quit()
            
            return jsonify({'message': 'Verification code sent to your email'}), 200

        except Exception as e:
            return jsonify({'error': f'Failed to send email: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Email not found'}), 404
    
    
#  ---------------------- Verification ---------------------------------

@app.route("/api/verify", methods=['POST'])
def verify():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check if the email exists in the database
    user = users_collection.find_one({'email': email})

    if user:
        verification_code = str(random.randint(1000, 9999))  # Generate a 4-digit code
        expiration_time = datetime.utcnow() + timedelta(minutes=5)  # Set expiration time to 5 minutes from now

        # Store the verification code and expiration time in the database
        users_collection.update_one(
            {'email': email},
            {'$set': {
                'verification_code': verification_code,
                'verification_expiration': expiration_time
            }}
        )
        # Store email in the session
        session['email'] = email

        # Send verification code to user's email
        try:
            sender_email = app.config['SENDER_EMAIL']
            sender_password = app.config['SENDER_PASSWORD']
            subject = "Your Verification Code"
            body = f"Your verification code is {verification_code}"

            # Create the email
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # Setup the server
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)

            # Send the email
            text = msg.as_string()
            server.sendmail(sender_email, email, text)
            server.quit()

            return jsonify({'message': 'Verification code sent to your email'}), 200

        except Exception as e:
            return jsonify({'error': f'Failed to send email: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Email not found'}), 404
    
# ---------------- Internal -----------------------------

@app.route("/api/resetPasswordInternal", methods=['POST'])
def resetPassword_internal():
    email = session.get('email')
    if not email:
        return jsonify({'error': 'Session expired or email not found'}), 400

    data = request.get_json()
    verification_code = data.get('verification_code')

    if not verification_code:
        return jsonify({'error': 'Verification code is required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.get('verification_code') != verification_code:
        return jsonify({'error': 'Verification code is incorrect!'}), 400

    # Check if the verification code is expired
    if datetime.utcnow() > user.get('verification_expiration'):
        return jsonify({'error': 'Verification code has expired'}), 400

    # Allow the user to proceed to reset the password
    return jsonify({'message': 'Verification successful, proceed to reset password.'}), 200

# ---------------------- reset Password -------------------------

@app.route("/api/resetPassword", methods=['POST'])
def resetPassword():
    email = session.get('email')
    if not email:
        return jsonify({'error': 'Session expired or email not found'}), 400

    data = request.get_json()
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not new_password or not confirm_password:
        return jsonify({'error': 'Password and confirmation are required'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    error_message, valid = validate_reset_password(data)
    if not valid:
        return jsonify({'error': error_message}), 401

    # If all checks pass, reset the password
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {'email': email},
        {'$set': {'password': hashed_password}, '$unset': {'verification_code': "", 'verification_expiration': ""}}
    )

    return jsonify({'message': 'Password reset successfully!'}), 200

#  ------------------- Edit Profile ---------------------------

@app.route('/api/edit-profile', methods=['PATCH'])
@token_required
def edit_profile(current_user):
    data = request.get_json()

    validation_error, is_valid = validate_editProfile(data, users_collection)
    if not is_valid:
        return jsonify({'error': validation_error}), 400
    update_fields = {}

    # Update email if provided
    if 'email' in data:
        email_exists = users_collection.find_one({'email': data['email']})
        if email_exists and email_exists['username'] != current_user['username']:
            return jsonify({'error': 'Email is already in use by another account.'}), 400
        update_fields['email'] = data['email']

    # Update username if provided
    if 'username' in data:
        username_exists = users_collection.find_one({'username': data['username']})
        if username_exists and username_exists['username'] != current_user['username']:
            return jsonify({'error': 'Username is already taken.'}), 400
        update_fields['username'] = data['username']

    # Update gender if provided
    if 'gender' in data:
        update_fields['gender'] = data['gender']

    # Update bio if provided
    if 'bio' in data:
        update_fields['bio'] = data['bio']

    # Apply updates if there are any fields to update
    if update_fields:
        users_collection.update_one({'username': current_user['username']}, {'$set': update_fields})

    # Fetch updated user data
    updated_user = users_collection.find_one({'username': update_fields.get('username', current_user['username'])})

    return jsonify({
        'message': 'Profile updated successfully!',
        'user': {
            'username': updated_user.get('username'),
            'email': updated_user.get('email'),
            'gender': updated_user.get('gender'),
            'bio': updated_user.get('bio')
        }
    }), 200

# -------------------------- Change password -------------------------------------
@app.route('/api/changePassword', methods=['PUT'])
@token_required
def changePassword(current_user):
    data = request.get_json()
    if 'current_password' not in data :
        return jsonify({'error': 'Current password is required.'}), 400

    if not check_password_hash(current_user['password'], data['current_password']):
        return jsonify({'error': 'Current password is incorrect.'}), 400

    validation_error, is_valid = validate_Change_password(data)
    if not is_valid:
        return jsonify({'error': validation_error}), 400

    hashed_password = generate_password_hash(data['new_password'])

    users_collection.update_one({'username': current_user['username']},
                                {'$set': {'password': hashed_password}})  # Update the user's passw
    return jsonify({'message': 'Password updated successfully!'}), 200

# ------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
