import re
from werkzeug.security import check_password_hash

def validate_registration_data(data, users_collection):

    def validate_username():
        if 'username' not in data:
            return 'Username is required'
        elif len(data['username']) < 2:
            return 'Username must be at least 2 characters long'
        elif len(data['username']) > 20:
            return 'Username must be no more than 20 characters long'
        else:
            return None

    def validate_email():
        if 'email' not in data:
            return 'Email is required'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', data['email']):
            return 'Invalid email format'
        else:
            return None

    def validate_password():
        if 'password' not in data:
            return 'Password is required'
        elif len(data['password']) < 6:
            return 'Password must be at least 6 characters long'
        elif len(data['password']) > 20:
            return 'Password must be no more than 20 characters long'
        else:
            return None

    def validate_confirm_password():
        if 'confirm_password' not in data:
            return 'Confirm password is required'
        elif data['password'] != data['confirm_password']:
            return 'Passwords do not match'
        else:
            return None

    validation_rules = {
        'username': validate_username,
        'email': validate_email,
        'password': validate_password,
        'confirm_password': validate_confirm_password
    }

    for field, validation_rule in validation_rules.items():
        error_message = validation_rule()
        if error_message:
            return error_message, False


    existing_email = users_collection.find_one({'email': data['email']})
    if existing_email:
        return 'Email already exists', False

    return None, True


def validate_login_data(data, users_collection):
    if 'email' not in data:
        return 'Email is required', False
    if 'password' not in data:
        return 'Password is required', False

    user = users_collection.find_one({'email': data['email']})
    if user and check_password_hash(user['password'], data['password']):
        return None, True
    return 'Invalid email or password', False
