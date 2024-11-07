from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, messaging

# Initialize the Flask app
app = Flask(__name__)

# Load Firebase credentials
cred = credentials.Certificate('graduationproject-4f4ab-firebase-adminsdk-spja4-dbb848a1df.json')
firebase_admin.initialize_app(cred)

def send_push_notification(registration_ids, message_title, message_body):
    message = messaging.MulticastMessage(
        tokens=registration_ids,
        notification=messaging.Notification(
            title=message_title,
            body=message_body
        )
    )
    response = messaging.send_multicast(message)
    
    # Loop through responses and print detailed information
    for idx, resp in enumerate(response.responses):
        if resp.success:
            print(f"Notification sent successfully to {registration_ids[idx]}")
        else:
            print(f"Failed to send notification to {registration_ids[idx]}: {resp.exception}")
    
    return response

# Route to send push notifications
@app.route("/api/send_notification", methods=['POST'])
def send_notification():
    data = request.get_json()
    registration_ids = data.get('registration_ids')  # FCM tokens of mobile devices
    message_title = data.get('title')
    message_body = data.get('body')

    if not registration_ids or not message_title or not message_body:
        return jsonify({'error': 'Missing required fields'}), 400

    # Send the push notification
    result = send_push_notification(registration_ids, message_title, message_body)

    return jsonify({'result': result.success_count, 'failure': result.failure_count}), 200

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
