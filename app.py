import requests
import json
import base64
from datetime import datetime
import time
from threading import Thread
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Global variable to control message sending status
sending = False

# Function to convert plain text encryption key to base64 with padding
def convert_to_base64_with_padding(plain_key):
    key_bytes = plain_key.encode('utf-8')
    base64_key = base64.b64encode(key_bytes).decode('utf-8')
    padding = len(base64_key) % 4
    if padding != 0:
        base64_key += '=' * (4 - padding)
    return base64_key

# Function to encrypt the message using the E2EE encryption key
def encrypt_message(message, encryption_key):
    encryption_key = convert_to_base64_with_padding(encryption_key)
    key_bytes = base64.b64decode(encryption_key)
    encrypted_message = base64.b64encode(message.encode('utf-8'))
    return encrypted_message

# Function to send the encrypted message
def send_e2ee_message(token, thread_id, encrypted_message, encryption_key, hatersname, time_to_send):
    url = f"https://www.facebook.com/messages/e2ee/t/{thread_id}"  
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    data = {
        'message': encrypted_message.decode('utf-8'),
        'thread_id': thread_id,
        'encryption_key': encryption_key,
        'hatersname': hatersname,
        'time_to_send': time_to_send,
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print("Message sent successfully!")
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Function to send messages at intervals
def send_message_at_intervals(message, token, thread_id, encryption_key, hatersname, start_time):
    global sending
    current_time = datetime.now()
    time_difference = (start_time - current_time).total_seconds()

    if time_difference > 0:
        print(f"Waiting for {time_difference} seconds to start...")
        time.sleep(time_difference)  # Wait till the set time
    
    sending = True  # Start sending messages
    while sending:
        encrypted_message = encrypt_message(message, encryption_key)
        send_e2ee_message(token, thread_id, encrypted_message, encryption_key, hatersname, start_time)
        print(f"Message sent at {datetime.now()}")
        time.sleep(60)  # Send the message every 60 seconds

# Home route to show the form
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Send E2EE Message</title>
    </head>
    <body>
        <h1>Send E2EE Message</h1>
        <form action="/send" method="POST" enctype="multipart/form-data">
            <label for="token">Access Token:</label><br>
            <input type="text" id="token" name="token" required><br><br>

            <label for="thread_id">Thread ID:</label><br>
            <input type="text" id="thread_id" name="thread_id" required><br><br>

            <label for="encryption_key">Encryption Key (Plain Text):</label><br>
            <input type="text" id="encryption_key" name="encryption_key" required><br><br>

            <label for="hatersname">Haters Name:</label><br>
            <input type="text" id="hatersname" name="hatersname" required><br><br>

            <label for="time_to_send">Time to Send:</label><br>
            <input type="datetime-local" id="time_to_send" name="time_to_send" required><br><br>

            <label for="message">Message:</label><br>
            <textarea id="message" name="message" required></textarea><br><br>

            <label for="message_file">Message File (Optional):</label><br>
            <input type="file" id="message_file" name="message_file"><br><br>

            <button type="submit">Send Message</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/send', methods=['POST'])
def send_message():
    token = request.form['token']
    thread_id = request.form['thread_id']
    encryption_key = request.form['encryption_key']
    hatersname = request.form['hatersname']
    time_to_send = request.form['time_to_send']
    message = request.form['message']
    message_file = request.files['message_file']  # File upload for messages

    # Convert time_to_send to datetime
    start_time = datetime.strptime(time_to_send, '%Y-%m-%dT%H:%M')

    # Message ko encrypt karo
    encrypted_message = encrypt_message(message, encryption_key)

    # Agar file upload ki hai toh usse save karo
    if message_file:
        message_file.save(f"messages/{message_file.filename}")
        print(f"Message file {message_file.filename} saved.")

    # Start the message sending process at intervals
    thread = Thread(target=send_message_at_intervals, args=(message, token, thread_id, encryption_key, hatersname, start_time))
    thread.start()

    return "Message sending started! It will start at the specified time and continue every 60 seconds."

# Route to stop sending messages
@app.route('/stop', methods=['POST'])
def stop_message():
    global sending
    sending = False
    return "Message sending stopped!"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
