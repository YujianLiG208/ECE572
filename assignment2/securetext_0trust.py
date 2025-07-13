#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger (Insecure Genesis Version)
A basic console-based messenger application with intentional security vulnerabilities.

Features:
- Account creation with plaintext password storage
- User login
- Send/receive messages via TCP sockets
- Basic password reset functionality
"""

import socket
import threading
import json
import os
import sys
import time
from datetime import datetime
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import secrets
import base64
import hashlib
import struct
#from pymd5 import md5, padding as pymd5_padding
import hmac
import pyotp
import qrcode
import webbrowser
import urllib.parse
import requests
from urllib.parse import parse_qs
import random
import string
import logging

# Add these constants at the top of the file after other imports
GITHUB_CLIENT_ID = "Ov23li942zRrpwAFzaTE"
GITHUB_CLIENT_SECRET = "4b5c089cfcf7bc7c8d337be69b71301c6dacb62c"
GITHUB_REDIRECT_URI = "http://localhost:8000/callback"
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com/user"
GITHUB_USER_EMAIL_URL = "https://api.github.com/user/emails"

SHARED_SECRET_KEY = "SuperSecretSharedKey123"  # Use a better key in production!
LOG_FILE = "action_log.json"

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        self.oauth_states = {}  # Initialize oauth_states dictionary
        self.failed_logins = {}  # username -> count
        
    def load_users(self):
        """Load users from JSON file or create empty dict if file doesn't exist"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
        return {}
    
    def save_users(self):
        """Save users to JSON file (passwords are already hashed and salted)"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def create_account(self, username, password, admin=False):
        """Create new user account with TOTP 2FA and ASCII QR code"""
        if username in self.users:
            return False, "Username already exists"

        # Generate a unique random 128-bit salt for this user
        salt_bytes = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        hashed_totp = hashlib.sha256(totp_secret.encode()).hexdigest()

        # Proper TOTP URI format
        totp_uri = f"otpauth://totp/SecureText:{username}?secret={totp_secret}&issuer=SecureText"

        # Generate QR code with error correction
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=1,
            border=2
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr_ascii = qr.print_ascii(invert=True)  # Display in ASCII art

        ph = PasswordHasher()
        password_with_salt = password + salt_b64
        hashed_password = ph.hash(password_with_salt)

        self.users[username] = {
            'password': hashed_password,
            'salt': salt_b64,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue',
            'totp_secret': hashed_totp,
            'totp_secret_raw': totp_secret,   # Store raw secret for TOTP verification
            'totp_enabled': True,
            'totp_attempts': 0,            # For rate limiting
            'totp_block_until': 0,          # Timestamp until which TOTP is blocked
            'admin': admin  # <-- Boolean admin flag
        }
        self.save_users()
        print("\nScan this QR code with your authenticator app:")
        qr.print_ascii(invert=True)
        print(f"\nOr manually enter this secret: {totp_secret}")
        return True, "Account created successfully. TOTP setup required."
    
    def verify_totp(self, username, totp_code):
        """Verify TOTP code for a user with rate limiting and time window tolerance"""
        RATE_LIMIT_MAX_ATTEMPTS = 5
        RATE_LIMIT_BLOCK_SECONDS = 60
        TIME_WINDOW_TOLERANCE = 1  # Accept codes ±1 time step (default step is 30s)

        if username not in self.users or not self.users[username].get('totp_enabled'):
            return False

        user = self.users[username]
        now = time.time()

        # Check if user is currently blocked
        if user.get('totp_block_until', 0) > now:
            return False  # Blocked due to too many failed attempts

        # Get stored hashed TOTP secret
        hashed_secret = user['totp_secret']

        # For demonstration, we need the original secret, but only the hash is stored.
        # In a real system we store the secret securely, not just the hash.
        # Here, we can't verify TOTP with only the hash, so this is a limitation.
        # For this assignment, let's assume we can retrieve the original secret.

        # --- Begin workaround for demonstration ---
        # totp_secret is the hash, but pyotp needs the original secret.
        # So, we should store the original secret as well (not just the hash).
        # Let's add 'totp_secret_raw' for this purpose.
        if 'totp_secret_raw' in user:
            totp_secret = user['totp_secret_raw']
        else:
            # If not present, fail
            return False
        # --- End workaround for demonstration ---

        totp = pyotp.TOTP(totp_secret)
        valid = totp.verify(totp_code, valid_window=TIME_WINDOW_TOLERANCE)

        if valid:
            user['totp_attempts'] = 0
            user['totp_block_until'] = 0
            self.save_users()
            return True
        else:
            user['totp_attempts'] = user.get('totp_attempts', 0) + 1
            if user['totp_attempts'] >= RATE_LIMIT_MAX_ATTEMPTS:
                user['totp_block_until'] = now + RATE_LIMIT_BLOCK_SECONDS
                user['totp_attempts'] = 0
            self.save_users()
            return False

    def authenticate(self, username, password=None, totp_code=None, oauth_callback_url=None):
        """Authenticate user with password and/or OAuth"""
        if oauth_callback_url:
            # Handle GitHub OAuth authentication
            success, message, user_info = self.verify_oauth_callback(oauth_callback_url)
            if success:
                # If username provided, try to link accounts
                if username:
                    if username in self.users:
                        # Link GitHub account to existing user
                        self.link_github_account(username, user_info)
                        return True, "GitHub account linked successfully"
                    else:
                        return False, "Local account not found"
                
                # Try to find existing linked account
                linked_username = self.find_linked_account(user_info)
                if linked_username:
                    return True, f"Logged in via GitHub as {linked_username}"
                
                # Create new linked account
                new_username, temp_password = self.create_linked_account(user_info)
                return True, f"Created new account: {new_username}"
            
            return False, message
        
        # Traditional password authentication
        if not username or not password:
            self.log_action("login_attempt", username, "Missing username or password", "failure")
            return False, "Username and password required"
        
        if username not in self.users:
            self.log_action("login_attempt", username, "Username not found", "failure")
            return False, "Username not found"
        
        user = self.users[username]
        ph = PasswordHasher()
        
        try:
            # Verify password
            salt_b64 = user.get('salt')
            if not salt_b64:
                return False, "Salt missing for user"
            
            password_with_salt = password + salt_b64
            if not ph.verify(user['password'], password_with_salt):
                self.failed_logins[username] = self.failed_logins.get(username, 0) + 1
                self.log_action("login_attempt", username, "Invalid password", "failure")
                if self.failed_logins[username] >= 3:
                    print(f"WARNING: 3 failed login attempts for user {username}")
                return False, "Invalid password"
            
            # Check if 2FA is required
            if user.get('totp_enabled'):
                if not totp_code:
                    self.log_action("login_attempt", username, "Missing 2FA code", "failure")
                    return False, "2FA code required"
                if not self.verify_totp(username, totp_code):
                    self.failed_logins[username] = self.failed_logins.get(username, 0) + 1
                    self.log_action("login_attempt", username, "Invalid 2FA code", "failure")
                    if self.failed_logins[username] >= 3:
                        print(f"WARNING: 3 failed login attempts for user {username}")
                    return False, "Invalid 2FA code"
            
            self.failed_logins[username] = 0  # Reset on success
            self.log_action("login_attempt", username, "Login", "success")
            return True, "Authentication successful"
            
        except Exception as e:
            self.log_action("login_attempt", username, f"Exception: {str(e)}", "failure")
            return False, f"Authentication error: {str(e)}"
    
    def reset_password(self, requester, username, new_password):
        """Only admin can reset others' passwords. Users can reset their own."""
        if username not in self.users:
            return False, "Username not found"
        if requester != username:
            # Only admin can reset others' passwords
            if not self.users.get(requester, {}).get("admin", False):
                return False, "Only admin can reset other users' passwords"
        self.users[username]['password'] = new_password
        self.save_users()
        return True, "Password reset successful"
    # --- Begin MAC and Key Management additions ---

    def get_shared_key(self):
        """
        Returns the pre-shared key for all users.
        Insecure: In a real system, use per-user keys and secure key exchange.
        """
        # Hardcoded pre-shared key (for demo only)
        return "SuperSecretSharedKey123"

    def mac(self, key, message):
        """
        Compute a flawed MAC using MD5(key || message).
        Args:
            key (str): The shared secret key.
            message (str): The message to authenticate.
        Returns:
            str: Hex digest of the MAC.
        """
        data = (key + message).encode('utf-8')
        return hashlib.md5(data).hexdigest()

    def verify_mac(self, key, message, mac_value):
        """
        Verify the MAC for a given message.
        Returns True if valid, False otherwise.
        """
        expected_mac = self.mac(key, message)
        return expected_mac == mac_value

    # --- End MAC and Key Management additions ---
    # --- Begin Secure MAC (HMAC-SHA256) implementation ---
    # HMAC-SHA256 is secure because it uses a secret key and the SHA-256 hash function in a specific construction
    # that prevents common attacks (like length extension). Only someone with the key can compute or verify the MAC,
    # ensuring both message integrity and authentication. HMAC's design has been extensively analyzed and is widely
    # trusted in cryptographic applications.

    def mac(self, key, message):
        """
        Compute a secure MAC using HMAC-SHA256.
        Args:
            key (str): The shared secret key.
            message (str): The message to authenticate.
        Returns:
            str: Hex digest of the MAC.
        """
        key_bytes = key.encode('utf-8')
        msg_bytes = message.encode('utf-8')
        return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    def verify_mac(self, key, message, mac_value):
        """
        Verify the MAC for a given message using HMAC-SHA256.
        Returns True if valid, False otherwise.
        """
        expected_mac = self.mac(key, message)
        # Use hmac.compare_digest for timing-attack resistance
        return hmac.compare_digest(expected_mac, mac_value)

    # --- End Secure MAC (HMAC-SHA256) implementation ---
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        print(f"New connection from {addr}")
        current_user = None
        
        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    command = message.get('command')
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        success, msg = self.create_account(username, password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LOGIN':
                        # Step 1: Send challenge to client
                        challenge = self.generate_challenge()
                        response = {'status': 'challenge', 'challenge': challenge}
                        conn.send(json.dumps(response).encode('utf-8'))

                        # Step 2: Wait for client's MAC response
                        data = conn.recv(1024).decode('utf-8')
                        try:
                            message = json.loads(data)
                            client_mac = message.get('mac')
                            username = message.get('username')
                            password = message.get('password')
                            totp_code = message.get('totp_code')

                            # Verify challenge-response
                            if not self.verify_challenge_response(challenge, client_mac):
                                response = {'status': 'error', 'message': 'Challenge-response failed'}
                            else:
                                success, msg = self.authenticate(username, password, totp_code)
                                if success:
                                    current_user = username
                                    self.active_connections[username] = conn
                                response = {'status': 'success' if success else 'error', 'message': msg}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Login error: {str(e)}'}
                        
                    elif command == 'SEND_MESSAGE':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            recipient = message.get('recipient')
                            msg_content = message.get('content')
                            
                            # Send message to recipient if they're online
                            if recipient in self.active_connections:
                                msg_data = {
                                    'type': 'MESSAGE',
                                    'from': current_user,
                                    'content': msg_content,
                                    'timestamp': datetime.now().isoformat()
                                }
                                try:
                                    self.active_connections[recipient].send(
                                        json.dumps(msg_data).encode('utf-8')
                                    )
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except:
                                    # Remove inactive connection
                                    del self.active_connections[recipient]
                                    response = {'status': 'error', 'message': 'Recipient is offline'}
                            else:
                                response = {'status': 'error', 'message': 'Recipient is offline'}
                    
                    elif command == 'RESET_PASSWORD':
                        username = message.get('username')
                        new_password = message.get('new_password')
                        # requester is current_user
                        is_admin = self.users.get(current_user, {}).get("admin", False)
                        if current_user != username and not is_admin:
                            self.log_action("role_access", current_user, f"Attempted to reset password for {username}", "denied")
                        success, msg = self.reset_password(current_user, username, new_password)
                        self.log_action("command", current_user, f"RESET_PASSWORD for {username}", "success" if success else "failure")
                        response = {'status': 'success' if success else 'error', 'message': msg}
                    
                    elif command == 'LIST_USERS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            online_users = list(self.active_connections.keys())
                            all_users = list(self.users.keys())
                            response = {
                                'status': 'success', 
                                'online_users': online_users,
                                'all_users': all_users
                            }
                    
                    elif command == 'START_OAUTH':
                        try:
                            username = message.get('username')
                            auth_url = self.start_oauth_flow(username)
                            if auth_url:
                                response = {
                                    'status': 'success',
                                    'auth_url': auth_url
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Failed to initialize OAuth flow'
                                }
                        except Exception as e:
                            response = {
                                'status': 'error',
                                'message': f'OAuth initialization error: {str(e)}'
                            }

                    elif command == 'OAUTH_CALLBACK':
                        try:
                            callback_url = message.get('callback_url')
                            username = message.get('username')
                            success, msg, user_info = self.verify_oauth_callback(callback_url)
                            
                            if success:
                                if username and username in self.users:
                                    # Link to existing account
                                    self.link_github_account(username, user_info)
                                    current_user = username
                                else:
                                    # Find or create account
                                    current_user = self.find_linked_account(user_info)
                                    if not current_user:
                                        current_user, _ = self.create_linked_account(user_info)
                                
                                self.active_connections[current_user] = conn
                                response = {
                                    'status': 'success',
                                    'message': f'Logged in as {current_user}',
                                    'username': current_user
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': msg
                                }
                        except Exception as e:
                            response = {
                                'status': 'error',
                                'message': f'OAuth callback error: {str(e)}'
                            }
                    
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
        except ConnectionResetError:
            pass
        finally:
            # Clean up connection
            if current_user and current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"Connection from {addr} closed")
    
    def start_oauth_flow(self, username=None):
        """Initialize OAuth flow for GitHub login/account linking"""
        state = secrets.token_urlsafe(16)
        self.oauth_states[state] = {
            'username': username,
            'timestamp': time.time()
        }
        params = {
            'client_id': GITHUB_CLIENT_ID,
            'redirect_uri': GITHUB_REDIRECT_URI,
            'scope': 'read:user user:email',
            'state': state
        }
        auth_url = f"{GITHUB_AUTH_URL}?{urllib.parse.urlencode(params)}"
        return auth_url

    def get_github_user_info(self, access_token):
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        user_response = requests.get(GITHUB_API_URL, headers=headers)
        user_data = user_response.json()
        email_response = requests.get(GITHUB_USER_EMAIL_URL, headers=headers)
        email_data = email_response.json()
        if user_response.status_code == 200 and email_response.status_code == 200:
            primary_email = next(
                (email['email'] for email in email_data if email['primary']),
                None
            )
            return {
                'github_id': str(user_data['id']),
                'github_username': user_data['login'],
                'email': primary_email,
                'name': user_data.get('name'),
                'avatar_url': user_data.get('avatar_url')
            }
        return None

    def find_linked_account(self, github_info):
        for username, user in self.users.items():
            if user.get('github_id') == github_info['github_id']:
                return username
            if user.get('email') == github_info.get('email'):
                return username
        return None

    def create_linked_account(self, github_info):
        base_username = github_info['github_username']
        username = base_username
        counter = 1
        while username in self.users:
            username = f"{base_username}{counter}"
            counter += 1
        temp_password = secrets.token_urlsafe(16)
        salt_bytes = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
        ph = PasswordHasher()
        password_with_salt = temp_password + salt_b64
        hashed_password = ph.hash(password_with_salt)
        self.users[username] = {
            'password': hashed_password,
            'salt': salt_b64,
            'created_at': datetime.now().isoformat(),
            'email': github_info.get('email'),
            'github_id': github_info['github_id'],
            'github_username': github_info['github_username'],
            'name': github_info.get('name'),
            'totp_enabled': False
        }
        self.save_users()
        return username, temp_password

    def link_github_account(self, username, github_info):
        if username not in self.users:
            return False
        self.users[username].update({
            'github_id': github_info['github_id'],
            'github_username': github_info['github_username'],
            'email': github_info.get('email'),
            'name': github_info.get('name')
        })
        self.save_users()
        return True

    def verify_oauth_callback(self, callback_url):
        parsed = urllib.parse.urlparse(callback_url)
        params = parse_qs(parsed.query)
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        if not code or not state:
            return False, "Invalid OAuth callback: missing parameters", None
        if state not in self.oauth_states:
            return False, "Invalid OAuth state", None
        self.oauth_states.pop(state)
        data = {
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code,
            'redirect_uri': GITHUB_REDIRECT_URI
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(GITHUB_TOKEN_URL, data=data, headers=headers)
        if response.status_code != 200:
            return False, "Failed to obtain access token", None
        token_data = response.json()
        access_token = token_data.get('access_token')
        if not access_token:
            return False, "No access token in response", None
        user_info = self.get_github_user_info(access_token)
        if not user_info:
            return False, "Failed to get GitHub user info", None
        return True, "OAuth verification successful", user_info

    def generate_challenge(self, length=32):
        """Generate a random challenge string."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def verify_challenge_response(self, challenge, response_mac):
        """Verify HMAC-SHA256 of challenge using shared key."""
        expected_mac = hmac.new(
            SHARED_SECRET_KEY.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_mac, response_mac)

    def log_action(self, event_type, username, details, outcome):
        """Log an action to the JSON log file."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            "username": username,
            "details": details,
            "outcome": outcome
        }
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as f:
                    logs = json.load(f)
            else:
                logs = []
            logs.append(entry)
            with open(LOG_FILE, "w") as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"Logging error: {e}")
    
    def start_server(self):
        """Start the TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()

class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            print("Error: Could not connect to server. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def send_command(self, command_data):
        """Send command to server and get response"""
        try:
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            response = self.socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
    
    def listen_for_messages(self):
        """Listen for incoming messages in a separate thread"""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if data:
                    message = json.loads(data)
                    if message.get('type') == 'MESSAGE':
                        print(f"\n[{message['timestamp']}] {message['from']}: {message['content']}")
                        print(">> ", end="", flush=True)
            except:
                break
    
    def create_account(self):
        """Create a new account"""
        print("\n=== Create Account ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Username and password cannot be empty!")
            return
        
        command = {
            'command': 'CREATE_ACCOUNT',
            'username': username,
            'password': password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def login(self):
        """Login to the system with password or OAuth"""
        print("\n=== Login ===")
        print("1. Login with username/password")
        print("2. Login with GitHub")
        choice = input("Choose login method: ").strip()
        
        if choice == "1":
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            totp_code = input("Enter 2FA code (from authenticator app): ").strip()

            command = {
                'command': 'LOGIN',
                'username': username,
                'password': password,
                'totp_code': totp_code
            }
            # Step 1: Request challenge from server
            self.socket.send(json.dumps(command).encode('utf-8'))
            response = self.socket.recv(1024).decode('utf-8')
            response = json.loads(response)
            if response.get('status') == 'challenge':
                challenge = response['challenge']
                # Step 2: Compute MAC and send back
                mac = hmac.new(
                    SHARED_SECRET_KEY.encode(),
                    challenge.encode(),
                    hashlib.sha256
                ).hexdigest()
                command = {
                    'mac': mac,
                    'username': username,
                    'password': password,
                    'totp_code': totp_code
                }
                self.socket.send(json.dumps(command).encode('utf-8'))
                response = self.socket.recv(1024).decode('utf-8')
                response = json.loads(response)
            print(f"\n{response['message']}")
            if response['status'] == 'success':
                self.logged_in = True
                self.username = response.get('username')
                self.running = True
                listen_thread = threading.Thread(target=self.listen_for_messages)
                listen_thread.daemon = True
                listen_thread.start()
            return
        elif choice == "2":
            # GitHub OAuth flow
            print("\nDo you want to link to an existing account? (y/n): ")
            link_account = input().strip().lower() == 'y'
            
            username = None
            if link_account:
                username = input("Enter existing username to link: ").strip()
            
            command = {
                'command': 'START_OAUTH',
                'username': username  # Will be None if not linking
            }
            response = self.send_command(command)
            
            if response['status'] == 'success':
                auth_url = response['auth_url']
                print("\nOpening GitHub login in your browser...")
                webbrowser.open(auth_url)
                
                print("\nAfter logging in, you will be redirected to a URL.")
                print("Please copy and paste the complete redirect URL here:")
                callback_url = input().strip()
                
                command = {
                    'command': 'OAUTH_CALLBACK',
                    'callback_url': callback_url,
                    'username': username  # Pass through the username if linking
                }
            else:
                print(f"Error starting OAuth: {response['message']}")
                return
        else:
            print("Invalid choice!")
            return
        
        response = self.send_command(command)
        print(f"\n{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = response.get('username')
            self.running = True
            
            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_message(self):
        """Send a message to another user"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
        
        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()
        content = input("Enter message: ").strip()
        
        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return
        
        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'content': content
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def list_users(self):
        """List all users and show who's online"""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        command = {'command': 'LIST_USERS'}
        response = self.send_command(command)
        
        if response['status'] == 'success':
            print(f"\nOnline users: {', '.join(response['online_users'])}")
            print(f"All users: {', '.join(response['all_users'])}")
        else:
            print(f"Error: {response['message']}")
    
    def reset_password(self):
        """Reset password (basic implementation)"""
        print("\n=== Reset Password ===")
        username = input("Enter username: ").strip()
        new_password = input("Enter new password: ").strip()
        
        command = {
            'command': 'RESET_PASSWORD',
            'username': username,
            'new_password': new_password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        print("=== SecureText Messenger (Insecure Version) ===")
        print("WARNING: This is an intentionally insecure implementation for educational purposes!")
        
        while True:
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Reset Password")
                print("4. Exit")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.reset_password()
                elif choice == '4':
                    break
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Logout")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out successfully")
                elif choice == '':
                    # Just wait for messages
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run as server
        server = SecureTextServer()
        server.start_server()
    else:
        # Run as client
        client = SecureTextClient()
        client.run()

if __name__ == "__main__":
    main()
