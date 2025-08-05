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
from threading import Timer #new for session management
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import psutil
# cryptography import to apply key derivation and serialization, and message encryption/decryption
GITHUB_CLIENT_ID = "Ov23li942zRrpwAFzaTE"
GITHUB_CLIENT_SECRET = "4b5c089cfcf7bc7c8d337be69b71301c6dacb62c"
GITHUB_REDIRECT_URI = "http://localhost:8000/callback"
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com/user"
GITHUB_USER_EMAIL_URL = "https://api.github.com/user/emails"

SHARED_SECRET_KEY = "SuperSecretSharedKey123"  # Use a better key in production!
LOG_FILE = "action_log.json"

SESSION_TIMEOUT_MINUTES = 5  # Session expires after X minutes, change as needed for testing
WARNING_BEFORE_TIMEOUT_MINUTES = 2  # Warning appears 2 minutes before timeout

class PerformanceMonitor:
    def __init__(self):
        self.crypto_metrics = {
            'ecdh_keygen_times': [],
            'ecdh_exchange_times': [],
            'hkdf_derivation_times': [],
            'aes_encryption_times': [],
            'aes_decryption_times': [],
            'pubkey_serialization_times': [],
            'pubkey_deserialization_times': []
        }
        self.memory_metrics = {
            'server_memory_usage': [],
            'crypto_object_count': 0,
            'session_keys_memory': 0,
            'pubkeys_memory': 0
        }
        self.start_time = time.time()
        self.process = psutil.Process()
        
    def start_timer(self):
        """Start timing an operation"""
        return time.perf_counter()
    
    def end_timer(self, start_time, operation_type):
        """End timing and record the duration"""
        duration = time.perf_counter() - start_time
        if operation_type in self.crypto_metrics:
            self.crypto_metrics[operation_type].append(duration * 1000)  # Convert to milliseconds
            # Keep only last 100 measurements
            if len(self.crypto_metrics[operation_type]) > 100:
                self.crypto_metrics[operation_type] = self.crypto_metrics[operation_type][-100:]
        return duration * 1000  # Return in milliseconds
    
    def record_memory_usage(self):
        """Record current memory usage"""
        memory_info = self.process.memory_info()
        self.memory_metrics['server_memory_usage'].append({
            'timestamp': time.time(),
            'rss_mb': memory_info.rss / 1024 / 1024,  # MB
            'vms_mb': memory_info.vms / 1024 / 1024   # MB
        })
        # Keep only last 50 measurements
        if len(self.memory_metrics['server_memory_usage']) > 50:
            self.memory_metrics['server_memory_usage'] = self.memory_metrics['server_memory_usage'][-50:]
    
    def update_crypto_object_counts(self, pubkeys_count, session_keys_count):
        """Update counts of cryptographic objects"""
        self.memory_metrics['crypto_object_count'] = pubkeys_count + session_keys_count
        # Estimate memory usage (rough estimates)
        self.memory_metrics['pubkeys_memory'] = pubkeys_count * 0.5  # ~0.5KB per PEM key
        self.memory_metrics['session_keys_memory'] = session_keys_count * 0.032  # 32 bytes per AES key
    
    def get_crypto_stats(self):
        """Get cryptographic performance statistics"""
        stats = {}
        for operation, times in self.crypto_metrics.items():
            if times:
                stats[operation] = {
                    'count': len(times),
                    'avg_ms': sum(times) / len(times),
                    'min_ms': min(times),
                    'max_ms': max(times),
                    'latest_ms': times[-1] if times else 0
                }
            else:
                stats[operation] = {'count': 0, 'avg_ms': 0, 'min_ms': 0, 'max_ms': 0, 'latest_ms': 0}
        return stats
    
    def get_memory_stats(self):
        """Get memory usage statistics"""
        if self.memory_metrics['server_memory_usage']:
            latest = self.memory_metrics['server_memory_usage'][-1]
            return {
                'current_memory_mb': latest['rss_mb'],
                'current_virtual_mb': latest['vms_mb'],
                'crypto_objects_count': self.memory_metrics['crypto_object_count'],
                'estimated_pubkeys_memory_kb': self.memory_metrics['pubkeys_memory'],
                'estimated_session_keys_memory_kb': self.memory_metrics['session_keys_memory'],
                'uptime_minutes': (time.time() - self.start_time) / 60
            }
        return {'current_memory_mb': 0, 'current_virtual_mb': 0, 'crypto_objects_count': 0, 
                'estimated_pubkeys_memory_kb': 0, 'estimated_session_keys_memory_kb': 0, 'uptime_minutes': 0}

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
        self.sessions = {}  # username -> {timestamp, timer}
        self.user_pubkeys = {}  # username -> PEM-encoded public key
        self.session_keys = {}  # username -> {peer_username -> derived_key}
        self.user_messages = {}  # username -> list of cached messages
        
        # Admin inspection features
        self.admin_inspectors = {}  # username -> connection (admins in inspection mode)
        self.inspection_logs = []  # Store recent inspection events
        self.max_inspection_logs = 100  # Keep last 100 events
        
        # Performance monitoring
        self.perf_monitor = PerformanceMonitor()
        
        # Start periodic memory monitoring
        self.start_memory_monitoring()
    
    def start_memory_monitoring(self):
        """Start periodic memory usage monitoring"""
        def monitor_memory():
            while True:
                self.perf_monitor.record_memory_usage()
                # Update crypto object counts
                pubkeys_count = len(self.user_pubkeys)
                session_keys_count = sum(len(keys) for keys in self.session_keys.values())
                self.perf_monitor.update_crypto_object_counts(pubkeys_count, session_keys_count)
                time.sleep(30)  # Record every 30 seconds
        
        monitor_thread = threading.Thread(target=monitor_memory)
        monitor_thread.daemon = True
        monitor_thread.start()
    
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
        """Create new user account with TOTP 2FA and QR code image"""
        if username in self.users:
            return False, "Username already exists", None

        # Generate a unique random 128-bit salt for this user
        salt_bytes = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        hashed_totp = hashlib.sha256(totp_secret.encode()).hexdigest()

        # Proper TOTP URI format with issuer and label
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="SecureText"
        )

        # Generate QR code image and save to file
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        qr_filename = f"qrcode_{username}.png"
        img.save(qr_filename)

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
            'totp_secret_raw': totp_secret,
            'totp_enabled': True,
            'totp_attempts': 0,
            'totp_block_until': 0,
            'admin': admin
        }
        self.save_users()

        # Return the QR code filename and manual setup info
        return True, "Account created successfully. TOTP setup required.", {
            'qr_code_file': qr_filename,
            'totp_secret': totp_secret,
            'totp_uri': totp_uri
        }
    
    def verify_totp(self, username, totp_code):
        """Verify TOTP code for a user"""
        if not username in self.users:
            return False
        
        user = self.users[username]
        if not user.get('totp_enabled'):
            return True  # If 2FA is not enabled, always return True
        
        if not 'totp_secret_raw' in user:
            return False
        
        totp = pyotp.TOTP(user['totp_secret_raw'])
        return totp.verify(totp_code, valid_window=1)  # Allow 30 seconds window

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

    def store_user_pubkey(self, username, pubkey_pem):
        """Store a user's public key (PEM format) with performance timing."""
        start_time = self.perf_monitor.start_timer()
        
        self.user_pubkeys[username] = pubkey_pem
        
        duration = self.perf_monitor.end_timer(start_time, 'pubkey_serialization_times')
        
        # Enhanced logging for ECDH key generation with performance data
        self.log_inspection_event(
            "ECDH_PUBKEY_STORED", 
            username, 
            f"ECDH public key generated and stored for {username} (took {duration:.2f}ms)",
            {
                "key_algorithm": "SECP256R1",
                "key_format": "PEM",
                "key_length": len(pubkey_pem),
                "storage_time_ms": duration,
                "key_preview": pubkey_pem[:100] + "..." if len(pubkey_pem) > 100 else pubkey_pem
            }
        )

    def get_user_pubkey(self, username):
        """Retrieve a user's public key (PEM format) with performance timing."""
        start_time = self.perf_monitor.start_timer()
        
        pubkey = self.user_pubkeys.get(username)
        
        duration = self.perf_monitor.end_timer(start_time, 'pubkey_deserialization_times')
        
        if pubkey:
            self.log_inspection_event(
                "ECDH_PUBKEY_REQUESTED", 
                username, 
                f"Public key requested for {username} (retrieved in {duration:.2f}ms)",
                {
                    "key_available": True,
                    "key_length": len(pubkey),
                    "retrieval_time_ms": duration
                }
            )
        else:
            self.log_inspection_event(
                "ECDH_PUBKEY_REQUESTED", 
                username, 
                f"Public key requested for {username} but not available (checked in {duration:.2f}ms)",
                {
                    "key_available": False,
                    "retrieval_time_ms": duration
                }
            )
        
        return pubkey

    def log_key_exchange_completion(self, user1, user2, success=True):
        """Log when ECDH key exchange is completed between two users"""
        if success:
            self.log_inspection_event(
                "ECDH_KEY_EXCHANGE_COMPLETED", 
                user1, 
                f"ECDH key exchange completed between {user1} and {user2}",
                {
                    "peer": user2,
                    "exchange_status": "success",
                    "shared_key_derived": True
                }
            )
        else:
            self.log_inspection_event(
                "ECDH_KEY_EXCHANGE_FAILED", 
                user1, 
                f"ECDH key exchange failed between {user1} and {user2}",
                {
                    "peer": user2,
                    "exchange_status": "failed",
                    "failure_reason": "Public key not available or invalid"
                }
            )

    def log_message_encryption(self, sender, recipient, success=True):
        """Log when a message is encrypted using ECDH-derived key"""
        if success:
            self.log_inspection_event(
                "MESSAGE_ENCRYPTED", 
                sender, 
                f"Message encrypted using ECDH-derived key: {sender} → {recipient}",
                {
                    "recipient": recipient,
                    "encryption_algorithm": "AES-256-GCM",
                    "key_derivation": "ECDH + HKDF-SHA256"
                }
            )
        else:
            self.log_inspection_event(
                "MESSAGE_ENCRYPTION_FAILED", 
                sender, 
                f"Message encryption failed: {sender} → {recipient}",
                {
                    "recipient": recipient,
                    "failure_reason": "ECDH key exchange not completed"
                }
            )
    def inspect_message_flow(self, sender, recipient, encrypted_content):
        """Log details about encrypted message flow for admin inspection"""
        # Create a truncated preview of the encrypted content
        preview = encrypted_content[:20] + "..." if len(encrypted_content) > 20 else encrypted_content
        # Log encrypted message flow for admin inspection (no emoji, clear for admin)
        self.log_inspection_event(
            "MESSAGE_FLOW", 
            sender, 
            f"ENCRYPTED MESSAGE FLOW: {sender} to {recipient}",
            {
                "sender": sender,
                "recipient": recipient,
                "content_length": len(encrypted_content) if encrypted_content else 0,
                "encrypted_preview": preview,
                "encryption": "AES-256-GCM with ECDH key exchange",
                "timestamp": datetime.now().isoformat()
            }
        )

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
                data = conn.recv(8192).decode('utf-8')
                if not data:
                    break

                try:
                    message = json.loads(data)
                    command = message.get('command')
                    
                    # Reset session timer IMMEDIATELY when receiving data from logged-in users
                    # This happens BEFORE command processing to ensure timer reset happens first
                    if current_user and current_user in self.sessions:
                        self.reset_session_timer(current_user)
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        success, msg, data = self.create_account(username, password)
                        response = {
                            'status': 'success' if success else 'error',
                            'message': msg,
                            'data': data if success else None
                        }
                        
                    elif command == 'LOGIN':
                        # Step 1: Send challenge to client
                        challenge = self.generate_challenge()
                        response = {'status': 'challenge', 'challenge': challenge}
                        conn.send(json.dumps(response).encode('utf-8'))

                        # Step 2: Wait for client's MAC response
                        data = conn.recv(8192).decode('utf-8')
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
                                    self.create_session(username)  # Start session timers here
                                response = {
                                    'status': 'success' if success else 'error',
                                    'message': msg,
                                    'username': username if success else None  # <-- Add this line
                                }
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Login error: {str(e)}'}
                        
                    elif command == 'LOGIN_RESPONSE':
                        client_mac = message.get('mac')
                        username = message.get('username')
                        password = message.get('password')
                        totp_code = message.get('totp_code')

                        # We need to verify the challenge-response without a stored challenge
                        # This is simplified - normally would validate against a stored challenge
                        success, msg = self.authenticate(username, password, totp_code)
                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                            self.create_session(username)  # Start session timers here
                        response = {
                            'status': 'success' if success else 'error',
                            'message': msg,
                            'username': username if success else None
                        }
                    
                    elif command == 'SEND_MESSAGE':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            recipient = message.get('recipient')
                            msg_content = message.get('content')

                            # --- Enhanced Inspection of Encrypted Message Flow ---
                            self.inspect_message_flow(current_user, recipient, msg_content)
                            
                            # Log that encrypted communication is happening
                            self.log_message_encryption(current_user, recipient, success=True)
                            # -----------------------------------------------------

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
                                    
                                    # Log successful message delivery with encrypted preview
                                    self.log_inspection_event(
                                        "MESSAGE_DELIVERED", 
                                        current_user, 
                                        f"Encrypted message delivered: {current_user} → {recipient}",
                                        {
                                            "sender": current_user,
                                            "recipient": recipient,
                                            "message_encrypted": True,
                                            "encrypted_preview": msg_content[:20] + "..." if len(msg_content) > 20 else msg_content,
                                            "timestamp": datetime.now().isoformat()
                                        }
                                    )
                                    
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except:
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
                    
                    elif command == 'PUBLISH_PUBKEY':
                        username = message.get('username')
                        pubkey_pem = message.get('pubkey')
                        self.store_user_pubkey(username, pubkey_pem)
                        response = {'status': 'success', 'message': 'Public key stored'}

                    elif command == 'GET_PUBKEY':
                        target_user = message.get('target_user')
                        requester = current_user if current_user else "unknown"
                        
                        # Log who is requesting whose public key
                        self.log_inspection_event(
                            "ECDH_PUBKEY_REQUEST", 
                            requester, 
                            f"{requester} requesting public key for {target_user}",
                            {
                                "target_user": target_user,
                                "purpose": "ECDH key exchange initiation"
                            }
                        )
                        
                        pubkey_pem = self.get_user_pubkey(target_user)
                        if pubkey_pem:
                            # Log successful key exchange initiation
                            self.log_key_exchange_completion(requester, target_user, success=True)
                            response = {'status': 'success', 'pubkey': pubkey_pem}
                        else:
                            # Log failed key exchange
                            self.log_key_exchange_completion(requester, target_user, success=False)
                            response = {'status': 'error', 'message': 'No public key for user'}
                    
                    elif command == 'START_ADMIN_INSPECTION':
                        admin_username = message.get('admin_username')
                        success, msg, data = self.start_admin_inspection(admin_username, conn)
                        response = {
                            'status': 'success' if success else 'error',
                            'message': msg,
                            'data': data if success else None
                        }
                    
                    elif command == 'STOP_ADMIN_INSPECTION':
                        admin_username = message.get('admin_username')
                        success, msg = self.stop_admin_inspection(admin_username)
                        response = {
                            'status': 'success' if success else 'error',
                            'message': msg
                        }
                    
                    elif command == 'START_INSPECTION':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            success, msg, logs = self.start_admin_inspection(current_user, conn)
                            if success:
                                response = {
                                    'status': 'success', 
                                    'message': msg,
                                    'recent_logs': logs
                                }
                                # Send the response first
                                conn.send(json.dumps(response).encode('utf-8'))
                                
                                # Then log the inspection event (which will notify other admins, not this one)
                                self.log_inspection_event("ADMIN_INSPECTION_START", current_user, "Admin started inspection mode")
                                
                                # Skip the normal response sending at the end
                                continue
                            else:
                                response = {'status': 'error', 'message': msg}

                    elif command == 'STOP_INSPECTION':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            success, msg = self.stop_admin_inspection(current_user)
                            response = {
                                'status': 'success' if success else 'error',
                                'message': msg
                            }

                    elif command == 'GET_CONNECTION_STATUS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        elif not self.users.get(current_user, {}).get('admin', False):
                            response = {'status': 'error', 'message': 'Admin privileges required'}
                        else:
                            status = self.get_connection_status()
                            response = {
                                'status': 'success',
                                'connection_status': status
                            }
                    
                    elif command == 'GET_PERFORMANCE_STATS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        elif not self.users.get(current_user, {}).get('admin', False):
                            response = {'status': 'error', 'message': 'Admin privileges required'}
                        else:
                            stats = self.get_performance_stats()
                            response = {
                                'status': 'success',
                                'performance_stats': stats
                            }
                    
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
                    # Remove the old session timer reset code that was here
                    # The timer reset now happens at the top of the loop
                    
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
        except ConnectionResetError:
            pass
        finally:
            # Clean up connection and session
            if current_user:
                if current_user in self.active_connections:
                    del self.active_connections[current_user]
                # Ensure session is cleared on disconnect
                if current_user in self.sessions:
                    self.clear_session(current_user)
            conn.close()
            print(f"Connection from {addr} closed")

    def reset_session_timer(self, username):
        """Reset the session timeout for a user upon activity."""
        if username in self.sessions:
            # Cancel existing timers
            self.sessions[username]['warning_timer'].cancel()
            self.sessions[username]['timeout_timer'].cancel()

            # Create new timers
            warning_timer = Timer(
                (SESSION_TIMEOUT_MINUTES - WARNING_BEFORE_TIMEOUT_MINUTES) * 60,
                self.send_timeout_warning,
                args=[username]
            )
            timeout_timer = Timer(
                SESSION_TIMEOUT_MINUTES * 60,
                self.expire_session,
                args=[username]
            )
            
            # Update session with new timers and activity timestamp
            self.sessions[username]['warning_timer'] = warning_timer
            self.sessions[username]['timeout_timer'] = timeout_timer
            self.sessions[username]['last_activity'] = time.time()
            
            # Start the new timers
            warning_timer.start()
            timeout_timer.start()
    
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
    
    def create_session(self, username):
        """Create a new session for user with timeout"""
        if username in self.sessions:
            self.clear_session(username)
        
        # Create warning and timeout timers
        warning_timer = Timer(
            (SESSION_TIMEOUT_MINUTES - WARNING_BEFORE_TIMEOUT_MINUTES) * 60,
            self.send_timeout_warning,
            args=[username]
        )
        timeout_timer = Timer(
            SESSION_TIMEOUT_MINUTES * 60,
            self.expire_session,
            args=[username]
        )
        
        self.sessions[username] = {
            'timestamp': time.time(),
            'warning_timer': warning_timer,
            'timeout_timer': timeout_timer,
            'last_activity': time.time()  # Track last activity
        }
        
        # Start the timers
        warning_timer.start()
        timeout_timer.start()

    def clear_session(self, username):
        """Safely clear session data and cryptographic material"""
        if username in self.sessions:
            # Cancel existing timers
            self.sessions[username]['warning_timer'].cancel()
            self.sessions[username]['timeout_timer'].cancel()
            # Remove session data
            del self.sessions[username]
        
        # Track what's being cleared for inspection
        cleared_items = []
        
        # Clear user's public key from server storage
        if username in self.user_pubkeys:
            del self.user_pubkeys[username]
            cleared_items.append("public_key")
        
        # Clear all session keys involving this user
        if username in self.session_keys:
            key_count = len(self.session_keys[username])
            del self.session_keys[username]
            cleared_items.append(f"session_keys({key_count})")
        
        # Clear session keys where this user is a peer
        peer_keys_cleared = 0
        for user in list(self.session_keys.keys()):
            if username in self.session_keys[user]:
                del self.session_keys[user][username]
                peer_keys_cleared += 1
        
        if peer_keys_cleared > 0:
            cleared_items.append(f"peer_keys({peer_keys_cleared})")
        
        # Clear cached messages for this user
        if username in self.user_messages:
            message_count = len(self.user_messages[username])
            del self.user_messages[username]
            cleared_items.append(f"cached_messages({message_count})")
        
        # Clear failed login attempts (security cleanup)
        if username in self.failed_logins:
            del self.failed_logins[username]
            cleared_items.append("failed_login_attempts")
        
        # Log the cleanup for inspection with detailed information 
        self.log_inspection_event(
            "CRYPTOGRAPHIC_MATERIAL_CLEARED", 
            username, 
            f"SECURE KEY CLEANUP: All cryptographic material cleared for {username}",
            {
                "cleared_items": cleared_items,
                "cleanup_reason": "session_timeout_or_logout",
                "security_impact": "All ECDH keys, session keys, and cached data permanently deleted",
                "items_detail": {
                    "ecdh_public_key": "REMOVED" if "public_key" in cleared_items else "NOT_PRESENT",
                    "session_keys": f"DELETED ({[item for item in cleared_items if 'session_keys' in item]})" if any('session_keys' in item for item in cleared_items) else "NONE",
                    "peer_keys": f"DELETED ({[item for item in cleared_items if 'peer_keys' in item]})" if any('peer_keys' in item for item in cleared_items) else "NONE",
                    "cached_messages": f"DELETED ({[item for item in cleared_items if 'cached_messages' in item]})" if any('cached_messages' in item for item in cleared_items) else "NONE"
                }
            }
        )
    
    def send_timeout_warning(self, username):
        """Send warning message to user before session expires"""
        if username in self.active_connections:
            warning_msg = {
                'type': 'SESSION_WARNING',
                'message': f'Your session will expire in {WARNING_BEFORE_TIMEOUT_MINUTES} minutes due to inactivity. Perform any action to reset the timer.',
                'remaining_minutes': WARNING_BEFORE_TIMEOUT_MINUTES
            }
            try:
                self.active_connections[username].send(
                    json.dumps(warning_msg).encode('utf-8')
                )
            except:
                pass

    def expire_session(self, username):
        """Handle session expiration with comprehensive cleanup"""
        print(f"[SESSION] Expiring session for user: {username} due to inactivity")
        
        # Log session expiration BEFORE cleanup for admin inspection
        self.log_inspection_event(
            "SESSION_TIMEOUT", 
            username, 
            f"SESSION EXPIRED: User {username} session expired after {SESSION_TIMEOUT_MINUTES} minutes of inactivity",
            {
                "timeout_duration_minutes": SESSION_TIMEOUT_MINUTES,
                "expiration_reason": "inactivity_timeout",
                "cleanup_pending": True,
                "user_notified": username in self.active_connections,
                "last_activity": self.sessions.get(username, {}).get('last_activity', 'unknown')
            }
        )
        
        if username in self.active_connections:
            expiration_msg = {
                'type': 'SESSION_EXPIRED',
                'message': f'Your session has expired due to {SESSION_TIMEOUT_MINUTES} minutes of inactivity. Please login again.',
                'force_cleanup': True
            }
            try:
                self.active_connections[username].send(
                    json.dumps(expiration_msg).encode('utf-8')
                )
                print(f"[SESSION] Sent inactivity-based session expiration notice to {username}")
            except:
                print(f"[SESSION] Could not notify {username} of session expiration")
        
        # Clean up all session data and cryptographic material
        if username in self.active_connections:
            try:
                self.active_connections[username].close()
            except:
                pass
            del self.active_connections[username]
            print(f"[SESSION] Closed connection for {username}")
        
        # Clear all session data including keys and messages
        self.clear_session(username)
        
        # Log the session expiration for security audit
        self.log_action("session", username, f"Session expired after {SESSION_TIMEOUT_MINUTES} minutes of inactivity - all keys and data cleared", "expired")

    def start_admin_inspection(self, admin_username, conn):
        """Start admin inspection mode - no session timeout"""
        print(f"[DEBUG] start_admin_inspection called for user: {admin_username}")
        
        if not self.users.get(admin_username, {}).get('admin', False):
            print(f"[DEBUG] User {admin_username} is not admin")
            return False, "Admin privileges required", None
        
        print(f"[DEBUG] User {admin_username} is admin, proceeding with inspection setup")
        
        # Cancel any existing session timeout for this admin
        if admin_username in self.sessions:
            self.sessions[admin_username]['warning_timer'].cancel()
            self.sessions[admin_username]['timeout_timer'].cancel()
            del self.sessions[admin_username]
            print(f"[DEBUG] Cancelled existing session for {admin_username}")
        
        self.admin_inspectors[admin_username] = conn
        print(f"[DEBUG] Added {admin_username} to admin_inspectors")
        
        # DON'T log the inspection event here - it causes immediate notification
        # self.log_inspection_event("ADMIN_INSPECTION_START", admin_username, "Admin started inspection mode")
        
        # Send recent inspection logs to admin
        try:
            recent_logs = self.get_recent_inspection_logs()
            print(f"[DEBUG] Retrieved {len(recent_logs)} recent logs")
            return True, "Inspection mode activated", recent_logs
        except Exception as e:
            print(f"[DEBUG] Error getting recent logs: {e}")
            return True, "Inspection mode activated", []

    def stop_admin_inspection(self, admin_username):
        """Stop admin inspection mode and restore normal session"""
        if admin_username in self.admin_inspectors:
            del self.admin_inspectors[admin_username]
            self.log_inspection_event("ADMIN_INSPECTION_STOP", admin_username, "Admin stopped inspection mode")
            # Restart normal session
            self.create_session(admin_username)
            return True, "Inspection mode deactivated"
        return False, "Not in inspection mode"

    def log_inspection_event(self, event_type, username, details, extra_data=None):
        """Log inspection events for admin monitoring"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'username': username,
            'details': details,
            'extra_data': extra_data
        }
        
        self.inspection_logs.append(event)
        
        # Keep only recent logs
        if len(self.inspection_logs) > self.max_inspection_logs:
            self.inspection_logs = self.inspection_logs[-self.max_inspection_logs:]
        
        # Notify all active admin inspectors
        self.notify_admin_inspectors(event)

    def notify_admin_inspectors(self, event):
        """Send inspection event to all active admin inspectors"""
        notification = {
            'type': 'INSPECTION_EVENT',
            'event': event
        }
        
        # Don't notify the admin who just triggered this event during startup
        triggering_admin = event.get('username') if event.get('event_type') == 'ADMIN_INSPECTION_START' else None
        
        # Use a copy of the items to avoid issues with dictionary size changing during iteration
        inspectors_to_notify = list(self.admin_inspectors.items())

        def send_notification(admin_username, conn):
            """Target function for the notification thread."""
            # Skip notifying the admin who just started inspection mode
            if admin_username == triggering_admin and event.get('event_type') == 'ADMIN_INSPECTION_START':
                return
            
            try:
                conn.send(json.dumps(notification).encode('utf-8'))
            except Exception:
                # If sending fails, we can schedule the cleanup on the main thread
                # For now, we just note it. The main loop will handle cleanup.
                print(f"[INSPECTION] Failed to send notification to {admin_username}. Connection may be closed.")

        for admin_username, conn in inspectors_to_notify:
            # Send each notification in a separate thread to avoid blocking
            notification_thread = threading.Thread(target=send_notification, args=(admin_username, conn))
            notification_thread.daemon = True
            notification_thread.start()

    def get_recent_inspection_logs(self):
        """Get recent inspection logs for admin"""
        return self.inspection_logs[-50:]  # Last 50 events

    def get_connection_status(self):
        """Get current connection status for admin inspection"""
        status = {
            'active_connections': list(self.active_connections.keys()),
            'active_sessions': list(self.sessions.keys()),
            'admin_inspectors': list(self.admin_inspectors.keys()),
            'stored_pubkeys': list(self.user_pubkeys.keys()),
            'session_keys_count': {user: len(keys) for user, keys in self.session_keys.items()},
            'total_users': len(self.users)
        }
        return status

    def get_performance_stats(self):
        """Get comprehensive performance statistics for admin inspection"""
        crypto_stats = self.perf_monitor.get_crypto_stats()
        memory_stats = self.perf_monitor.get_memory_stats()
        
        return {
            'cryptographic_performance': crypto_stats,
            'memory_usage': memory_stats,
            'server_status': {
                'active_connections': len(self.active_connections),
                'stored_pubkeys': len(self.user_pubkeys),
                'total_session_keys': sum(len(keys) for keys in self.session_keys.values()),
                'active_sessions': len(self.sessions),
                'admin_inspectors': len(self.admin_inspectors)
            }
        }

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
        self.ecdh_private_key = None
        self.ecdh_public_key_pem = None
        self.inspection_mode = False  # Track if in inspection mode
        self.countdown_active = False  # Track if countdown is currently displaying
        self.stop_countdown = False   # Signal to stop countdown display

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
            # Stop countdown display when user performs any action
            if self.countdown_active:
                self.stop_countdown = True
                time.sleep(0.1)  # Brief pause to let countdown thread clear the line
            
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            response = self.socket.recv(8192).decode('utf-8')  # Increased buffer size
            return json.loads(response)
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
    
    def listen_for_messages(self):
        """Listen for incoming messages including session notifications and inspection events"""
        while self.running:
            try:
                data = self.socket.recv(8192).decode('utf-8')
                if data:
                    message = json.loads(data)
                    
                    if message.get('type') == 'SESSION_WARNING':
                        if not self.inspection_mode:  # Don't show warnings in inspection mode
                            print(f"\n [INACTIVITY WARNING] {message['message']}")
                            self.start_countdown(message['remaining_minutes'])
                            print(">> ", end="", flush=True)
                    
                    elif message.get('type') == 'SESSION_EXPIRED':
                        print(f"\n [SESSION EXPIRED] {message['message']}")
                        
                        # Clear all cryptographic material if forced cleanup
                        if message.get('force_cleanup'):
                            self.clear_crypto_material()
                        
                        self.logged_in = False
                        self.username = None
                        self.running = False
                        self.inspection_mode = False
                        break
                    
                    elif message.get('type') == 'INSPECTION_EVENT':
                        # Display real-time inspection events
                        if self.inspection_mode:
                            print("\n--- New Inspection Event ---")
                            self.display_inspection_event(message['event'])
                            print(">> ", end="", flush=True)
                    
                    elif message.get('type') == 'MESSAGE':
                        sender = message['from']
                        encrypted_content = message['content']
                        
                        # Show the encrypted content to receiver
                        print(f"\n[MESSAGE] From {sender} (encrypted): '{encrypted_content[:50]}...'")
                        
                        # ECDH key agreement with sender's pubkey
                        peer_pubkey = self.get_peer_pubkey(sender)
                        if peer_pubkey:
                            shared_key = self.derive_shared_key(peer_pubkey)
                            try:
                                plaintext = self.decrypt_message(encrypted_content, shared_key)
                            except Exception as e:
                                plaintext = "[Decryption failed]"
                        else:
                            plaintext = "[No public key for sender]"
                        print(f"[{message['timestamp']}] {sender}: {plaintext}")
                        print(">> ", end="", flush=True)
            except:
                break
    
    def start_countdown(self, minutes):
        """Display countdown timer for inactivity warning"""
        def countdown():
            self.countdown_active = True
            self.stop_countdown = False
            remaining_seconds = minutes * 60
            
            while remaining_seconds > 0 and self.running and not self.stop_countdown:
                mins = remaining_seconds // 60
                secs = remaining_seconds % 60
                print(f"\r [Inactivity timeout in: {mins:02d}:{secs:02d} - perform any action to reset]", end="", flush=True)
                time.sleep(1)
                remaining_seconds -= 1
            
            # Clear countdown line when stopping
            if self.stop_countdown or not self.running:
                print("\r" + " " * 80 + "\r", end="", flush=True)  # Clear countdown line
            
            self.countdown_active = False
        
        countdown_thread = threading.Thread(target=countdown)
        countdown_thread.daemon = True
        countdown_thread.start()

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
        print(f"\n{response['message']}")
        
        if response['status'] == 'success' and 'data' in response:
            print("\n=== 2FA Setup Instructions ===")
            print("A QR code image has been generated on the server.")
            print(f"File name: {response['data']['qr_code_file']}")
            print("Open this image file and scan it with your authenticator app (Google Authenticator, Authy, etc.).")
            print("\nCan't scan the QR code? Use manual setup:")
            print(f"- Secret key: {response['data']['totp_secret']}")
            print(f"- Type: Time-based (TOTP)")
            print(f"- Account: {username}")
            print(f"- Issuer: SecureText")
            print("\nAlternatively, use this URI in your app:")
            print(response['data']['totp_uri'])
            print("\nIMPORTANT: Save these credentials securely - you'll need them to log in!")
            input("\nPress Enter once you've set up 2FA in your authenticator app...")
            
            webbrowser.open(response['data']['qr_code_file'])
    
    def login(self):
        """Login to the system with password or OAuth"""
        print("\n=== Login ===")
        print("1. Login with username/password")
        print("2. Login with GitHub")
        choice = input("Choose login method: ").strip()
        
        # Check if socket is still valid and reconnect if needed
        try:
            self.socket.getpeername()  # This will raise an exception if socket is closed
        except:
            print("Reconnecting to server...")
            if not self.connect():
                print("Failed to reconnect to server.")
                return
    
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
            
            try:
                response = self.socket.recv(8192).decode('utf-8')
                response = json.loads(response)
                if response.get('status') == 'challenge':
                    challenge = response['challenge']
                    # Step 2: Compute MAC and send back
                    mac = hmac.new(
                        SHARED_SECRET_KEY.encode(),
                        challenge.encode(),
                        hashlib.sha256
                    ).hexdigest()
                    response_command = {
                        'command': 'LOGIN_RESPONSE',  # Add command field here
                        'mac': mac,
                        'username': username,
                        'password': password,
                        'totp_code': totp_code
                    }
                    self.socket.send(json.dumps(response_command).encode('utf-8'))
                    
                    response = self.socket.recv(8192).decode('utf-8')
                    try:
                        response = json.loads(response)
                        
                        # Process the login response here instead of falling through
                        if response['status'] == 'success':
                            self.logged_in = True
                            self.username = response.get('username')
                            self.running = True
                            
                            # --- ECDH Key Exchange ---
                            self.generate_ecdh_keypair()
                            self.publish_pubkey()
                            # -------------------------

                            # Start listening for messages
                            listen_thread = threading.Thread(target=self.listen_for_messages)
                            listen_thread.daemon = True
                            listen_thread.start()
                            
                        print(f"\n{response['message']}")
                        return  # Return here to avoid the duplicate command processing below
                        
                    except json.JSONDecodeError as e:
                        print(f"Error decoding server response: {e}")
                        print(f"Raw response: {response}")
                        return
            except Exception as e:
                print(f"Connection error during login: {e}")
                print("Please try reconnecting.")
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
            
            # --- ECDH Key Exchange ---
            self.generate_ecdh_keypair()
            self.publish_pubkey()
            # -------------------------

            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_message(self):
        """Send a message to another user (ECDH key exchange for encryption)"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return

        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()
        content = input("Enter message: ").strip()

        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return

        try:
            # --- ECDH Key Exchange ---
            peer_pubkey = self.get_peer_pubkey(recipient)
            if not peer_pubkey:
                print("Could not get recipient's public key.")
                return
            
            shared_key = self.derive_shared_key(peer_pubkey)
            encrypted_content = self.encrypt_message(content, shared_key)
            # -------------------------
            
            command = {
                'command': 'SEND_MESSAGE',
                'recipient': recipient,
                'content': encrypted_content  # Encrypted!
            }

            response = self.send_command(command)
            print(f"{response['message']}")
            
        except Exception as e:
            print(f"Error sending message: {str(e)}")
            print("Please try again or check if recipient has published their public key.")
    
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
        
        print("=== SecureText Messenger ===")
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
                
                # Simple menu without admin detection issues
                print("1. Send Message")
                print("2. List Users")
                print("3. Get Connection Status (Admin only)")
                print("4. Get Performance Stats (Admin only)")
                #The get performance stats command cannot be used directly after sign in as admin. Otherwise the program will get stuck.
                #The first thing you should do is to start inspection mode.
                print("5. Start Inspection Mode (Admin only)")
                print("6. Stop Inspection Mode (Admin only)")
                print("7. Logout")
                
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.get_connection_status()  # Will show error if not admin
                elif choice == '4':
                    self.get_performance_stats()  # Will show error if not admin
                elif choice == '5':
                    self.start_inspection_mode()  # Will show error if not admin
                elif choice == '6':
                    self.stop_inspection_mode()  # Will show error if not admin
                elif choice == '7':
                    # Logout
                    self.clear_crypto_material()
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    self.inspection_mode = False
                    print("Logged out successfully")
                elif choice == '':
                    # Just wait for messages
                    if self.inspection_mode:
                        print("Monitoring server activity... (press Enter to show menu)")
                    else:
                        print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")

    def generate_ecdh_keypair(self):
        """Generate ECDH key pair and store PEM public key with performance timing."""
        start_time = time.perf_counter()
        
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        keygen_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
        
        start_time = time.perf_counter()
        pubkey = self.ecdh_private_key.public_key()
        self.ecdh_public_key_pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        serialization_time = (time.perf_counter() - start_time) * 1000
        
        print(f"[ECDH] Generated new ECDH key pair for {self.username}")
        print(f"[PERFORMANCE] Key generation: {keygen_time:.2f}ms, Serialization: {serialization_time:.2f}ms")

    def publish_pubkey(self):
        """Send public key to server after login."""
        command = {
            'command': 'PUBLISH_PUBKEY',
            'username': self.username,
            'pubkey': self.ecdh_public_key_pem
        }
        response = self.send_command(command)
        
        if response.get('status') == 'success':
            print(f"[ECDH] Public key published to server for {self.username}")
        else:
            print(f"[ECDH] Failed to publish public key: {response.get('message')}")

    def get_peer_pubkey(self, peer_username):
        """Get another user's public key from the server."""
        print(f"[ECDH] Requesting public key for {peer_username}")
        
        command = {
            'command': 'GET_PUBKEY',
            'target_user': peer_username
        }
        response = self.send_command(command)
        
        # Add error handling for missing 'status' key
        if not isinstance(response, dict):
            print(f"Error: Invalid response from server: {response}")
            return None
            
        if response.get('status') == 'success':
            try:
                pubkey = serialization.load_pem_public_key(response['pubkey'].encode('utf-8'))
                print(f"[ECDH] Successfully retrieved public key for {peer_username}")
                return pubkey
            except Exception as e:
                print(f"Error loading public key: {e}")
                return None
        else:
            print(f"Error: {response.get('message', 'Unknown error occurred')}")
            return None

    def derive_shared_key(self, peer_pubkey):
        """Derive shared key using ECDH with performance timing."""
        print(f"[ECDH] Deriving shared key using ECDH key exchange")
        
        start_time = time.perf_counter()
        shared_key = self.ecdh_private_key.exchange(ec.ECDH(), peer_pubkey)
        exchange_time = (time.perf_counter() - start_time) * 1000
        
        start_time = time.perf_counter()
        # Use HKDF to derive a proper 32-byte key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for AES-256
            salt=None,
            info=b'SecureText ECDH',
        ).derive(shared_key)
        hkdf_time = (time.perf_counter() - start_time) * 1000
        
        print(f"[ECDH] Shared key derived successfully (32 bytes for AES-256)")
        print(f"[PERFORMANCE] ECDH exchange: {exchange_time:.2f}ms, HKDF derivation: {hkdf_time:.2f}ms")
        return derived_key

    def encrypt_message(self, plaintext, shared_key):
        """Encrypt a message using AES-256-GCM with performance timing."""
        print(f"[ENCRYPTION] Encrypting message using ECDH-derived key")
        print(f"[ENCRYPTION] Original text: '{plaintext}'")
        
        start_time = time.perf_counter()
        aesgcm = AESGCM(shared_key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Send nonce + ciphertext, both base64-encoded for JSON safety
        encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
        encryption_time = (time.perf_counter() - start_time) * 1000
        
        print(f"[ENCRYPTION] Message encrypted successfully using AES-256-GCM")
        print(f"[ENCRYPTION] Encrypted form (base64): '{encrypted[:50]}...'")
        print(f"[PERFORMANCE] AES-256-GCM encryption: {encryption_time:.2f}ms")
        return encrypted

    def decrypt_message(self, b64_ciphertext, shared_key):
        """Decrypt a message using AES-256-GCM with performance timing."""
        print(f"[DECRYPTION] Decrypting received message using ECDH-derived key")
        print(f"[DECRYPTION] Encrypted form (base64): '{b64_ciphertext[:50]}...'")

        start_time = time.perf_counter()
        aesgcm = AESGCM(shared_key)
        data = base64.b64decode(b64_ciphertext)
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        decoded_text = plaintext.decode('utf-8')
        decryption_time = (time.perf_counter() - start_time) * 1000
        
        print(f"[DECRYPTION] Message decrypted successfully")
        print(f"[DECRYPTION] Decrypted text: '{decoded_text}'")
        print(f"[PERFORMANCE] AES-256-GCM decryption: {decryption_time:.2f}ms")
        return decoded_text
    
    def display_inspection_event(self, event):
        """Display an inspection event in a formatted way"""
        timestamp = event['timestamp'][:19]  # Remove microseconds
        event_type = event['event_type']
        username = event['username']
        details = event['details']
        
        
        print(f"[{timestamp}] {event_type}")
        print(f"  User: {username}")
        print(f"  Details: {details}")
        
        if event.get('extra_data'):
            extra = event['extra_data']
            print(f"  Extra Info:")
            for key, value in extra.items():
                print(f"    {key}: {value}")
        print()

    def start_inspection_mode(self):
        """Start admin inspection mode"""
        if not self.logged_in:
            print("You must be logged in to start inspection!")
            return
        
        command = {
            'command': 'START_INSPECTION',
            'admin_username': self.username  # Add the username
        }
        response = self.send_command(command)
        
        # Add error handling for missing 'status' key
        if not isinstance(response, dict):
            print(f"Error: Invalid response from server: {response}")
            return
            
        status = response.get('status')
        if status == 'success':
            self.inspection_mode = True
            print(f"\n{response.get('message', 'Inspection mode started')}")
            print(f"\n{response.get('message', 'Inspection mode stopped')}")
        elif status == 'error':
            print(f"Error: {response.get('message', 'Unknown error occurred')}")
        else:
            print(f"Unexpected response: {response}")

    def get_connection_status(self):
        """Get current server connection status"""
        command = {'command': 'GET_CONNECTION_STATUS'}
        response = self.send_command(command)
        
        # Add error handling for missing 'status' key
        if not isinstance(response, dict):
            print(f"Error: Invalid response from server: {response}")
            return
            
        status = response.get('status')
        if status == 'success':
            conn_status = response.get('connection_status', {})
            print("\n=== Server Connection & Cryptographic Status ===")
            print(f" Active Connections: {', '.join(conn_status.get('active_connections', [])) or 'None'}")
            print(f" Active Sessions: {', '.join(conn_status.get('active_sessions', [])) or 'None'}")
            print(f" Admin Inspectors: {', '.join(conn_status.get('admin_inspectors', [])) or 'None'}")
            print(f" Users with ECDH Public Keys: {', '.join(conn_status.get('stored_pubkeys', [])) or 'None'}")
            
            session_keys = conn_status.get('session_keys_count', {})
            if session_keys:
                print(f" ECDH Session Keys Per User:")
                for user, count in session_keys.items():
                    print(f"    {user}: {count} derived keys")
            else:
                print(f" ECDH Session Keys: None derived yet")
                
            print(f" Total Registered Users: {conn_status.get('total_users', 0)}")
            
            # Additional ECDH status info
            total_pubkeys = len(conn_status.get('stored_pubkeys', []))
            total_session_keys = sum(session_keys.values()) if session_keys else 0
            print(f"\n Cryptographic Summary:")
            print(f"    ECDH Public Keys Available: {total_pubkeys}")
            print(f"    Total Derived Session Keys: {total_session_keys}")
            print(f"    Key Exchange Capability: {'Active' if total_pubkeys > 1 else 'Limited (need ≥2 users with keys)'}")
            
        elif status == 'error':
            print(f"Error: {response.get('message', 'Unknown error occurred')}")
        else:
            print(f"Unexpected response: {response}")

    def get_performance_stats(self):
        """Get performance statistics from server"""
        command = {'command': 'GET_PERFORMANCE_STATS'}
        response = self.send_command(command)
        
        if not isinstance(response, dict):
            print(f"Error: Invalid response from server: {response}")
            return
            
        status = response.get('status')
        if status == 'success':
            stats = response.get('performance_stats', {})
            self.display_performance_stats(stats)
        elif status == 'error':
            print(f"Error: {response.get('message', 'Unknown error occurred')}")
        else:
            print(f"Unexpected response: {response}")

    def display_performance_stats(self, stats):
        """Display performance statistics in a formatted way"""
        print("\n=== E2EE Performance & Memory Statistics ===")
        
        # Cryptographic Performance
        crypto = stats.get('cryptographic_performance', {})
        print("\nCryptographic Operations Performance:")
        
        operations = {
            'ecdh_keygen_times': 'ECDH Key Generation',
            'ecdh_exchange_times': 'ECDH Key Exchange', 
            'hkdf_derivation_times': 'HKDF Key Derivation',
            'aes_encryption_times': 'AES-256-GCM Encryption',
            'aes_decryption_times': 'AES-256-GCM Decryption',
            'pubkey_serialization_times': 'Public Key Storage',
            'pubkey_deserialization_times': 'Public Key Retrieval'
        }
        
        for op_key, op_name in operations.items():
            op_stats = crypto.get(op_key, {})
            count = op_stats.get('count', 0)
            avg_ms = op_stats.get('avg_ms', 0)
            min_ms = op_stats.get('min_ms', 0)
            max_ms = op_stats.get('max_ms', 0)
            latest_ms = op_stats.get('latest_ms', 0)
            
            if count > 0:
                print(f"  {op_name}:")
                print(f"    Operations: {count} | Avg: {avg_ms:.2f}ms | Min: {min_ms:.2f}ms | Max: {max_ms:.2f}ms | Latest: {latest_ms:.2f}ms")
            else:
                print(f"  {op_name}: No operations recorded")
        
        # Memory Usage
        memory = stats.get('memory_usage', {})
        print(f"\nMemory Usage:")
        print(f"  Server Memory (RSS): {memory.get('current_memory_mb', 0):.1f} MB")
        print(f"  Virtual Memory: {memory.get('current_virtual_mb', 0):.1f} MB")
        print(f"  Cryptographic Objects: {memory.get('crypto_objects_count', 0)}")
        print(f"  Estimated Public Keys Memory: {memory.get('estimated_pubkeys_memory_kb', 0):.2f} KB")
        print(f"  Estimated Session Keys Memory: {memory.get('estimated_session_keys_memory_kb', 0):.3f} KB")
        print(f"  Server Uptime: {memory.get('uptime_minutes', 0):.1f} minutes")
        
        # Server Status
        server = stats.get('server_status', {})
        print(f"\nServer Cryptographic Status:")
        print(f"  Active Connections: {server.get('active_connections', 0)}")
        print(f"  ECDH Public Keys Stored: {server.get('stored_pubkeys', 0)}")
        print(f"  Total Session Keys Derived: {server.get('total_session_keys', 0)}")
        print(f"  Active Sessions: {server.get('active_sessions', 0)}")
        print(f"  Admin Inspectors: {server.get('admin_inspectors', 0)}")

    def clear_crypto_material(self):
        """Clear all cryptographic material from client memory."""
        print("[SECURITY] Clearing all cryptographic material...")
        
        # Clear ECDH private key (most sensitive)
        if self.ecdh_private_key:
            self.ecdh_private_key = None
            print("[SECURITY] Cleared ECDH private key")
        
        # Clear public key PEM
        if self.ecdh_public_key_pem:
            self.ecdh_public_key_pem = None
            print("[SECURITY] Cleared ECDH public key PEM")
        
        print("[SECURITY] All cryptographic material cleared from client")

# ALERT: The main function should NOT be changed in any situation!
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