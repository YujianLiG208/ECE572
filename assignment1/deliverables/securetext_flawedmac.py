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
from pymd5 import md5, padding as pymd5_padding

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        
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
    
    def create_account(self, username, password):
        """Create new user account - stores password using Argon2 hash and unique salt"""
        if username in self.users:
            return False, "Username already exists"
        
        # Generate a unique random 128-bit salt for this user
        salt_bytes = secrets.token_bytes(16)  # 128 bits
        salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')

        ph = PasswordHasher()
        # Combine password and salt for hashing
        password_with_salt = password + salt_b64
        hashed_password = ph.hash(password_with_salt)
        self.users[username] = {
            'password': hashed_password,  # Argon2 hash
            'salt': salt_b64,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue'  # Default for simplicity
        }
        self.save_users()
        return True, "Account created successfully"
    
    def authenticate(self, username, password):
        """Authenticate user with Argon2 password verification and stored salt"""
        if username not in self.users:
            return False, "Username not found"
        
        ph = PasswordHasher()
        stored_password = self.users[username]['password']
        salt_b64 = self.users[username].get('salt')

        # --- Password migration for backward compatibility ---
        # If the stored password is not an Argon2 hash, treat it as plaintext and migrate
        if not (isinstance(stored_password, str) and stored_password.startswith("$argon2")):
            # Legacy plaintext password: compare directly
            if stored_password == password:
                # Migrate: generate salt, hash password, update user record
                if not salt_b64:
                    salt_bytes = secrets.token_bytes(16)
                    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
                    self.users[username]['salt'] = salt_b64
                password_with_salt = password + salt_b64
                hashed_password = ph.hash(password_with_salt)
                self.users[username]['password'] = hashed_password
                self.save_users()
                return True, "Authentication successful (password migrated)"
            else:
                return False, "Invalid password"
        # --- End migration logic ---

        try:
            if not salt_b64:
                return False, "Salt missing for user"
            password_with_salt = password + salt_b64
            if ph.verify(self.users[username]['password'], password_with_salt):
                return True, "Authentication successful"
            else:
                return False, "Invalid password"
        except argon2_exceptions.VerifyMismatchError:
            return False, "Invalid password"
        except Exception as e:
            return False, f"Authentication error: {e}"
    
    def reset_password(self, username, new_password):
        """Basic password reset - just requires existing username"""
        if username not in self.users:
            return False, "Username not found"
        
        # SECURITY VULNERABILITY: No proper verification for password reset!
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
    # --- Begin Merkle-Damgård length extension attack demo ---

    def forge_mac_length_extension(self, orig_message, orig_mac, append_data):
        """
        Demonstrate Merkle-Damgård length extension attack on MAC(k||m) = MD5(k||m).
        Given orig_message and its MAC, forge a valid MAC for orig_message||padding||append_data.
        Returns (forged_message, forged_mac).
        """

        # Helper: MD5 padding for a message of given length (in bytes)
        def md5_padding(msg_len_bytes):
            # MD5 uses 64-byte blocks
            pad = b'\x80'
            pad += b'\x00' * ((56 - (msg_len_bytes + 1) % 64) % 64)
            pad += struct.pack('<Q', msg_len_bytes * 8)
            return pad

        # The attacker doesn't know the key, but can guess its length (e.g., 16 bytes)
        key_len_guess = 16
        total_len = key_len_guess + len(orig_message)
        padding = md5_padding(total_len)
        forged_message = orig_message.encode('utf-8') + padding + append_data.encode('utf-8')

        # Parse original MAC as MD5 state

        # Use a 3rd-party library to set MD5 state (Python's hashlib doesn't support this natively)
        try:
            # Recompute padding using pymd5 for compatibility
            pymd5_pad = pymd5_padding((key_len_guess + len(orig_message)) * 8)
            m = md5(state=bytes.fromhex(orig_mac), count=(key_len_guess + len(orig_message) + len(pymd5_pad)) * 8)
            m.update(append_data)
            forged_mac = m.hexdigest()
            return forged_message, forged_mac
        except ImportError:
            # If pymd5 is not available, just return None
            print("pymd5 required for length extension attack demo (pip install pymd5)")
            return None, None

    # Example usage for demonstration:
    # orig_msg = "CMD=SET_QUOTA&USER=bob&LIMIT=100"
    # orig_mac = self.mac(self.get_shared_key(), orig_msg)
    # forged_msg, forged_mac = self.forge_mac_length_extension(orig_msg, orig_mac, "&LIMIT=1000000")
    # Now forged_msg and forged_mac can be sent to the server, which will accept them as valid!

    # --- End Merkle-Damgård length extension attack demo ---
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
                        username = message.get('username')
                        password = message.get('password')
                        success, msg = self.authenticate(username, password)
                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
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
                        success, msg = self.reset_password(username, new_password)
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
        """Login to the system"""
        print("\n=== Login ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
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
