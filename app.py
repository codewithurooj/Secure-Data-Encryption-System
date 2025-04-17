import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# User Data
DATA_FILE = "data.json"
SALT = b"salt_value"  # Corrected 'slat_value' to 'salt_value'
LOCKOUT_DURATION = 60  # Lockout duration in seconds

# Initialize session state variables
if "username" not in st.session_state:
    st.session_state.username = None
if "logged_attempt" not in st.session_state:
    st.session_state.logged_attempt = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

stored_data = load_data()

# Navbar
st.title("🛡️ Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navbar", menu)

if choice == "Home":
    st.subheader("🔓 Welcome to Secure Data Encryption System")
    st.markdown("Don't have an account? Register now.")
    st.markdown("Already have an account? Login now.")

elif choice == "Register":
    st.subheader("Register New User 📝")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []  # Initialize 'data' key as an empty list
                }
                save_data(stored_data)
                st.success("✅ Registration successful!")
        else:
            st.warning("Please enter a username and password.")

elif choice == "Login":
    st.subheader("Login 🔑")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Locked out for {remaining} seconds. Please try again later.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.username = username
            st.session_state.logged_attempt = 0
            st.success("✅ Login successful!")
        else:
            st.session_state.logged_attempt += 1
            remaining_attempts = 3 - st.session_state.logged_attempt
            st.error(f"🚫 Invalid username or password. {remaining_attempts} attempts left.")

            if st.session_state.logged_attempt >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error(f"🚫 Locked out for {LOCKOUT_DURATION} seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.username:
        st.warning("Please log in to store data.")
    else:
        st.subheader("Store Encrypted Data 📝")
        data = st.text_area("Enter data to be encrypted")
        passkey = st.text_input("Enter encryption key (passphrase)", type="password")

        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.username]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
            else:
                st.warning("Please enter data and an encryption key.")

elif choice == "Retrieve Data":
    if not st.session_state.username:
        st.warning("Please log in to retrieve data.")
    else:
        st.subheader("Retrieve Data 📝")
        user_data = stored_data.get(st.session_state.username, {}).get("data", [])

        if not user_data:
            st.info("No data found for this user.")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

        encrypted_input = st.text_area("Enter encrypted data to be decrypted")
        passkey = st.text_input("Enter decryption key (passphrase)", type="password")

        if st.button("Decrypt"):
            result = decrypt_text(encrypted_input, passkey)

            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                st.error("🚫 Invalid decryption key or encrypted data.")
