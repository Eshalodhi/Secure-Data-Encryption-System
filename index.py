import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Session state setup
if "authentication_user" not in st.session_state:
    st.session_state.authentication_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Data functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(text.encode()).decode()
    except:
        return None

# Load existing user data
stored_data = load_data()

# UI Navigation
st.title("🔐 Secure Data Encryption System")
menu = ["🏠 Home", "🔑 Login", "📝 Register", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

# Home Page
if choice == "🏠 Home":
    st.subheader("🤗 Welcome to the Secure Data Encryption System")
    st.markdown("""
    ✅ Store your data with a unique passkey  
    🔐 Decrypt with the correct key only  
    🚫 Multiple failed attempts trigger forced reauthorization  
    📦 Everything runs in-memory without external databases  
    """)

# Register Page
elif choice == "📝 Register":
    st.subheader("🆕 Create an Account")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("✅ Register"):
        if username and password:
            if username in stored_data:
                st.error("⚠️ Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 Registration successful!")
        else:
            st.error("⚠️ Please fill in all fields")

# Login Page
elif choice == "🔑 Login":
    st.subheader("🔐 Login to Your Account")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("✅ Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authentication_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🔓 Login successful, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 5 - st.session_state.failed_attempts
            st.error(f"⚠️ Incorrect password. {remaining} attempt(s) remaining.")

            if st.session_state.failed_attempts >= 5:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Account locked due to too many failed attempts. Try again later.")
                st.stop()

# Store Data Page
elif choice == "📥 Store Data":
    if not st.session_state.authentication_user:
        st.error("⚠️ You must be logged in to store data.")
    else:
        st.subheader("📥 Store Your Data")
        data = st.text_area("📝 Enter data to store")
        passkey = st.text_input("🔑 Enter passkey", type="password")

        if st.button("🔐 Encrypt and Save"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authentication_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("🎉 Data stored successfully!")
            else:
                st.error("⚠️ Please fill in all fields.")

# Retrieve Data Page
elif choice == "📤 Retrieve Data":
    if not st.session_state.authentication_user:
        st.warning("⚠️ You must be logged in to retrieve data.")
    else:
        st.subheader("📤 Retrieve Your Data")
        user_data = stored_data.get(st.session_state.authentication_user, {})

        if not user_data or not user_data.get("data"):
            st.info("📭 No data found.")
        else:
            st.write("🗂️ Encrypted Data Entries:")
            for i, entry in enumerate(user_data["data"], 1):
                st.code(entry, language="text")

            encrypted_input = st.text_input("📥 Paste encrypted data")
            passkey = st.text_input("🔑 Enter passkey to decrypt", type="password")

            if st.button("🔓 Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted data: {result}")
                else:
                    st.error("❌ Incorrect passkey or invalid encrypted data.")
