import streamlit as st
import hashlib
import json
import os
import time
from typing import List

# -----------------------------
# File Paths
# -----------------------------
USERS_FILE = "users.json"
WALLETS_FILE = "wallets.json"

# -----------------------------
# Blockchain Classes
# -----------------------------
class Block:
    def __init__(self, index, previous_hash, transactions):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.transactions}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != '0' * difficulty:
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.difficulty = 2
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", [])
        self.chain.append(genesis_block)

    def add_block(self, transactions):
        prev_block = self.chain[-1]
        new_block = Block(len(self.chain), prev_block.hash, transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

# -----------------------------
# Authentication / File Utils
# -----------------------------
def load_json(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r') as f:
        return json.load(f)

def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, role):
    users = load_json(USERS_FILE)
    if username in users:
        return False, "Username already exists."
    users[username] = {"password": hash_password(password), "role": role}
    save_json(USERS_FILE, users)

    wallets = load_json(WALLETS_FILE)
    wallets[username] = {"balance": 1000}  # Default starting balance
    save_json(WALLETS_FILE, wallets)
    return True, "User registered successfully."

def login_user(username, password):
    users = load_json(USERS_FILE)
    if username not in users:
        return False, "User does not exist."
    if users[username]["password"] != hash_password(password):
        return False, "Incorrect password."
    return True, users[username]["role"]

def get_balance(username):
    wallets = load_json(WALLETS_FILE)
    return wallets.get(username, {}).get("balance", 0)

def transfer_funds(sender, receiver, amount):
    wallets = load_json(WALLETS_FILE)
    if sender not in wallets or receiver not in wallets:
        return False, "Invalid user(s)."
    if wallets[sender]["balance"] < amount:
        return False, "Insufficient balance."
    wallets[sender]["balance"] -= amount
    wallets[receiver]["balance"] += amount
    save_json(WALLETS_FILE, wallets)
    return True, f"Transferred {amount} to {receiver}."

# -----------------------------
# Streamlit App
# -----------------------------
st.set_page_config(page_title="Blockchain Bank", layout="centered")
st.title("\U0001F4B0 Digital Blockchain Bank")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""

blockchain = Blockchain()

# -----------------------------
# Auth Section
# -----------------------------
def show_login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        success, result = login_user(username, password)
        if success:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = result
            st.success("Login successful!")
        else:
            st.error(result)

def show_register():
    st.subheader("Register")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    role = st.selectbox("Role", ["user", "admin"])
    if st.button("Register"):
        success, message = register_user(username, password, role)
        if success:
            st.success(message)
        else:
            st.error(message)

# -----------------------------
# Dashboard
# -----------------------------
def user_dashboard():
    st.subheader(f"Welcome, {st.session_state.username}!")
    balance = get_balance(st.session_state.username)
    st.info(f"Current Balance: ${balance}")

    receiver = st.text_input("Receiver Username")
    amount = st.number_input("Amount", min_value=1)
    if st.button("Transfer"):
        success, msg = transfer_funds(st.session_state.username, receiver, amount)
        if success:
            st.success(msg)
        else:
            st.error(msg)

def admin_dashboard():
    st.subheader("Admin Panel")
    if st.button("Mine New Block"):
        blockchain.add_block(["Admin manually mined a block"])
        st.success("Block mined successfully!")
    st.subheader("Blockchain")
    for block in blockchain.chain:
        st.write(f"Index: {block.index}")
        st.write(f"Hash: {block.hash}")
        st.write(f"Transactions: {block.transactions}")
        st.write("---")

# -----------------------------
# Main Logic
# -----------------------------
if not st.session_state.logged_in:
    choice = st.radio("Choose Option", ["Login", "Register"])
    if choice == "Login":
        show_login()
    else:
        show_register()
else:
    st.sidebar.success(f"Logged in as: {st.session_state.username} ({st.session_state.role})")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = ""
        st.experimental_rerun()

    if st.session_state.role == "admin":
        admin_dashboard()
    else:
        user_dashboard()
