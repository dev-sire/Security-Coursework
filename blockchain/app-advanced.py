
import streamlit as st
import json
import hashlib
import time
import os
import uuid
from datetime import datetime
from collections import defaultdict

USERS_FILE = "users.json"
WALLETS_FILE = "wallets.json"
BLOCKCHAIN_FILE = "blockchain.json"
TX_POOL_FILE = "txpool.json"

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0, hash=None):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    difficulty = 2

    def __init__(self):
        self.chain = []
        self.load_chain()

    def load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, "r") as f:
                data = json.load(f)
                self.chain = [Block(**b) for b in data]
        else:
            genesis_block = Block(0, [], str(time.time()), "0")
            self.chain = [genesis_block]
            self.save_chain()

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump([b.__dict__ for b in self.chain], f, indent=4)

    def add_block(self, transactions):
        last_block = self.chain[-1]
        new_block = Block(len(self.chain), transactions, str(time.time()), last_block.hash)
        new_block = self.proof_of_work(new_block)
        self.chain.append(new_block)
        self.save_chain()

    def proof_of_work(self, block):
        while not block.hash.startswith("0" * self.difficulty):
            block.nonce += 1
            block.hash = block.compute_hash()
        return block

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

if "user" not in st.session_state:
    st.session_state.user = None

def register_user(username, password):
    users = load_json(USERS_FILE, {})
    if username in users:
        return False
    users[username] = {"password": hash_password(password), "role": "user"}
    save_json(USERS_FILE, users)

    wallets = load_json(WALLETS_FILE, {})
    wallets[username] = 1000
    save_json(WALLETS_FILE, wallets)
    return True

def authenticate(username, password):
    users = load_json(USERS_FILE, {})
    user = users.get(username)
    if user and user["password"] == hash_password(password):
        return user["role"]
    return None

def add_transaction(sender, recipient, amount):
    tx_pool = load_json(TX_POOL_FILE, [])
    tx_pool.append({
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "timestamp": datetime.utcnow().isoformat()
    })
    save_json(TX_POOL_FILE, tx_pool)

def get_pending_transactions():
    return load_json(TX_POOL_FILE, [])

def clear_pending_transactions():
    save_json(TX_POOL_FILE, [])

def login_page():
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        role = authenticate(username, password)
        if role:
            st.session_state.user = {"username": username, "role": role}
            st.success(f"Welcome, {username}!")
            st.rerun()
        else:
            st.error("Invalid credentials")

def register_page():
    st.title("📝 Register")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    if st.button("Register"):
        if register_user(username, password):
            st.success("User registered successfully")
            st.session_state.user = {"username": username, "role": "user"}
            st.rerun()
        else:
            st.error("Username already exists")

def user_dashboard():
    st.title("💼 Wallet Dashboard")
    wallets = load_json(WALLETS_FILE, {})
    user = st.session_state.user["username"]
    balance = wallets.get(user, 0)
    st.metric("Your Balance", f"${balance}")

    recipient = st.text_input("Send money to")
    amount = st.number_input("Amount", min_value=1, value=10)
    if st.button("Submit Transaction"):
        if recipient == user:
            st.warning("You cannot send money to yourself.")
        elif recipient not in wallets:
            st.error("Recipient does not exist.")
        elif balance < amount:
            st.error("Insufficient funds.")
        else:
            add_transaction(user, recipient, amount)
            wallets[user] -= amount
            wallets[recipient] += amount
            save_json(WALLETS_FILE, wallets)
            st.success(f"Sent ${amount} to {recipient}.")

    txs = [tx for tx in get_pending_transactions() if tx["sender"] == user or tx["recipient"] == user]
    st.subheader("📜 Pending Transactions")
    for tx in txs:
        st.json(tx)

def admin_dashboard(blockchain):
    st.title("🛠️ Admin Dashboard")
    if st.button("Mine Block"):
        pending = get_pending_transactions()
        if pending:
            with st.spinner("Mining..."):
                blockchain.add_block(pending)
                clear_pending_transactions()
                st.success("Block mined and added to the chain.")
        else:
            st.info("No transactions to mine.")

    st.subheader("🔗 Blockchain Viewer")
    for block in blockchain.chain:
        with st.expander(f"Block #{block.index}"):
            st.json(block.__dict__)

    st.subheader("📈 Blockchain Growth")
    st.line_chart([len(json.dumps(b.transactions)) for b in blockchain.chain])

def main():
    blockchain = Blockchain()
    st.sidebar.title("Navigation")
    if not st.session_state.user:
        page = st.sidebar.radio("Choose page", ["Login", "Register"])
        if page == "Login":
            login_page()
        else:
            register_page()
    else:
        user = st.session_state.user
        page = st.sidebar.radio("Dashboard", ["Home", "Logout"])
        if page == "Home":
            if user["role"] == "admin":
                admin_dashboard(blockchain)
            else:
                user_dashboard()
        else:
            st.session_state.user = None
            st.rerun()

if __name__ == "__main__":
    main()
