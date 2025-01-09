import os
import json
import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
from flask import Flask, request, jsonify, render_template

# Flask application setup
app = Flask(__name__)

# Path to store encrypted private keys
KEY_STORAGE = "keys/"
os.makedirs(KEY_STORAGE, exist_ok=True)

# Encryption setup
SECRET_KEY = b"my_super_secret_key!"
IV = os.urandom(16)

# Blockchain API endpoint (adjust for Future (FTR) blockchain)
API_ENDPOINT = "https://api.future-blockchain.com"

# Utility: Encrypt a private key
def encrypt_private_key(private_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CFB(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    return IV + encryptor.update(private_key) + encryptor.finalize()

# Utility: Decrypt a private key
def decrypt_private_key(encrypted_key: bytes) -> bytes:
    iv = encrypted_key[:16]
    encrypted_content = encrypted_key[16:]
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_content) + decryptor.finalize()

# Generate new wallet
def generate_wallet():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    encrypted_private_key = encrypt_private_key(private_key_bytes)
    wallet_id = os.urandom(8).hex()
    with open(f"{KEY_STORAGE}/{wallet_id}.key", "wb") as key_file:
        key_file.write(encrypted_private_key)

    return wallet_id, public_key_bytes.decode("utf-8")

# Check balance
def check_balance(public_key: str):
    response = requests.get(f"{API_ENDPOINT}/wallet/balance", params={"public_key": public_key})
    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch balance."}

# Send transaction
def send_transaction(sender_private_key: bytes, recipient_address: str, amount: float):
    transaction = {
        "sender": sender_private_key,
        "recipient": recipient_address,
        "amount": amount
    }
    response = requests.post(f"{API_ENDPOINT}/transaction/send", json=transaction)
    return response.json()

# QR Code Generation and Scanning
def create_qr_code(data: dict, output_file: str):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(json.dumps(data))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_file)

# Routes
@app.route('/create_wallet', methods=['GET'])
def create_wallet_route():
    wallet_id, public_key = generate_wallet()
    return jsonify({"wallet_id": wallet_id, "public_key": public_key})

@app.route('/balance', methods=['GET'])
def balance_route():
    public_key = request.args.get("public_key")
    balance = check_balance(public_key)
    return jsonify(balance)

@app.route('/send_transaction', methods=['POST'])
def send_transaction_route():
    data = request.json
    wallet_id = data.get("wallet_id")
    recipient = data.get("recipient")
    amount = data.get("amount")

    try:
        with open(f"{KEY_STORAGE}/{wallet_id}.key", "rb") as key_file:
            encrypted_key = key_file.read()
        private_key = decrypt_private_key(encrypted_key)
        response = send_transaction(private_key.decode("utf-8"), recipient, amount)
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/generate_qr', methods=['POST'])
def generate_qr_route():
    data = request.json
    output_file = data.get("output_file", "qr_code.png")
    create_qr_code(data, output_file)
    return jsonify({"message": "QR code generated.", "file": output_file})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
