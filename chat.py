from fastapi import APIRouter, HTTPException
from typing import Dict
import base64
import os

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric

from schemas import RegisterResponse, SendRequest, EncryptedPayload, ReceiveRequest, ReceiveResponse

router = APIRouter()

users: Dict[str, Dict] = {}

@router.post("/register", response_model=RegisterResponse)
def register(username: str):
    if username in users:
        raise HTTPException(status_code=400, detail="User already registered")

    # Generate RSA keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    # Random HMAC key
    hmac_key = os.urandom(32)  # 256-bit HMAC key

    # Serialize public key to send to clients
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Serialize private key for server storage (PEM bytes)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    users[username] = {
        "private_key_pem": private_pem,
        "public_key_pem": public_pem.encode(),
        "hmac_key": hmac_key,
    }

    return RegisterResponse(username=username, public_key_pem=public_pem)

@router.get("/users")
def list_users():
    return {"users": list(users.keys())}

def base64u(b: bytes) -> str:
    return base64.b64encode(b).decode()

def base64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

@router.post("/send", response_model=EncryptedPayload)
def send_message(req: SendRequest):
    sender = req.sender
    recipient = req.recipient
    plaintext = req.plaintext.encode()

    if sender not in users or recipient not in users:
        raise HTTPException(status_code=404, detail="sender or recipient not registered")

    # Load recipient public key
    recipient_pub = serialization.load_pem_public_key(users[recipient]["public_key_pem"])

    # Load sender private key for signing
    sender_priv = serialization.load_pem_private_key(users[sender]["private_key_pem"], password=None)

    # 1) Generate random AES-256-GCM key
    aes_key = os.urandom(32)
    nonce = os.urandom(12)  # 96-bit nonce for GCM

    # 2) AES-GCM encrypt the plaintext
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # 3) Encrypt AES key with recipient RSA public key (RSA-OAEP)
    encrypted_key = recipient_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # 4) Compute HMAC over ciphertext using sender's HMAC key
    h = hmac.HMAC(users[sender]["hmac_key"], hashes.SHA256())
    h.update(ciphertext)
    hmac_tag = h.finalize()

    # 5) Sign the ciphertext with sender's RSA private key (PSS)
    signature = sender_priv.sign(
        ciphertext,
        asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric.padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    payload = EncryptedPayload(
        encrypted_key_b64=base64u(encrypted_key),
        nonce_b64=base64u(nonce),
        ciphertext_b64=base64u(ciphertext),
        tag_b64=base64u(tag),
        hmac_b64=base64u(hmac_tag),
        signature_b64=base64u(signature),
    )
    return payload

@router.post("/receive", response_model=ReceiveResponse)
def receive_message(req: ReceiveRequest):
    recipient = req.recipient
    sender = req.sender
    payload = req.payload

    if sender not in users or recipient not in users:
        raise HTTPException(status_code=404, detail="sender or recipient not registered")

    # Load recipient private key
    recipient_priv = serialization.load_pem_private_key(users[recipient]["private_key_pem"], password=None)

    # Load sender public key for signature verification
    sender_pub = serialization.load_pem_public_key(users[sender]["public_key_pem"])

    # Decode base64 fields
    encrypted_key = base64d(payload.encrypted_key_b64)
    nonce = base64d(payload.nonce_b64)
    ciphertext = base64d(payload.ciphertext_b64)
    tag = base64d(payload.tag_b64)
    hmac_tag = base64d(payload.hmac_b64)
    signature = base64d(payload.signature_b64)

    # 1) Decrypt AES key with recipient private RSA key
    try:
        aes_key = recipient_priv.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decrypt AES key: {e}")

    # 2) Verify HMAC
    verified_hmac = False
    try:
        h = hmac.HMAC(users[sender]["hmac_key"], hashes.SHA256())
        h.update(ciphertext)
        h.verify(hmac_tag)
        verified_hmac = True
    except Exception:
        verified_hmac = False

    # 3) Verify signature (RSA PSS)
    verified_sig = False
    try:
        sender_pub.verify(
            signature,
            ciphertext,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified_sig = True
    except Exception:
        verified_sig = False

    # 4) Decrypt AES-GCM ciphertext
    try:
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext_str = plaintext.decode()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decrypt ciphertext: {e}")

    return ReceiveResponse(
        verified_hmac=verified_hmac,
        verified_signature=verified_sig,
        decrypted_plaintext=plaintext_str
    )
