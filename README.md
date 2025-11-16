
# Secure Communication and Encrypted Chat Prototype

**Authors:** Jaival (U23AI035), Vikram (U23AI034), Kartik (U23AI025)

**Date:** 16 November 2025

A small, educational prototype demonstrating a hybrid encryption workflow for secure messaging. It combines RSA, AES-GCM, HMAC, and RSA signatures to provide confidentiality, integrity, and authenticity in a simple message exchange demo.

**Quick highlights:**
- Register a user → RSA key pair and HMAC key are generated.
- Send a message → AES-GCM for message, RSA-OAEP to protect the AES key, HMAC for integrity, and RSA-PSS signature for authentication.
- Receive a message → RSA decrypt AES key, verify HMAC, verify signature, then AES-GCM decrypt.

**Table of Contents**
- [Introduction](#introduction)
- [Goals & Scope](#goals--scope)
- [Environment & Dependencies](#environment--dependencies)
- [Design & Architecture](#design--architecture)
- [Implementation Details](#implementation-details)
- [Key Algorithms & Methods](#key-algorithms--methods)
- [Threats & Limitations](#threats--limitations)
- [Performance & Complexity](#performance--complexity)
- [How to Run](#how-to-run)
- [Demo Workflow](#demo-workflow)

---

## Introduction

This project is an educational prototype that demonstrates core cryptographic building blocks used in secure messaging: confidentiality, integrity, and authentication. It uses:

- RSA (2048-bit) for asymmetric operations (encrypting the per-message AES key and signing).
- AES-GCM for symmetric encryption (message confidentiality + authentication tag).
- HMAC-SHA256 for an additional integrity check.
- FastAPI for the backend endpoints.
- Streamlit for a minimal UI.

## Goals & Scope

Goals:

- Provide a simple flow to register users (generates RSA keypairs and HMAC keys).
- Send messages using hybrid encryption (AES-GCM + RSA-OAEP) with HMAC and RSA-PSS signatures.
- Receive messages: decrypt, verify integrity and authenticity, and return plaintext and verification flags.
- Provide a minimal UI to interact with the backend.

Scope (what this prototype does NOT do):

- No group chats or persistent message storage.
- No forward secrecy (no DH/ratchet protocols).
- No key revocation or a full PKI/trust model.

## Environment & Dependencies

- Language: Python 3.10+
- Key packages: `cryptography`, `fastapi`, `uvicorn`, `streamlit`, `pydantic`

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Design & Architecture

The backend exposes simple REST endpoints and maintains an in-memory user store containing each user's RSA key pair and HMAC key.

Endpoints (examples):

- `POST /register` — create a user and generate keys.
- `POST /send` — build an encrypted payload for a recipient.
- `POST /receive` — attempt to decrypt and verify a payload.

Frontend (`ui.py`) provides a Streamlit-based interface to register users, compose messages, and paste or load received payloads to verify/decrypt.

Data flow summary:

1. On send: generate ephemeral AES-256 key + nonce, encrypt plaintext with AES-GCM, encrypt AES key with recipient RSA-OAEP, compute HMAC over ciphertext (sender's HMAC key), sign ciphertext with sender's RSA-PSS, pack fields as Base64 for JSON.
2. On receive: Base64-decode fields, decrypt AES key with recipient RSA private key, verify HMAC (sender's HMAC key), verify RSA signature (sender's public key), AES-GCM decrypt to recover plaintext.

## Implementation Details

User store (in-memory) contains per-user:

- `private_key_pem` — PEM-encoded RSA private key
- `public_key_pem` — PEM-encoded RSA public key
- `hmac_key` — 32-byte HMAC key (hex/base64 stored as appropriate)

Message process highlights:

- AES-GCM: 32-byte key, 12-byte nonce (recommended).
- RSA: OAEP with SHA-256 for encryption; PSS with SHA-256 for signatures.
- HMAC: SHA-256 over the ciphertext.
- All binary fields (encrypted AES key, nonce, ciphertext, tag, HMAC, signature) are Base64-encoded when transported in JSON.

Error handling policy:

- AES key decryption failures produce an HTTP 400 with details.
- AES-GCM decryption failures produce an HTTP 400 with details.
- Signature/HMAC verification failures are reported as boolean flags in the `/receive` response when decryption succeeded.

## Key Algorithms & Methods

- AES-GCM: efficient symmetric encryption with authentication tag.
- RSA-OAEP: secure asymmetric encryption padding for protecting the AES key.
- RSA-PSS: probabilistic signature scheme for strong authenticity guarantees.
- HMAC-SHA256: additional integrity protection over the ciphertext.

## Threats & Limitations

Threats addressed:

- Eavesdropping — message confidentiality provided by AES-GCM.
- Tampering — detected via HMAC, GCM tag, and signatures.
- Impersonation — mitigated by RSA signatures.

Limitations / Not addressed:

- No forward secrecy: long-term private key compromise exposes prior messages.
- No persistent storage or key revocation.
- No PKI/trust verification for public keys.
- Prototype uses in-memory storage and is not production ready.

## Performance & Complexity

- RSA operations (encrypt/decrypt/sign/verify) are the most expensive; AES-GCM and HMAC are fast.
- Suitable for small-scale demos; production systems require profiling, key management, and scaling strategies.

## How to Run

1. Create and activate a virtual environment (Windows PowerShell example):

```powershell
python -m venv env; .\env\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the backend (FastAPI):

```powershell
uvicorn main:app --reload
```

4. Run the UI (Streamlit) in a separate terminal:

```powershell
streamlit run ui.py
```

Default addresses:

- FastAPI: `http://localhost:8000`
- Streamlit UI: `http://localhost:8501`

## Demo Workflow

1. Register users (e.g., Alice, Bob) — each gets an RSA keypair and HMAC key.
2. Compose a message in the UI and send it — the app builds a hybrid-encrypted payload.
3. Paste or load the payload into the recipient's UI view — the app verifies and decrypts the message, showing verification flags and plaintext.

---

Files of interest: `main.py`, `chat.py`, `ui.py`, `schemas.py`.

---


