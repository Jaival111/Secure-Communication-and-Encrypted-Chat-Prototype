import streamlit as st
import requests
import json

BACKEND_URL = "http://127.0.0.1:8000"

# ---------------------------
# Streamlit Page Settings
# ---------------------------
st.set_page_config(page_title="Secure Chat Prototype", layout="wide")

st.title("Secure Communication & Encrypted Chat Prototype")
st.caption("Uses RSA Keys + AES Encryption + HMAC + Digital Signatures")

st.markdown("""
This demo shows a secure communication workflow:

**1. Register a user → automatically generates RSA keypair**  
**2. Send a message → AES encryption + HMAC integrity + RSA signature**  
**3. Receive message → AES decrypt + verify HMAC + verify signature**

Use this tool to demonstrate cryptographic concepts step-by-step.
""")

# -----------------------------------------------------
# SECTION 1 — USER REGISTRATION
# -----------------------------------------------------
st.header("Register Users")

col1, col2 = st.columns([1, 1])

with col1:
    username = st.text_input(
        "Enter username to register",
        placeholder="e.g., Alice",
        help="This will auto-generate RSA public/private keys for the user."
    )

    if st.button("Register User"):
        if not username.strip():
            st.warning("Please enter a valid username.")
        else:
            try:
                r = requests.post(f"{BACKEND_URL}/register", params={"username": username.strip()})
                r.raise_for_status()
                data = r.json()

                st.success(f"User `{data['username']}` registered successfully!")
                st.subheader("Generated RSA Public Key (PEM)")
                st.code(data["public_key_pem"])

            except Exception as e:
                st.error(f"Registration failed: {e}")

with col2:
    if st.button("Show Registered Users"):
        try:
            r = requests.get(f"{BACKEND_URL}/users")
            r.raise_for_status()
            st.success("Registered Users:")
            st.write(r.json().get("users", []))
        except Exception as e:
            st.error(f"Error fetching users: {e}")

# -----------------------------------------------------
# SECTION 2 — COMPOSE MESSAGE
# -----------------------------------------------------
st.markdown("---")
st.header("Compose & Send Secure Message")

# Fetch users for dropdowns
try:
    r = requests.get(f"{BACKEND_URL}/users")
    users = r.json().get("users", [])
except:
    users = []

col1, col2 = st.columns([1, 1])

with col1:
    sender = st.selectbox(
        "Select Sender",
        options=[""] + users,
        help="This user's private key will be used to SIGN the message."
    )
    recipient = st.selectbox(
        "Select Recipient",
        options=[""] + users,
        help="This user's public key will be used to ENCRYPT the AES key."
    )

    plaintext = st.text_area(
        "Enter message to encrypt:",
        placeholder="Type a confidential message here...",
        help="This plaintext will be encrypted using AES-GCM."
    )

with col2:
    if st.button("Send Secure Message"):
        if not sender or not recipient:
            st.warning("Select both sender and recipient.")
        elif sender == recipient:
            st.warning("Sender and recipient must be different.")
        elif not plaintext.strip():
            st.warning("Enter a message to encrypt.")
        else:
            try:
                payload = {"sender": sender, "recipient": recipient, "plaintext": plaintext}
                r = requests.post(f"{BACKEND_URL}/send", json=payload)
                r.raise_for_status()

                data = r.json()
                st.session_state["last_payload"] = data

                st.success("Message successfully encrypted!")
                st.subheader("🔐 Generated Payload (encrypted fields in Base64):")
                st.json(data)

            except Exception as e:
                st.error(f"Failed to send message: {e}")

# -----------------------------------------------------
# SECTION 3 — RECEIVE AND VERIFY
# -----------------------------------------------------
st.markdown("---")
st.header("Receive Message — Decrypt & Verify")

col_left, col_right = st.columns([1.2, 1.8])

with col_left:
    st.subheader("Last Generated Payload")
    last_payload = st.session_state.get("last_payload")

    if last_payload:
        st.json(last_payload)
    else:
        st.info("Send a message first to generate encrypted payload.")

    st.markdown("Paste a payload below to simulate receiving from a network.")

with col_right:
    recipient_recv = st.selectbox(
        "Receiving User",
        options=[""] + users,
        help="This user will decrypt the message using their PRIVATE key."
    )
    sender_recv = st.selectbox(
        "Original Sender",
        options=[""] + users,
        help="Used to verify the RSA signature."
    )

    pasted_payload = st.text_area(
        "Paste payload JSON here",
        placeholder="Paste encrypted payload JSON here...",
        key="payload_box"
    )

    # if st.button("Use Last Payload"):
    #     if "last_payload" in st.session_state:
    #         st.session_state["payload_box"] = json.dumps(st.session_state["last_payload"])
    #         st.experimental_rerun()
    #     else:
    #         st.warning("No payload available.")

    if st.button("Receive & Verify"):
        if not recipient_recv or not sender_recv:
            st.warning("Select both receiving user and sender.")
        else:
            try:
                payload_json = json.loads(st.session_state["payload_box"])

                req = {
                    "recipient": recipient_recv,
                    "sender": sender_recv,
                    "payload": payload_json
                }

                r = requests.post(f"{BACKEND_URL}/receive", json=req)
                r.raise_for_status()
                data = r.json()

                st.success("Message successfully decrypted & verified!")

                st.subheader("🔍 Verification Results")
                st.write(f"**HMAC Integrity Valid:** {data['verified_hmac']}")
                st.write(f"**Digital Signature Valid:** {data['verified_signature']}")

                st.subheader("📩 Decrypted Plaintext")
                st.code(data["decrypted_plaintext"])

            except Exception as e:
                st.error(f"Receive failed: {e}")

# -----------------------------------------------------
# FOOTER
# -----------------------------------------------------
st.markdown("---")
