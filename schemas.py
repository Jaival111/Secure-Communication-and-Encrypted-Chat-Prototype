from pydantic import BaseModel

class RegisterResponse(BaseModel):
    username: str
    public_key_pem: str

class SendRequest(BaseModel):
    sender: str
    recipient: str
    plaintext: str

class EncryptedPayload(BaseModel):
    encrypted_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    tag_b64: str
    hmac_b64: str
    signature_b64: str

    
class ReceiveRequest(BaseModel):
    recipient: str
    sender: str
    payload: EncryptedPayload

class ReceiveResponse(BaseModel):
    verified_hmac: bool
    verified_signature: bool
    decrypted_plaintext: str