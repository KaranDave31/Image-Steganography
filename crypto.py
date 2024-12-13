from base64 import b64encode, b64decode
from typing import Union
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_key_pair(size: int = 3072):
    key_pair = RSA.generate(size)
    private_key = key_pair.export_key()
    public_key = key_pair.public_key().export_key()
    return public_key, private_key


def get_header(data: bytes, sep: Union[bytes, str] = b';') -> bytes:
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    header, *_ = [b64decode(i) for i in data.split(sep)]
    return header


def encrypt_rsa(data: Union[bytes, str], public_key_path: str, header: Union[bytes, str] = b'', sep: Union[bytes, str] = b';') -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(header, str):
        header = header.encode('utf-8')
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    with open(public_key_path, 'rb') as file:
        public_key = file.read()
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted = cipher.encrypt(data)
    return sep.join(b64encode(i) for i in [header, encrypted])


def decrypt_rsa(data: bytes, private_key_path: str, sep: Union[bytes, str] = b';') -> tuple[bytes, bytes]:
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    header, encrypted = [b64decode(i) for i in data.split(sep)]
    with open(private_key_path, 'rb') as file:
        private_key = file.read()
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted = cipher.decrypt(encrypted)
    return header, decrypted


def encrypt_aes(data: Union[bytes, str], public_key_path: str, header: Union[bytes, str] = b'', sep: Union[bytes, str] = b';', key_size: int = 16) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(header, str):
        header = header.encode('utf-8')
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    aes_key = get_random_bytes(key_size)
    aes_key_encrypted = encrypt_rsa(aes_key, public_key_path)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return sep.join(b64encode(i) for i in [header, aes_key_encrypted, cipher.nonce, tag, encrypted])


def decrypt_aes(data: bytes, private_key_path: str, sep: Union[bytes, str] = b';') -> tuple[bytes, bytes]:
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    header, aes_key_encrypted, nonce, tag, encrypted = [b64decode(i) for i in data.split(sep)]
    _, aes_key = decrypt_rsa(aes_key_encrypted, private_key_path)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce)
    decrypted = cipher.decrypt_and_verify(encrypted, tag)
    return header, decrypted


def encrypt_chacha20(data: Union[bytes, str], public_key_path: str, header: Union[bytes, str] = b'', sep: Union[bytes, str] = b';') -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(header, str):
        header = header.encode('utf-8')
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    
    # Generate ChaCha20 key (32 bytes) and nonce (12 bytes)
    chacha_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    
    # Encrypt the ChaCha20 key with RSA
    chacha_key_encrypted = encrypt_rsa(chacha_key, public_key_path)
    
    # Create cipher and encrypt data
    cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
    encrypted = cipher.encrypt(data)
    
    return sep.join(b64encode(i) for i in [header, chacha_key_encrypted, nonce, encrypted])


def decrypt_chacha20(data: bytes, private_key_path: str, sep: Union[bytes, str] = b';') -> tuple[bytes, bytes]:
    if isinstance(sep, str):
        sep = sep.encode('utf-8')
    
    header, chacha_key_encrypted, nonce, encrypted = [b64decode(i) for i in data.split(sep)]
    
    # Decrypt the ChaCha20 key using RSA
    _, chacha_key = decrypt_rsa(chacha_key_encrypted, private_key_path)
    
    # Create cipher and decrypt data
    cipher = ChaCha20.new(key=chacha_key, nonce=nonce)
    decrypted = cipher.decrypt(encrypted)
    
    return header, decrypted