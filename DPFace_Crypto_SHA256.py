import hashlib


# SHA256_hash(str文本) -> str散列
def SHA256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

