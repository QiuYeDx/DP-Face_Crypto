import base64


# Base64.encode(文本) -> base64文本
def encode(text: str) -> str:
    st = text.encode()
    ans = str(base64.b64encode(st))
    ans = ans[2:len(ans)-1]
    return ans


# Base64.decode(base64文本) -> 文本
def decode(text: str) -> str:
    ans = str(base64.b64decode(text))
    ans = ans[2:len(ans)-1]
    return ans