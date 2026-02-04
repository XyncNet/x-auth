from jwt import ExpiredSignatureError


class ExpiredSignature(Exception):
    def __init__(self, uid: int, encoded_token: str, secret: str, _e: ExpiredSignatureError): ...
