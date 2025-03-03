from jwt import ExpiredSignatureError


class ExpiredSignature(Exception):
    def __init__(self, _uid: int, _encoded_token: str, _e: ExpiredSignatureError): ...
