from base64 import b64encode

from pydantic import Base64Bytes, BaseModel, field_serializer


class SRPChallengeInput(BaseModel):
    username: str
    A: Base64Bytes


class SRPChallengeOutput(BaseModel):
    session_id: str
    s: bytes
    B: bytes

    @field_serializer("s", "B", when_used="json")
    def _bytes_as_b64(self, v: bytes) -> str:
        return b64encode(v).decode("ascii")


class SRPProofInput(BaseModel):
    session_id: str
    username: str
    M: Base64Bytes


class SRPProofOutput(BaseModel):
    HAMK: bytes
    user_id: int
    salt: bytes
    access_token: str

    @field_serializer("HAMK", "salt", when_used="json")
    def _bytes_as_b64(self, v: bytes) -> str:
        return b64encode(v).decode("ascii")
