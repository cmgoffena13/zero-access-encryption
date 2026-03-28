from pydantic import Base64Bytes, BaseModel


class RegisterInput(BaseModel):
    username: str
    salt: Base64Bytes
    verifier: Base64Bytes
