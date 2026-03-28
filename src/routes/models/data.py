from base64 import b64encode

from pydantic import Base64Bytes, BaseModel, field_serializer


class DataUploadInput(BaseModel):
    user_id: int
    blob: Base64Bytes


class DataGetOutput(BaseModel):
    blob: bytes

    @field_serializer("blob", when_used="json")
    def _blob_as_b64(self, v: bytes) -> str:
        return b64encode(v).decode("ascii")
