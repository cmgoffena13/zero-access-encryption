from fastapi import APIRouter, HTTPException, Response, status
from sqlmodel import select

from src.database.models import UserData
from src.database.session import SessionDep
from src.routes.models.data import DataGetOutput, DataUploadInput

data_router = APIRouter()


@data_router.post("/data/upload")
async def data_upload(input: DataUploadInput, session: SessionDep, response: Response):
    result = await session.exec(
        select(UserData).where(UserData.user_id == input.user_id)
    )
    existing = result.first()
    try:
        if existing is None:
            session.add(UserData(user_id=input.user_id, blob=input.blob))
        else:
            existing.blob = input.blob
            session.add(existing)
        await session.commit()
    except Exception as e:
        await session.rollback()
        raise e
    response.status_code = status.HTTP_201_CREATED


@data_router.get("/data/{user_id}")
async def get_data(user_id: int, session: SessionDep, response: Response):
    result = await session.exec(select(UserData).where(UserData.user_id == user_id))
    user_data = result.first()
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User data not found"
        )
    response.status_code = status.HTTP_200_OK
    return DataGetOutput(blob=user_data.blob)
