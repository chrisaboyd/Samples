from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class UserBase(BaseModel):
    username: str
    email: str


class User(UserBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


class MessageBase(BaseModel):
    content: str


class MessagePayload(BaseModel):
    message: str


class Message(MessageBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


class ItemBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: Optional[float] = None


class Item(ItemBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True 