from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class MessageQuery(BaseModel):
    query: str


class MessageResponse(BaseModel):
    content: str
    similarity_score: Optional[float] = None
    rag_processed: bool = True


class UserBase(BaseModel):
    username: str
    email: str


class User(UserBase):
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


class RAGResponse(BaseModel):
    result: Any
    source_documents: Optional[List[Dict[str, Any]]] = None
    rag_processed: bool = True
