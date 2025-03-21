from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from . import models, schemas, database
from pydantic import BaseModel

# Create database tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="API Service")

# Dependency to get the database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def read_root():
    """Return 404 for the root route"""
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@app.post("/api/hello")
def get_hello_world(payload: schemas.MessagePayload, db: Session = Depends(get_db)):
    """Get the 'hello world' message from the database - requires a message payload"""
    message = db.query(models.Message).filter(models.Message.content == "hello world").first()
    if not message:
        raise HTTPException(status_code=404, detail="Hello world message not found")
    return {"message": message.content, "received": payload.message}


@app.get("/api/users", response_model=list[schemas.User])
def get_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get a list of users from the database"""
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users


@app.get("/api/items", response_model=list[schemas.Item])
def get_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get a list of items from the database"""
    items = db.query(models.Item).offset(skip).limit(limit).all()
    return items


@app.get("/api/items/{item_id}", response_model=schemas.Item)
def get_item(item_id: int, db: Session = Depends(get_db)):
    """Get a specific item by ID"""
    item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.get("/api/health")
def health_check():
    """Check the health of the API"""
    return {"status": "OK"}