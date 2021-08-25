from fastapi import FastAPI,status, Depends, HTTPException, APIRouter
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from loguru import logger
from oauth2 import get_current_user
from models import User, Login
from secret import SECRET_KEY,ALGORITHM,ACCESS_TOKEN_EXPIRE_MINUTES
from database import col
from secret import pwd_context


router = APIRouter()


@router.post("/create")
def createUser(request:User):
    if request.password != request.confirm_password:
        return {"message" :"Password doesn't match!!"}
    hashedPassword = pwd_context.hash(request.password)
    logger.debug("Password Hashed")
    newUser = {"username":request.username,
                "password":hashedPassword,
                "confirm_password":hashedPassword}
    logger.debug("User created")
    col.insert_one(newUser)
    logger.debug("User Inserted in DB")
    return {"message": "User Created Successfully"}



def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


@router.post("/login")
def login(request:OAuth2PasswordRequestForm = Depends()):
    output = col.find_one({"username":request.username})
    if not output:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No user found!", headers={"header":"header"})
    if not verify_password(request.password, output["password"]):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid Credentials!", headers={"header":"header"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": output["username"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}            



@router.get("/all-users")
def allUsers(get_current_user: User = Depends(get_current_user)):
    output = col.find({})
    logger.debug("Data fetched")
    lst = []
    logger.debug(type(output))
    for data in output:
        logger.debug(data)
        logger.debug("Entered in for loop")
        lst.append(User(**data))
        logger.debug("Data Appended")
    return lst
