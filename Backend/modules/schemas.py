from pydantic import BaseModel,EmailStr

class Login(BaseModel):
    email:EmailStr
    password: str
    role : str

class Register(BaseModel):
    name: str 
    email : EmailStr
    password: str 
    confirm_password: str