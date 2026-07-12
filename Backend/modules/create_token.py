from jwt import encode,decode
import os
from dotenv import load_dotenv
import datetime
load_dotenv()

def create_token(data:dict)->bytes:
    user_data=data.copy()
    user_data["iat"]=datetime.datetime.utcnow()
    user_data["exp"]=datetime.datetime.utcnow()+datetime.timedelta(minutes=20)
    token=encode(user_data,os.getenv("SECRET_KEY"),os.getenv("ALGORITHM"))
    return token

def decode_token(token:bytes)->dict:
    try:
        data=decode(token,os.getenv("SECRET_KEY"),algorithms=[os.getenv("ALGORITHM")])
    except Exception as e:
        return None
    else:
        return data