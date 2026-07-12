from bcrypt import checkpw,hashpw,gensalt

def hashed_password(password:str)->bytes:
    return hashpw(password.encode("UTF-8"),gensalt(12))

def check_password(password:str,hashed_pw:bytes):
    return checkpw(password.encode("UTF-8"),hashed_pw)