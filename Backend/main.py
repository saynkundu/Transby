from modules.create_token import create_token,decode_token
from modules.hashed_password import check_password,hashed_password
from  modules.schemas import Login,Register
from fastapi import FastAPI,Request,Depends,Response
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

app=FastAPI(
    title="TransitOps",
    description="vehicale management system"
)

templates=Jinja2Templates(directory="frontend")

@app.get("/",response_class=HTMLResponse)
def home(request:Request):
    return templates.TemplateResponse({"request":request},"index.html")

