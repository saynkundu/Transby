from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from modules.db import Base, engine, get_db
from modules.database import Role, User
from modules.hashed_password import check_password, hashed_password
from modules.schemas import Login, Register


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "Frontend"

app = FastAPI(title="TransitOps", description="Vehicle management system")
templates = Jinja2Templates(directory=str(FRONTEND_DIR))


@app.on_event("startup")
def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
  return templates.TemplateResponse(request, "register.html")


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(payload: Register, db: Session = Depends(get_db)):
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    if db.query(User).filter(User.email == str(payload.email).lower()).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    role_name = payload.role.strip()
    role = db.query(Role).filter(Role.role_name == role_name).first()
    if not role:
        role = Role(role_name=role_name)
        db.add(role)
        db.flush()

    user = User(
        full_name=payload.full_name.strip(),
        email=str(payload.email).lower(),
        phone=payload.phone.strip() if payload.phone else None,
        password_hash=hashed_password(payload.password).decode("utf-8"),
        role_id=role.role_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Account created successfully.", "user_id": user.user_id}


@app.post("/api/login")
def login(payload: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user or not check_password(payload.password, user.password_hash.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is inactive.")
    if not user.role or user.role.role_name != payload.role:
        raise HTTPException(status_code=403, detail="The selected role does not match this account.")
    return {"message": "Login successful.", "user": {"id": user.user_id, "name": user.full_name, "role": user.role.role_name}}


# Makes the remaining frontend pages, such as dashboard.html, available after login.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
