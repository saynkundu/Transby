import hashlib
import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.utils import parseaddr
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from modules.db import Base, engine, get_db
from modules.database import PasswordResetRequest, Role, User, Vehicle
from modules.hashed_password import check_password, hashed_password
from modules.schemas import (
    ForgotPassword,
    Login,
    Register,
    ResetPassword,
    VerifyPasswordOtp,
    VehicleCreate,
)



BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "Frontend"
load_dotenv(BASE_DIR / ".env")

OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5

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


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _send_otp_email(recipient: str, otp: str) -> None:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", smtp_username or "")
    sender_email = parseaddr(sender)[1]

    if not all((smtp_host, smtp_username, smtp_password, sender_email)):
        raise RuntimeError("Email delivery is not configured.")

    message = MIMEText(
        f"Your TransitOps password-reset OTP is: {otp}\n\n"
        f"It expires in {OTP_EXPIRY_MINUTES} minutes. Do not share this code.",
        "plain",
        "utf-8",
    )
    message["Subject"] = "Your TransitOps password-reset OTP"
    message["From"] = sender
    message["To"] = recipient

    if os.getenv("SMTP_USE_SSL", "false").lower() == "true":
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as server:
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, [recipient], message.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                server.starttls()
                server.ehlo()
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, [recipient], message.as_string())


@app.post("/api/password-reset/request")
def request_password_reset(payload: ForgotPassword, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    user = db.query(User).filter(User.email == email, User.is_active.is_(True)).first()

    # Keep the response generic so this endpoint does not disclose registered emails.
    if not user:
        return {"message": "If that email is registered, an OTP has been sent."}

    otp = f"{secrets.randbelow(1_000_000):06d}"
    db.query(PasswordResetRequest).filter(
        PasswordResetRequest.user_id == user.user_id
    ).delete(synchronize_session=False)
    db.add(
        PasswordResetRequest(
            user_id=user.user_id,
            otp_hash=_hash_value(otp),
            expires_at=datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES),
        )
    )
    db.commit()

    try:
        _send_otp_email(email, otp)
    except (OSError, smtplib.SMTPException, RuntimeError):
        db.query(PasswordResetRequest).filter(
            PasswordResetRequest.user_id == user.user_id
        ).delete(synchronize_session=False)
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="Unable to send the OTP email. Please try again later.",
        )

    return {"message": "If that email is registered, an OTP has been sent."}


@app.post("/api/password-reset/verify")
def verify_password_reset_otp(payload: VerifyPasswordOtp, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    reset_request = (
        db.query(PasswordResetRequest)
        .filter(PasswordResetRequest.user_id == user.user_id)
        .order_by(PasswordResetRequest.created_at.desc())
        .first()
    )
    if (
        not reset_request
        or reset_request.expires_at < datetime.utcnow()
        or reset_request.attempts >= OTP_MAX_ATTEMPTS
        or reset_request.verified_at
        or not secrets.compare_digest(reset_request.otp_hash, _hash_value(payload.otp))
    ):
        if reset_request and reset_request.attempts < OTP_MAX_ATTEMPTS:
            reset_request.attempts += 1
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    reset_token = secrets.token_urlsafe(32)
    reset_request.verified_at = datetime.utcnow()
    reset_request.reset_token_hash = _hash_value(reset_token)
    db.commit()
    return {"message": "OTP verified.", "reset_token": reset_token}


@app.post("/api/password-reset/complete")
def complete_password_reset(payload: ResetPassword, db: Session = Depends(get_db)):
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    if not re.fullmatch(r"(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}", payload.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters and include an uppercase letter, number, and special character.",
        )

    reset_request = (
        db.query(PasswordResetRequest)
        .filter(
            PasswordResetRequest.reset_token_hash == _hash_value(payload.reset_token),
            PasswordResetRequest.verified_at.is_not(None),
            PasswordResetRequest.expires_at >= datetime.utcnow(),
        )
        .first()
    )
    if not reset_request:
        raise HTTPException(status_code=400, detail="Your reset session is invalid or expired.")

    user = db.query(User).filter(User.user_id == reset_request.user_id).first()
    user.password_hash = hashed_password(payload.password).decode("utf-8")
    db.delete(reset_request)
    db.commit()
    return {"message": "Password reset successfully. You can now sign in."}


@app.post("/api/login")
def login(payload: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user or not check_password(payload.password, user.password_hash.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is inactive.")
    if payload.role and (not user.role or user.role.role_name != payload.role):
        raise HTTPException(status_code=403, detail="The selected role does not match this account.")
    return {"message": "Login successful.", "user": {"id": user.user_id, "name": user.full_name, "role": user.role.role_name}}



@app.post("/api/add_vehicle", status_code=status.HTTP_201_CREATED)
def add_vehicle(
    payload: VehicleCreate,
    db: Session = Depends(get_db)
):
    # Check if registration number already exists
    existing_vehicle = (
        db.query(Vehicle)
        .filter(
            Vehicle.registration_number == payload.registration_number
        )
        .first()
    )

    if existing_vehicle:
        raise HTTPException(
            status_code=409,
            detail="Vehicle with this registration number already exists."
        )

    # Create Vehicle Object
    vehicle = Vehicle(
        registration_number=payload.registration_number.strip().upper(),
        vehicle_name=payload.vehicle_name.strip(),
        vehicle_type=payload.vehicle_type.strip(),
        max_load_capacity=payload.max_load_capacity,
        odometer=payload.odometer,
        acquisition_cost=payload.acquisition_cost,
        region=payload.region,
        status="Available"
    )

    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)

    return {
        "message": "Vehicle added successfully.",
        "vehicle": {
            "vehicle_id": vehicle.vehicle_id,
            "registration_number": vehicle.registration_number,
            "vehicle_name": vehicle.vehicle_name,
            "vehicle_type": vehicle.vehicle_type,
            "status": vehicle.status
        }
    }

from modules.database import Vehicle

@app.get("/api/vehicles")
def get_all_vehicles(db: Session = Depends(get_db)):
    vehicles = db.query(Vehicle).all()

    return [
        {
            "vehicle_id": vehicle.vehicle_id,
            "registration_number": vehicle.registration_number,
            "vehicle_name": vehicle.vehicle_name,
            "vehicle_type": vehicle.vehicle_type,
            "max_load_capacity": vehicle.max_load_capacity,
            "odometer": vehicle.odometer,
            "acquisition_cost": vehicle.acquisition_cost,
            "region": vehicle.region,
            "status": vehicle.status,
        }
        for vehicle in vehicles
    ]

@app.get("/vehicles", response_class=HTMLResponse)
def vehicles_page(
    request: Request,
    db: Session = Depends(get_db)
):

    vehicles = db.query(Vehicle).all()

    return templates.TemplateResponse(
        
        {
            "request": request,
            "vehicles": vehicles
        },"vehicles.html"
    )

@app.delete("/api/vehicle/{vehicle_id}")
def delete_vehicle(
    vehicle_id: int,
    db: Session = Depends(get_db)
):

    vehicle = db.query(Vehicle).filter(
        Vehicle.vehicle_id == vehicle_id
    ).first()

    if not vehicle:
        raise HTTPException(
            status_code=404,
            detail="Vehicle not found."
        )

    db.delete(vehicle)
    db.commit()

    return {
        "message": "Vehicle deleted successfully."
    }
# Makes the remaining frontend pages, such as dashboard.html, available after login.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
