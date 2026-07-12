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
from modules.database import PasswordResetRequest, Role, User, Vehicle,Driver,Trip
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


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/drivers", response_class=HTMLResponse)
def drivers_page(request: Request):
    return templates.TemplateResponse(request, "drivers.html")


@app.get("/trips", response_class=HTMLResponse)
def trips_page(request: Request):
    return templates.TemplateResponse(request, "trips.html")


@app.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(request: Request):
    return templates.TemplateResponse(request, "maintenance.html")


@app.get("/fuel-expenses", response_class=HTMLResponse)
def fuel_expenses_page(request: Request):
    return templates.TemplateResponse(request, "fuel-expenses.html")


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    return templates.TemplateResponse(request, "reports.html")


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html")


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
        request,
        "vehicles.html",
        {
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




@app.get("/drivers", response_class=HTMLResponse)
def drivers_page(
    request: Request,
    db: Session = Depends(get_db)
):

    drivers = db.query(Driver).all()

    return templates.TemplateResponse(
        "drivers.html",
        {
            "request": request,
            "drivers": drivers
        }
    )

from sqlalchemy import func

@app.get("/drivers", response_class=HTMLResponse)
def drivers_page(
    request: Request,
    db: Session = Depends(get_db)
):

    drivers = db.query(Driver).all()

    performance = []

    for driver in drivers:

        total_trips = db.query(Trip).filter(
            Trip.driver_id == driver.driver_id
        ).count()

        completed = db.query(Trip).filter(
            Trip.driver_id == driver.driver_id,
            Trip.status == "Completed"
        ).count()

        cancelled = db.query(Trip).filter(
            Trip.driver_id == driver.driver_id,
            Trip.status == "Cancelled"
        ).count()

        performance.append({
            "name": driver.full_name,
            "total": total_trips,
            "completed": completed,
            "cancelled": cancelled,
            "rating": driver.safety_score
        })

    return templates.TemplateResponse(
        "drivers.html",
        {
            "request": request,
            "drivers": drivers,
            "performance": performance
        }
    )

@app.get("/trips", response_class=HTMLResponse)
def trips_page(
    request: Request,
    db: Session = Depends(get_db)
):

    trips = (
        db.query(Trip)
        .all()
    )

    return templates.TemplateResponse(
        "trips.html",
        {
            "request": request,
            "trips": trips
        }
    )

@app.get("/trip/{trip_id}", response_class=HTMLResponse)
def trip_details(
    trip_id: int,
    request: Request,
    db: Session = Depends(get_db)
):

    trip = db.query(Trip).filter(
        Trip.trip_id == trip_id
    ).first()

    if not trip:
        raise HTTPException(
            status_code=404,
            detail="Trip not found."
        )

    return templates.TemplateResponse(
        "trip_details.html",
        {
            "request": request,
            "trip": trip
        }
    )


@app.get("/trips", response_class=HTMLResponse)
def trips_page(
    request: Request,
    db: Session = Depends(get_db)
):

    trips = db.query(Trip).all()

    return templates.TemplateResponse(
        "trips.html",
        {
            "request": request,
            "trips": trips
        }
    )

from sqlalchemy import func, case
from modules.database import Trip

@app.get("/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    db: Session = Depends(get_db)
):

    delivery_performance = (
        db.query(
            Trip.source_location,
            Trip.destination_location,
            func.count(Trip.trip_id).label("total_trips"),
            func.sum(
                case(
                    (Trip.status == "Completed", 1),
                    else_=0
                )
            ).label("on_time"),
            func.sum(
                case(
                    (Trip.status == "Cancelled", 1),
                    else_=0
                )
            ).label("delayed")
        )
        .group_by(
            Trip.source_location,
            Trip.destination_location
        )
        .all()
    )

    return templates.TemplateResponse(
        "reports.html",
        {
            "request": request,
            "delivery_performance": delivery_performance
        }
    )

from datetime import datetime

@app.get("/trips", response_class=HTMLResponse)
def trips_page(
    request: Request,
    db: Session = Depends(get_db)
):

    trips = db.query(Trip).all()

    alerts = []

    for trip in trips:

        # Cancelled Trip
        if trip.status == "Cancelled":
            alerts.append({
                "type": "danger",
                "message": f"Trip {trip.trip_code} has been cancelled."
            })

        # Vehicle in Maintenance
        if trip.vehicle and trip.vehicle.status == "In Shop":
            alerts.append({
                "type": "warning",
                "message": f"Vehicle {trip.vehicle.registration_number} is under maintenance."
            })

        # Driver Suspended
        if trip.driver and trip.driver.status == "Suspended":
            alerts.append({
                "type": "danger",
                "message": f"Driver {trip.driver.full_name} is suspended."
            })

        # Low Safety Score
        if trip.driver and trip.driver.safety_score < 70:
            alerts.append({
                "type": "warning",
                "message": f"{trip.driver.full_name}'s safety score is below 70."
            })

    return templates.TemplateResponse(
        "trips.html",
        {
            "request": request,
            "trips": trips,
            "alerts": alerts
        }
    )

from sqlalchemy import func
from modules.database import Trip

@app.get("/reports", response_class=HTMLResponse)
def reports_page(
    request: Request,
    db: Session = Depends(get_db)
):

    trips = db.query(Trip).all()

    # -------- Trip Completion --------
    completed = db.query(Trip).filter(
        Trip.status == "Completed"
    ).count()

    dispatched = db.query(Trip).filter(
        Trip.status == "Dispatched"
    ).count()

    cancelled = db.query(Trip).filter(
        Trip.status == "Cancelled"
    ).count()

    draft = db.query(Trip).filter(
        Trip.status == "Draft"
    ).count()

    trip_chart = {
        "labels": ["Completed", "Dispatched", "Draft", "Cancelled"],
        "values": [completed, dispatched, draft, cancelled]
    }

    # -------- Route Performance --------

    routes = (
        db.query(
            Trip.source_location,
            Trip.destination_location,
            func.count(Trip.trip_id)
        )
        .group_by(
            Trip.source_location,
            Trip.destination_location
        )
        .all()
    )

    route_chart = {
        "labels": [
            f"{r.source_location} → {r.destination_location}"
            for r in routes
        ],
        "values": [
            r[2]
            for r in routes
        ]
    }

    return templates.TemplateResponse(
        "reports.html",
        {
            "request": request,
            "trip_chart": trip_chart,
            "route_chart": route_chart
        }
    )

##maintenance.html 
from modules.database import MaintenanceLog

@app.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(
    request: Request,
    db: Session = Depends(get_db)
):

    maintenance_logs = (
        db.query(MaintenanceLog)
        .all()
    )

    return templates.TemplateResponse(
        "maintenance.html",
        {
            "request": request,
            "maintenance_logs": maintenance_logs
        }
    )

from datetime import date
from modules.database import MaintenanceLog

@app.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(
    request: Request,
    db: Session = Depends(get_db)
):

    maintenance_logs = db.query(MaintenanceLog).all()

    upcoming_maintenance = (
        db.query(MaintenanceLog)
        .filter(
            MaintenanceLog.status == "Active"
        )
        .order_by(MaintenanceLog.start_date)
        .all()
    )

    return templates.TemplateResponse(
        "maintenance.html",
        {
            "request": request,
            "maintenance_logs": maintenance_logs,
            "upcoming_maintenance": upcoming_maintenance
        }
    )

from datetime import date

@app.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(
    request: Request,
    db: Session = Depends(get_db)
):

    maintenance_logs = db.query(MaintenanceLog).all()

    upcoming_maintenance = (
        db.query(MaintenanceLog)
        .filter(MaintenanceLog.status == "Active")
        .order_by(MaintenanceLog.start_date)
        .all()
    )

    vehicles = db.query(Vehicle).all()

    fleet_health = []

    for vehicle in vehicles:

        last_service = (
            db.query(MaintenanceLog)
            .filter(
                MaintenanceLog.vehicle_id == vehicle.vehicle_id,
                MaintenanceLog.status == "Completed"
            )
            .order_by(MaintenanceLog.end_date.desc())
            .first()
        )

        next_service = (
            db.query(MaintenanceLog)
            .filter(
                MaintenanceLog.vehicle_id == vehicle.vehicle_id,
                MaintenanceLog.status == "Active"
            )
            .order_by(MaintenanceLog.start_date)
            .first()
        )

        # Simple Health Score
        health_score = 100

        if vehicle.status == "In Shop":
            health_score -= 40

        if next_service:
            health_score -= 20

        if health_score < 0:
            health_score = 0

        fleet_health.append({
            "vehicle": vehicle.registration_number,
            "health_score": health_score,
            "last_service": last_service.end_date if last_service else None,
            "next_service": next_service.start_date if next_service else None
        })

    return templates.TemplateResponse(
        "maintenance.html",
        {
            "request": request,
            "maintenance_logs": maintenance_logs,
            "upcoming_maintenance": upcoming_maintenance,
            "fleet_health": fleet_health
        }
    )

from sqlalchemy import func
from modules.database import Mechanic, MaintenanceLog

@app.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(
    request: Request,
    db: Session = Depends(get_db)
):

    mechanics = (
        db.query(
            Mechanic,
            func.count(MaintenanceLog.maintenance_id).label("jobs")
        )
        .outerjoin(
            MaintenanceLog,
            Mechanic.mechanic_id == MaintenanceLog.mechanic_id
        )
        .group_by(Mechanic.mechanic_id)
        .all()
    )

    return templates.TemplateResponse(
        "maintenance.html",
        {
            "request": request,
            "mechanics": mechanics
        }
    )

# Makes the remaining frontend pages, such as dashboard.html, available after login.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
