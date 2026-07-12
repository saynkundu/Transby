from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from modules.db import Base, engine, get_db
from modules.database import Role, User,Vehicle
from modules.hashed_password import check_password, hashed_password
from modules.schemas import Login, Register,VehicleCreate



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
        "vehicles.html",
        {
            "request": request,
            "vehicles": vehicles
        }
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
