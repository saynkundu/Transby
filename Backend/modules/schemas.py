from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


# =====================================================
# AUTH
# =====================================================

class Login(BaseModel):
    email: EmailStr
    password: str
    role: str


class Register(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    confirm_password: str
    role_id: int


# =====================================================
# ROLE
# =====================================================

class RoleResponse(BaseModel):
    role_id: int
    role_name: str

    class Config:
        from_attributes = True


# =====================================================
# USER
# =====================================================

class UserResponse(BaseModel):
    user_id: int
    full_name: str
    email: EmailStr
    role_id: int
    is_active: bool

    class Config:
        from_attributes = True


# =====================================================
# VEHICLE
# =====================================================

class VehicleCreate(BaseModel):
    registration_number: str
    vehicle_name: str
    vehicle_type: str
    max_load_capacity: float
    odometer: float
    acquisition_cost: float
    region: str


class VehicleUpdate(BaseModel):
    vehicle_name: Optional[str] = None
    vehicle_type: Optional[str] = None
    max_load_capacity: Optional[float] = None
    odometer: Optional[float] = None
    acquisition_cost: Optional[float] = None
    status: Optional[str] = None
    region: Optional[str] = None


class VehicleResponse(BaseModel):
    vehicle_id: int
    registration_number: str
    vehicle_name: str
    vehicle_type: str
    max_load_capacity: float
    odometer: float
    acquisition_cost: float
    status: str
    region: str

    class Config:
        from_attributes = True


# =====================================================
# DRIVER
# =====================================================

class DriverCreate(BaseModel):
    full_name: str
    license_number: str
    license_category: str
    license_expiry: date
    contact_number: str
    safety_score: float


class DriverUpdate(BaseModel):
    contact_number: Optional[str] = None
    safety_score: Optional[float] = None
    status: Optional[str] = None


class DriverResponse(BaseModel):
    driver_id: int
    full_name: str
    license_number: str
    license_category: str
    license_expiry: date
    contact_number: str
    safety_score: float
    status: str

    class Config:
        from_attributes = True


# =====================================================
# TRIP
# =====================================================

class TripCreate(BaseModel):
    vehicle_id: int
    driver_id: int
    source_location: str
    destination_location: str
    cargo_weight: float
    planned_distance: float
    revenue: float


class TripUpdate(BaseModel):
    actual_distance: Optional[float] = None
    fuel_used: Optional[float] = None
    end_odometer: Optional[float] = None
    status: Optional[str] = None


class TripResponse(BaseModel):
    trip_id: int
    vehicle_id: int
    driver_id: int
    source_location: str
    destination_location: str
    cargo_weight: float
    planned_distance: float
    actual_distance: Optional[float]
    status: str

    class Config:
        from_attributes = True


# =====================================================
# MAINTENANCE
# =====================================================

class MaintenanceCreate(BaseModel):
    vehicle_id: int
    maintenance_type: str
    description: str
    maintenance_cost: float
    start_date: date


class MaintenanceUpdate(BaseModel):
    end_date: Optional[date] = None
    status: Optional[str] = None


class MaintenanceResponse(BaseModel):
    maintenance_id: int
    vehicle_id: int
    maintenance_type: str
    maintenance_cost: float
    status: str

    class Config:
        from_attributes = True


# =====================================================
# FUEL LOG
# =====================================================

class FuelLogCreate(BaseModel):
    vehicle_id: int
    trip_id: int
    liters: float
    fuel_cost: float
    fuel_date: date


class FuelLogResponse(BaseModel):
    fuel_log_id: int
    vehicle_id: int
    trip_id: int
    liters: float
    fuel_cost: float

    class Config:
        from_attributes = True


# =====================================================
# EXPENSE
# =====================================================

class ExpenseCreate(BaseModel):
    vehicle_id: int
    trip_id: int
    expense_type: str
    amount: float
    expense_date: date
    remarks: str


class ExpenseResponse(BaseModel):
    expense_id: int
    vehicle_id: int
    trip_id: int
    expense_type: str
    amount: float

    class Config:
        from_attributes = True


# =====================================================
# VEHICLE DOCUMENT
# =====================================================

class VehicleDocumentCreate(BaseModel):
    vehicle_id: int
    document_name: str
    file_path: str
    expiry_date: date


class VehicleDocumentResponse(BaseModel):
    document_id: int
    vehicle_id: int
    document_name: str
    file_path: str
    expiry_date: date

    class Config:
        from_attributes = True