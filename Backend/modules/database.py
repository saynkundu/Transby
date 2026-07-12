from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Date,
    DateTime,
    Boolean,
    Text,
    Enum,
    ForeignKey
)

from sqlalchemy.orm import relationship

from database import Base

from datetime import datetime


# =====================================================
# ROLES
# =====================================================

class Role(Base):

    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, index=True)

    role_name = Column(String(50), unique=True, nullable=False)

    users = relationship("User", back_populates="role")


# =====================================================
# USERS
# =====================================================

class User(Base):

    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(100), nullable=False)

    email = Column(String(120), unique=True, nullable=False)

    password_hash = Column(String(255), nullable=False)

    role_id = Column(Integer, ForeignKey("roles.role_id"))

    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    role = relationship("Role", back_populates="users")


# =====================================================
# VEHICLES
# =====================================================

class Vehicle(Base):

    __tablename__ = "vehicles"

    vehicle_id = Column(Integer, primary_key=True, index=True)

    registration_number = Column(String(30), unique=True, nullable=False)

    vehicle_name = Column(String(100), nullable=False)

    vehicle_type = Column(String(50))

    max_load_capacity = Column(Float)

    odometer = Column(Float, default=0)

    acquisition_cost = Column(Float)

    status = Column(
        Enum(
            "Available",
            "On Trip",
            "In Shop",
            "Retired",
            name="vehicle_status"
        ),
        default="Available"
    )

    region = Column(String(80))

    created_at = Column(DateTime, default=datetime.utcnow)

    trips = relationship("Trip", back_populates="vehicle")

    maintenance_logs = relationship("MaintenanceLog", back_populates="vehicle")

    fuel_logs = relationship("FuelLog", back_populates="vehicle")

    expenses = relationship("Expense", back_populates="vehicle")

    documents = relationship("VehicleDocument", back_populates="vehicle")


# =====================================================
# DRIVERS
# =====================================================

class Driver(Base):

    __tablename__ = "drivers"

    driver_id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(100), nullable=False)

    license_number = Column(String(50), unique=True, nullable=False)

    license_category = Column(String(30))

    license_expiry = Column(Date)

    contact_number = Column(String(20))

    safety_score = Column(Float, default=100)

    status = Column(
        Enum(
            "Available",
            "On Trip",
            "Off Duty",
            "Suspended",
            name="driver_status"
        ),
        default="Available"
    )

    created_at = Column(DateTime, default=datetime.utcnow)

    trips = relationship("Trip", back_populates="driver")


# =====================================================
# TRIPS
# =====================================================

class Trip(Base):

    __tablename__ = "trips"

    trip_id = Column(Integer, primary_key=True, index=True)

    trip_code = Column(String(40), unique=True)

    vehicle_id = Column(Integer, ForeignKey("vehicles.vehicle_id"))

    driver_id = Column(Integer, ForeignKey("drivers.driver_id"))

    source_location = Column(String(120))

    destination_location = Column(String(120))

    cargo_weight = Column(Float)

    planned_distance = Column(Float)

    actual_distance = Column(Float)

    start_odometer = Column(Float)

    end_odometer = Column(Float)

    fuel_used = Column(Float)

    revenue = Column(Float, default=0)

    status = Column(
        Enum(
            "Draft",
            "Dispatched",
            "Completed",
            "Cancelled",
            name="trip_status"
        ),
        default="Draft"
    )

    created_at = Column(DateTime, default=datetime.utcnow)

    completed_at = Column(DateTime)

    vehicle = relationship("Vehicle", back_populates="trips")

    driver = relationship("Driver", back_populates="trips")

    fuel_logs = relationship("FuelLog", back_populates="trip")

    expenses = relationship("Expense", back_populates="trip")


# =====================================================
# MAINTENANCE LOGS
# =====================================================

class MaintenanceLog(Base):

    __tablename__ = "maintenance_logs"

    maintenance_id = Column(Integer, primary_key=True, index=True)

    vehicle_id = Column(Integer, ForeignKey("vehicles.vehicle_id"))

    maintenance_type = Column(String(100))

    description = Column(Text)

    maintenance_cost = Column(Float)

    start_date = Column(Date)

    end_date = Column(Date)

    status = Column(
        Enum(
            "Active",
            "Completed",
            name="maintenance_status"
        ),
        default="Active"
    )

    vehicle = relationship("Vehicle", back_populates="maintenance_logs")


# =====================================================
# FUEL LOGS
# =====================================================

class FuelLog(Base):

    __tablename__ = "fuel_logs"

    fuel_log_id = Column(Integer, primary_key=True, index=True)

    vehicle_id = Column(Integer, ForeignKey("vehicles.vehicle_id"))

    trip_id = Column(Integer, ForeignKey("trips.trip_id"))

    liters = Column(Float)

    fuel_cost = Column(Float)

    fuel_date = Column(Date)

    vehicle = relationship("Vehicle", back_populates="fuel_logs")

    trip = relationship("Trip", back_populates="fuel_logs")


# =====================================================
# EXPENSES
# =====================================================

class Expense(Base):

    __tablename__ = "expenses"

    expense_id = Column(Integer, primary_key=True, index=True)

    vehicle_id = Column(Integer, ForeignKey("vehicles.vehicle_id"))

    trip_id = Column(Integer, ForeignKey("trips.trip_id"))

    expense_type = Column(
        Enum(
            "Toll",
            "Maintenance",
            "Parking",
            "Fine",
            "Other",
            name="expense_type"
        )
    )

    amount = Column(Float)

    expense_date = Column(Date)

    remarks = Column(Text)

    vehicle = relationship("Vehicle", back_populates="expenses")

    trip = relationship("Trip", back_populates="expenses")


# =====================================================
# VEHICLE DOCUMENTS
# =====================================================

class VehicleDocument(Base):

    __tablename__ = "vehicle_documents"

    document_id = Column(Integer, primary_key=True, index=True)

    vehicle_id = Column(Integer, ForeignKey("vehicles.vehicle_id"))

    document_name = Column(String(100))

    file_path = Column(String(255))

    expiry_date = Column(Date)

    uploaded_at = Column(DateTime, default=datetime.utcnow)

    vehicle = relationship("Vehicle", back_populates="documents")