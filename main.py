import os
import re
import jwt
import uuid
import bcrypt
import random
import string
import base64
import pymysql
import cloudinary
import cloudinary.uploader
import cloudinary.api
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_, or_
from PIL import Image
import io

import smtplib
import socket


from threading import Thread
from queue import Queue
import concurrent.futures
from flask import current_app

# Install PyMySQL as MySQLdb
pymysql.install_as_MySQLdb()

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://dip-mandal.github.io", "http://localhost:5500", "http://127.0.0.1:5500", "http://127.0.0.1:5000", "http://localhost:5000"])

# ==================== CONFIGURATION ====================
class Config:
    # JWT Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in environment")
    
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    if not JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY must be set in environment")
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL must be set in environment")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Memory optimization
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 5,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 2  # Reduce from 10
    }
    
    # Email timeout
    MAIL_TIMEOUT = 30
    
    # Cloudinary Configuration
    CLOUDINARY_CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME')
    CLOUDINARY_API_KEY = os.getenv('CLOUDINARY_API_KEY')
    CLOUDINARY_API_SECRET = os.getenv('CLOUDINARY_API_SECRET')
    
    if not all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]):
        raise ValueError("Cloudinary credentials must be set in environment")
    
    # Email Configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    if not all([MAIL_USERNAME, MAIL_PASSWORD]):
        raise ValueError("Email credentials must be set in environment")
    
    # Application Settings
    OTP_EXPIRY_MINUTES = 10
    BASE_URL = os.getenv('BASE_URL', 'http://127.0.0.1:5000')
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://127.0.0.1:5500')

app.config.from_object(Config)



# ==================== INITIALIZE EXTENSIONS ====================
db = SQLAlchemy(app)
mail = Mail(app)

# Configure Cloudinary
cloudinary.config(
    cloud_name=app.config['CLOUDINARY_CLOUD_NAME'],
    api_key=app.config['CLOUDINARY_API_KEY'],
    api_secret=app.config['CLOUDINARY_API_SECRET']
)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    """Main users table - stores all registered users"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('student', 'teacher', 'admin'), nullable=False, default='student')
    gender = db.Column(db.Enum('male', 'female', 'other'), nullable=True)
    avatar = db.Column(db.Text, nullable=True)  # Changed to TEXT for longer URLs
    phone = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    address = db.Column(db.Text, nullable=True)
    
    # Account status
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    student_profile = db.relationship('Student', backref='user', uselist=False, cascade='all, delete-orphan')
    teacher_profile = db.relationship('Teacher', backref='user', uselist=False, cascade='all, delete-orphan')
    tokens = db.relationship('RefreshToken', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    event_registrations = db.relationship('EventRegistration', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self, include_private=False):
        data = {
            'id': self.id,
            'email': self.email,
            'fullName': self.full_name,
            'role': self.role,
            'gender': self.gender,
            'avatar': self.avatar or f"https://ui-avatars.com/api/?name={self.full_name}&background=4361ee&color=fff&size=200",
            'phone': self.phone,
            'isVerified': self.is_verified,
            'isActive': self.is_active,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }
        if include_private:
            data.update({
                'dateOfBirth': self.date_of_birth.isoformat() if self.date_of_birth else None,
                'address': self.address,
                'lastLogin': self.last_login.isoformat() if self.last_login else None
            })
        return data


class PendingUser(db.Model):
    """Temporary storage for users awaiting email verification"""
    __tablename__ = 'pending_users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('student', 'teacher'), nullable=False)
    gender = db.Column(db.Enum('male', 'female', 'other'), nullable=True)
    avatar = db.Column(db.Text, nullable=True)  # Changed to TEXT
    
    # Registration data (JSON field for additional data)
    registration_data = db.Column(db.JSON, nullable=True)
    
    # OTP verification
    otp_code = db.Column(db.String(6), nullable=False)
    otp_expiry = db.Column(db.DateTime, nullable=False)
    otp_attempts = db.Column(db.Integer, default=0)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def generate_otp(self):
        self.otp_code = ''.join(random.choices(string.digits, k=6))
        self.otp_expiry = datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])
        self.otp_attempts = 0
        return self.otp_code
    
    def verify_otp(self, otp):
        if self.otp_code != otp:
            self.otp_attempts += 1
            return False, 'invalid'
        if datetime.utcnow() > self.otp_expiry:
            return False, 'expired'
        return True, 'valid'


class Student(db.Model):
    """Student specific information"""
    __tablename__ = 'students'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True)
    
    # Academic information
    registration_no = db.Column(db.String(50), unique=True, nullable=False)
    course = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    caste = db.Column(db.String(50), nullable=True)
    
    # Academic performance (calculated from actual data)
    cgpa = db.Column(db.Float, nullable=True)
    attendance = db.Column(db.Float, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    projects = db.relationship('Project', backref='student', lazy='dynamic')
    achievements = db.relationship('Achievement', backref='student', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'userId': self.user_id,
            'registrationNo': self.registration_no,
            'course': self.course,
            'year': self.year,
            'semester': self.semester,
            'caste': self.caste,
            'cgpa': self.cgpa,
            'attendance': self.attendance
        }


class Teacher(db.Model):
    """Teacher specific information"""
    __tablename__ = 'teachers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True)
    
    # Professional information
    employee_id = db.Column(db.String(50), unique=True, nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(255), nullable=False)
    experience_years = db.Column(db.Integer, default=0)
    specialization = db.Column(db.String(255), nullable=True)
    research_interests = db.Column(db.Text, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    office = db.Column(db.String(100), nullable=True)
    office_hours = db.Column(db.String(255), nullable=True)
    
    # Social links
    linkedin = db.Column(db.String(255), nullable=True)
    google_scholar = db.Column(db.String(255), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    projects = db.relationship('Project', backref='teacher', lazy='dynamic')
    publications = db.relationship('Publication', backref='teacher', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'userId': self.user_id,
            'employeeId': self.employee_id,
            'designation': self.designation,
            'qualification': self.qualification,
            'experience': self.experience_years,
            'specialization': self.specialization,
            'researchInterests': self.research_interests,
            'bio': self.bio,
            'office': self.office,
            'officeHours': self.office_hours,
            'linkedin': self.linkedin,
            'googleScholar': self.google_scholar
        }


class RefreshToken(db.Model):
    """Store refresh tokens for JWT authentication"""
    __tablename__ = 'refresh_tokens'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token = db.Column(db.String(500), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    revoked = db.Column(db.Boolean, default=False)


class Program(db.Model):
    """Academic programs offered by department"""
    __tablename__ = 'programs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    duration = db.Column(db.String(50), nullable=False)
    seats = db.Column(db.Integer, nullable=False)
    icon = db.Column(db.String(50), default='fa-laptop-code')
    highlights = db.Column(db.JSON, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'description': self.description,
            'duration': self.duration,
            'seats': self.seats,
            'icon': self.icon,
            'highlights': self.highlights or [],
            'isActive': self.is_active
        }


class Faculty(db.Model):
    """Faculty members (public facing)"""
    __tablename__ = 'faculty'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    teacher_id = db.Column(db.String(36), db.ForeignKey('teachers.id', ondelete='SET NULL'), nullable=True)
    name = db.Column(db.String(255), nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(255), nullable=False)
    image = db.Column(db.Text, nullable=True)  # Changed to TEXT
    expertise = db.Column(db.JSON, nullable=True)
    email = db.Column(db.String(255), nullable=True)
    linkedin = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    display_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'designation': self.designation,
            'qualification': self.qualification,
            'image': self.image or f"https://ui-avatars.com/api/?name={self.name}&background=4361ee&color=fff&size=200",
            'expertise': self.expertise or [],
            'email': self.email,
            'linkedin': self.linkedin,
            'bio': self.bio
        }


class Project(db.Model):
    """Student/Faculty projects"""
    __tablename__ = 'projects'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image = db.Column(db.Text, nullable=True)  # Changed to TEXT
    technologies = db.Column(db.JSON, nullable=True)
    github = db.Column(db.String(500), nullable=True)
    demo = db.Column(db.String(500), nullable=True)
    
    # Relationships
    student_id = db.Column(db.String(36), db.ForeignKey('students.id', ondelete='SET NULL'), nullable=True)
    teacher_id = db.Column(db.String(36), db.ForeignKey('teachers.id', ondelete='SET NULL'), nullable=True)
    
    # Status
    is_approved = db.Column(db.Boolean, default=False)
    is_featured = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'image': self.image or 'https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=400&h=200&fit=crop',
            'technologies': self.technologies or [],
            'github': self.github,
            'demo': self.demo,
            'isApproved': self.is_approved,
            'isFeatured': self.is_featured,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }


class Event(db.Model):
    """Department events"""
    __tablename__ = 'events'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.Enum('academic', 'cultural', 'technical', 'workshop', 'seminar'), nullable=False)
    
    # Date and time
    event_date = db.Column(db.Date, nullable=False)
    event_time = db.Column(db.String(50), nullable=False)
    event_end_date = db.Column(db.Date, nullable=True)
    event_end_time = db.Column(db.String(50), nullable=True)
    
    location = db.Column(db.String(255), nullable=False)
    image = db.Column(db.Text, nullable=True)  # Changed to TEXT
    
    # Registration
    max_participants = db.Column(db.Integer, nullable=True)
    current_participants = db.Column(db.Integer, default=0)
    registration_deadline = db.Column(db.Date, nullable=True)
    
    # Organizer
    organizer = db.Column(db.String(255), nullable=True)
    contact_email = db.Column(db.String(255), nullable=True)
    contact_phone = db.Column(db.String(20), nullable=True)
    
    # External link
    link = db.Column(db.String(500), nullable=True)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'type': self.event_type,
            'date': self.event_date.isoformat() if self.event_date else None,
            'time': self.event_time,
            'endDate': self.event_end_date.isoformat() if self.event_end_date else None,
            'endTime': self.event_end_time,
            'location': self.location,
            'image': self.image,
            'maxParticipants': self.max_participants,
            'currentParticipants': self.current_participants,
            'registrationDeadline': self.registration_deadline.isoformat() if self.registration_deadline else None,
            'organizer': self.organizer,
            'contactEmail': self.contact_email,
            'contactPhone': self.contact_phone,
            'link': self.link,
            'isActive': self.is_active,
            'isFeatured': self.is_featured
        }


class EventRegistration(db.Model):
    """Event registrations by users"""
    __tablename__ = 'event_registrations'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.String(36), db.ForeignKey('events.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    # Registration details
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    
    # Status
    status = db.Column(db.Enum('registered', 'attended', 'cancelled'), default='registered')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    event = db.relationship('Event')
    
    def to_dict(self):
        return {
            'id': self.id,
            'eventId': self.event_id,
            'event': self.event.to_dict() if self.event else None,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'status': self.status,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }


class Topper(db.Model):
    """Academic toppers - calculated from actual student data"""
    __tablename__ = 'toppers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    student_id = db.Column(db.String(36), db.ForeignKey('students.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    course = db.Column(db.String(100), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    semester = db.Column(db.Integer, nullable=True)
    cgpa = db.Column(db.Float, nullable=False)
    achievements = db.Column(db.Text, nullable=True)
    image = db.Column(db.Text, nullable=True)  # Changed to TEXT
    linkedin = db.Column(db.String(500), nullable=True)
    github = db.Column(db.String(500), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    
    # Academic year (e.g., "2023-2024")
    academic_year = db.Column(db.String(20), nullable=False)
    
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'course': self.course,
            'year': self.year,
            'cgpa': self.cgpa,
            'achievements': self.achievements,
            'image': self.image or f"https://ui-avatars.com/api/?name={self.name}&background=4361ee&color=fff&size=200",
            'linkedin': self.linkedin,
            'github': self.github,
            'email': self.email,
            'academicYear': self.academic_year
        }


class ContactMessage(db.Model):
    """Contact form messages"""
    __tablename__ = 'contact_messages'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    is_replied = db.Column(db.Boolean, default=False)
    replied_at = db.Column(db.DateTime, nullable=True)
    reply_message = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'subject': self.subject,
            'message': self.message,
            'isRead': self.is_read,
            'isReplied': self.is_replied,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }


class Achievement(db.Model):
    """Student achievements"""
    __tablename__ = 'achievements'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    student_id = db.Column(db.String(36), db.ForeignKey('students.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'date': self.date.isoformat() if self.date else None,
            'category': self.category
        }


class Publication(db.Model):
    """Faculty publications"""
    __tablename__ = 'publications'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    teacher_id = db.Column(db.String(36), db.ForeignKey('teachers.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    authors = db.Column(db.String(500), nullable=False)
    journal = db.Column(db.String(255), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    doi = db.Column(db.String(255), nullable=True)
    link = db.Column(db.String(500), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'authors': self.authors,
            'journal': self.journal,
            'year': self.year,
            'doi': self.doi,
            'link': self.link
        }


class DepartmentInfo(db.Model):
    """Department information and settings"""
    __tablename__ = 'department_info'
    
    id = db.Column(db.Integer, primary_key=True, default=1)
    university = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(255), nullable=False)
    vision = db.Column(db.Text, nullable=False)
    mission = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # Contact information
    address = db.Column(db.Text, nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    office_hours = db.Column(db.String(255), nullable=False)
    
    # Social media
    facebook = db.Column(db.String(255), nullable=True)
    twitter = db.Column(db.String(255), nullable=True)
    linkedin = db.Column(db.String(255), nullable=True)
    youtube = db.Column(db.String(255), nullable=True)
    instagram = db.Column(db.String(255), nullable=True)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'university': self.university,
            'department': self.department,
            'vision': self.vision,
            'mission': self.mission,
            'description': self.description,
            'address': self.address,
            'phone': self.phone,
            'email': self.email,
            'hours': self.office_hours,
            'facebook': self.facebook,
            'twitter': self.twitter,
            'linkedin': self.linkedin,
            'youtube': self.youtube,
            'instagram': self.instagram
        }


class NewsletterSubscriber(db.Model):
    """Newsletter subscribers"""
    __tablename__ = 'newsletter_subscribers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    unsubscribed_at = db.Column(db.DateTime, nullable=True)


class ActivityLog(db.Model):
    """System activity logs"""
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    entity_type = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==================== HELPER FUNCTIONS ====================

def generate_tokens(user_id):
    """Generate access and refresh tokens"""
    # Access token
    access_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        },
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    
    # Refresh token
    refresh_token = jwt.encode(
        {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
        },
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )
    
    # Store refresh token in database
    token_record = RefreshToken(
        user_id=user_id,
        token=refresh_token,
        expires_at=datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
    )
    db.session.add(token_record)
    db.session.commit()
    
    return {
        'accessToken': access_token,
        'refreshToken': refresh_token
    }


def token_required(f):
    """Decorator to require valid access token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Decode token
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            if data.get('type') != 'access':
                return jsonify({'message': 'Invalid token type'}), 401
            
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
            if not current_user.is_active:
                return jsonify({'message': 'Account is deactivated'}), 401
            if not current_user.is_verified:
                return jsonify({'message': 'Email not verified'}), 401
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def teacher_required(f):
    """Decorator to require teacher or admin role"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role not in ['teacher', 'admin']:
            return jsonify({'message': 'Teacher access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def student_required(f):
    """Decorator to require student role"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'student':
            return jsonify({'message': 'Student access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone):
    """Validate phone number"""
    if not phone:
        return True
    pattern = r'^[0-9+\-\s]{10,15}$'
    return re.match(pattern, phone) is not None


def process_and_upload_image(base64_string, folder, public_id=None):
    """
    Process base64 image and upload to Cloudinary
    Returns: secure_url or None
    """
    try:
        # Parse base64
        if ',' in base64_string:
            header, encoded = base64_string.split(',', 1)
        else:
            encoded = base64_string
        
        # Decode
        file_data = base64.b64decode(encoded)
        
        # Open with PIL for processing
        img = Image.open(io.BytesIO(file_data))
        
        # Convert to RGB if needed (for PNG with transparency)
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                background.paste(img, mask=img.split()[3])
            else:
                background.paste(img)
            img = background
        
        # Resize to reasonable size (max 800x800)
        max_size = (800, 800)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        # Save to bytes with compression
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85, optimize=True)
        output.seek(0)
        
        # Generate public_id if not provided
        if not public_id:
            public_id = f"image_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}"
        
        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            output,
            folder=f"department_portal/{folder}",
            public_id=public_id,
            overwrite=True,
            resource_type="image"
        )
        
        return upload_result.get('secure_url')
    
    except Exception as e:
        print(f"Image processing error: {e}")
        return None


def log_activity(user_id, action, entity_type=None, entity_id=None, details=None):
    """Log user activity"""
    try:
        log = ActivityLog(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")
        db.session.rollback()


def get_department_stats():
    """Get real department statistics"""
    try:
        total_students = User.query.filter_by(
            role='student', 
            is_verified=True, 
            is_active=True, 
            is_deleted=False
        ).count()
        
        total_faculty = User.query.filter_by(
            role='teacher', 
            is_verified=True, 
            is_active=True, 
            is_deleted=False
        ).count()
        
        total_projects = Project.query.filter_by(is_approved=True).count()
        
        # Calculate placement percentage from actual placement data
        # For now, get from department_info or calculate from placed students
        dept_info = DepartmentInfo.query.get(1)
        placement_percentage = dept_info.placement_percentage if dept_info and hasattr(dept_info, 'placement_percentage') else 0
        
        return {
            'students': total_students,
            'faculty': total_faculty,
            'projects': total_projects,
            'placement': placement_percentage
        }
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            'students': 0,
            'faculty': 0,
            'projects': 0,
            'placement': 0
        }


# ==================== EMAIL FUNCTIONS ====================

def send_email(recipient, subject, template):
    """Send email using SMTP with timeout handling"""
    try:        
        # Set timeout for email connection
        app.config['MAIL_TIMEOUT'] = 30  # 30 seconds timeout
        
        msg = Message(
            subject=subject,
            recipients=[recipient],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        # Send with timeout
        mail.send(msg)
        print(f"Email sent successfully to {recipient}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print(f"Email authentication error for {recipient}")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP error for {recipient}: {str(e)}")
        return False
    except socket.timeout:
        print(f"Email timeout for {recipient}")
        return False
    except Exception as e:
        print(f"Email error to {recipient}: {str(e)}")
        return False


def get_verification_email(name, otp):
    """OTP verification email template"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #4361ee, #3a0ca3);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .otp-code {{
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 25px 0;
                border: 2px dashed #4361ee;
            }}
            .otp-digits {{
                font-size: 48px;
                font-weight: 700;
                letter-spacing: 10px;
                color: #4361ee;
                font-family: 'Courier New', monospace;
            }}
            .warning {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
                color: #856404;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 14px;
                border-top: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 Email Verification</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>Thank you for registering with the Department of Computer Science & Engineering. To complete your registration, please verify your email address using the OTP below:</p>
                
                <div class="otp-code">
                    <div class="otp-digits">{otp}</div>
                </div>
                
                <p>This OTP is valid for <strong>10 minutes</strong>. If you didn't request this verification, please ignore this email.</p>
                
                <div class="warning">
                    <strong>⚠️ Important:</strong> For security reasons, never share this OTP with anyone. Our staff will never ask for your OTP.
                </div>
                
                <p>Once verified, you'll have access to:</p>
                <ul>
                    <li>Student/Faculty Dashboard</li>
                    <li>Event Registrations</li>
                    <li>Project Submissions</li>
                    <li>Academic Resources</li>
                </ul>
            </div>
            <div class="footer">
                <p>© 2024 Department of Computer Science & Engineering. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    """.format(name=name, otp=otp)


def get_welcome_email(name, role, login_url):
    """Welcome email after verification"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Welcome to CSE Department</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #4361ee, #3a0ca3);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .feature-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                margin: 30px 0;
            }}
            .feature-item {{
                text-align: center;
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 8px;
            }}
            .feature-icon {{
                font-size: 32px;
                color: #4361ee;
                margin-bottom: 10px;
            }}
            .button {{
                display: inline-block;
                padding: 14px 40px;
                background: linear-gradient(135deg, #4361ee, #3a0ca3);
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                margin: 20px 0;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 14px;
                border-top: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎉 Welcome to CSE Department!</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>Welcome to the Department of Computer Science & Engineering! Your account has been successfully verified and created as a <strong>{role}</strong>.</p>
                
                <p>We're excited to have you join our academic community. Here's what you can do now:</p>
                
                <div class="feature-grid">
                    <div class="feature-item">
                        <div class="feature-icon">📊</div>
                        <h3>Dashboard</h3>
                        <p>Access your personalized dashboard</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon">📅</div>
                        <h3>Events</h3>
                        <p>Register for department events</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon">💻</div>
                        <h3>Projects</h3>
                        <p>Showcase your work</p>
                    </div>
                    <div class="feature-item">
                        <div class="feature-icon">👥</div>
                        <h3>Network</h3>
                        <p>Connect with faculty & peers</p>
                    </div>
                </div>
                
                <div style="text-align: center;">
                    <a href="{login_url}" class="button">🔑 Access Your Dashboard</a>
                </div>
                
                <p><strong>Quick Tips:</strong></p>
                <ul>
                    <li>Complete your profile information</li>
                    <li>Check upcoming events and register early</li>
                    <li>Explore student projects for inspiration</li>
                    <li>Enable notifications for important updates</li>
                </ul>
            </div>
            <div class="footer">
                <p>© 2024 Department of Computer Science & Engineering</p>
                <p>Have questions? Contact us at cse.department@university.edu</p>
            </div>
        </div>
    </body>
    </html>
    """.format(name=name, role=role, login_url=login_url)


def get_forgot_password_email(name, otp):
    """Password reset OTP email template"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Password Reset Request</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #f72585, #b5179e);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .otp-code {{
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                margin: 25px 0;
                border: 2px dashed #f72585;
            }}
            .otp-digits {{
                font-size: 48px;
                font-weight: 700;
                letter-spacing: 10px;
                color: #f72585;
                font-family: 'Courier New', monospace;
            }}
            .warning {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
                color: #856404;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 14px;
                border-top: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔑 Password Reset</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>We received a request to reset your password. Use the OTP below to proceed:</p>
                
                <div class="otp-code">
                    <div class="otp-digits">{otp}</div>
                </div>
                
                <p>This OTP is valid for <strong>10 minutes</strong>. If you didn't request this, please ignore this email and ensure your account is secure.</p>
                
                <div class="warning">
                    <strong>⚠️ Security Alert:</strong> If you didn't request a password reset, please contact the department immediately.
                </div>
                
                <p>After entering the OTP, you'll be able to set a new password.</p>
            </div>
            <div class="footer">
                <p>© 2024 Department of Computer Science & Engineering</p>
                <p>Need help? Contact us at cse.department@university.edu</p>
            </div>
        </div>
    </body>
    </html>
    """.format(name=name, otp=otp)


def get_event_notification_email(name, event_title, event_date, event_time, event_location):
    """Event registration confirmation email"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Event Registration Confirmation</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #4cc9f0, #4361ee);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .event-details {{
                background-color: #f8f9fa;
                padding: 25px;
                border-radius: 8px;
                margin: 25px 0;
            }}
            .detail-row {{
                display: flex;
                margin-bottom: 15px;
                border-bottom: 1px solid #dee2e6;
                padding-bottom: 10px;
            }}
            .detail-label {{
                font-weight: 600;
                width: 100px;
                color: #4361ee;
            }}
            .detail-value {{
                flex: 1;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 14px;
                border-top: 1px solid #dee2e6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✅ Registration Confirmed</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>You have successfully registered for the following event:</p>
                
                <div class="event-details">
                    <h3 style="margin-top: 0; color: #4361ee;">{event_title}</h3>
                    
                    <div class="detail-row">
                        <div class="detail-label">📅 Date</div>
                        <div class="detail-value">{event_date}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">⏰ Time</div>
                        <div class="detail-value">{event_time}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">📍 Location</div>
                        <div class="detail-value">{event_location}</div>
                    </div>
                </div>
                
                <p><strong>What's next?</strong></p>
                <ul>
                    <li>Add this event to your calendar</li>
                    <li>Arrive 10 minutes before the start time</li>
                    <li>Bring your student ID for check-in</li>
                </ul>
                
                <p>We look forward to seeing you there!</p>
            </div>
            <div class="footer">
                <p>© 2024 Department of Computer Science & Engineering</p>
                <p>Questions? Contact the event organizer</p>
            </div>
        </div>
    </body>
    </html>
    """.format(name=name, event_title=event_title, event_date=event_date, event_time=event_time, event_location=event_location)


def get_newsletter_email(name, updates):
    """Newsletter/update email"""
    updates_html = ''.join([f'<li>{update}</li>' for update in updates])
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Department Newsletter</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333333;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #4361ee, #3a0ca3);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .update-list {{
                background-color: #f8f9fa;
                padding: 25px;
                border-radius: 8px;
                margin: 25px 0;
            }}
            .update-list li {{
                margin-bottom: 10px;
                color: #4361ee;
            }}
            .button {{
                display: inline-block;
                padding: 12px 30px;
                background: linear-gradient(135deg, #4361ee, #3a0ca3);
                color: white;
                text-decoration: none;
                border-radius: 6px;
                margin: 20px 0;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 14px;
                border-top: 1px solid #dee2e6;
            }}
            .unsubscribe {{
                color: #6c757d;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📬 Department Newsletter</h1>
            </div>
            <div class="content">
                <h2>Hello {name},</h2>
                <p>Here are the latest updates from our department:</p>
                
                <div class="update-list">
                    <ul>
                        {updates_html}
                    </ul>
                </div>
                
                <div style="text-align: center;">
                    <a href="{frontend_url}/events" class="button">View All Events</a>
                </div>
                
                <p>Stay tuned for more exciting updates!</p>
                
                <p class="unsubscribe" style="text-align: center; margin-top: 30px;">
                    <a href="{frontend_url}/unsubscribe?email={name}">Unsubscribe</a> from these emails
                </p>
            </div>
            <div class="footer">
                <p>© 2024 Department of Computer Science & Engineering</p>
            </div>
        </div>
    </body>
    </html>
    """.format(name=name, updates_html=updates_html, frontend_url=app.config['FRONTEND_URL'])


# ==================== API ROUTES ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        db.session.execute('SELECT 1')
        db_status = 'connected'
    except Exception as e:
        db_status = f'disconnected: {str(e)}'
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': db_status
    }), 200


# ==================== AUTHENTICATION ROUTES ====================

from threading import Thread
from queue import Queue
import concurrent.futures
from flask import current_app

# Create a thread pool executor for background tasks
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

def background_email_task(app, email, full_name, otp):
    """Send email in background thread"""
    with app.app_context():
        try:
            # Get the email template with the parameters
            email_html = get_verification_email(full_name, otp)
            
            # Send email with proper parameters
            send_email(
                email,
                'Verify Your Email - CSE Department',
                email_html
            )
            print(f"Background email sent to {email}")
        except Exception as e:
            print(f"Background email error for {email}: {e}")

def background_image_upload_task(image_data, email, folder='profiles'):
    """Upload image in background thread"""
    try:
        if image_data and image_data.startswith('data:image'):
            public_id = f"user_{email.split('@')[0]}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            avatar_url = process_and_upload_image(
                image_data, 
                folder,
                public_id
            )
            print(f"Background image uploaded: {avatar_url}")
            return avatar_url
    except Exception as e:
        print(f"Background image upload error: {e}")
    return None

@app.route('/api/auth/register', methods=['POST'])
def register():
    global app
    """User registration with background processing for faster response"""
    data = request.get_json()
    
    # Validate required fields (synchronous - fast operation)
    required_fields = ['email', 'password', 'fullName', 'userType', 'gender']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    email = data['email'].lower().strip()
    
    # Validate email format
    if not validate_email(email):
        return jsonify({'message': 'Invalid email format'}), 400
    
    # Validate password strength
    if len(data['password']) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400
    
    # Check if user already exists (synchronous - necessary for data integrity)
    existing_user = User.query.filter_by(email=email, is_deleted=False).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 409
    
    # Check and cleanup pending user
    pending = PendingUser.query.filter_by(email=email).first()
    if pending:
        db.session.delete(pending)
        db.session.commit()
    
    # Generate OTP (fast operation)
    otp = ''.join(random.choices(string.digits, k=6))
    
    # Create pending user WITHOUT avatar initially
    pending_user = PendingUser(
        email=email,
        full_name=data['fullName'].strip(),
        role=data['userType'],
        gender=data.get('gender'),
        avatar=None,  # Will be updated by background task
        otp_code=otp,
        otp_expiry=datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])
    )
    pending_user.set_password(data['password'])
    
    # Store additional registration data - EXCLUDE registrationNo and employeeId
    registration_data = {}
    for k, v in data.items():
        if k not in ['email', 'password', 'fullName', 'userType', 'gender', 'profilePic', 'confirmPassword', 'registrationNo', 'employeeId']:
            registration_data[k] = v
    
    pending_user.registration_data = registration_data
    
    try:
        # Save to database first (fast operation)
        db.session.add(pending_user)
        db.session.commit()
        
        # Get the current app context for background threads
        app = current_app._get_current_object()
        
        # Start email sending in background
        executor.submit(background_email_task, app, email, data['fullName'], otp)
        
        # Handle profile picture in background if present
        if data.get('profilePic'):
            def update_avatar_callback(future):
                """Callback to update user with uploaded avatar URL"""
                try:
                    avatar_url = future.result()
                    if avatar_url:
                        with app.app_context():
                            user = PendingUser.query.filter_by(email=email).first()
                            if user:
                                user.avatar = avatar_url
                                db.session.commit()
                                print(f"Avatar URL updated for {email}: {avatar_url}")
                except Exception as e:
                    print(f"Avatar update callback error: {e}")
            
            # Submit image upload task
            future = executor.submit(
                background_image_upload_task, 
                data['profilePic'], 
                email
            )
            # Add callback to update database
            future.add_done_callback(update_avatar_callback)
        
        # Return immediate response
        response = jsonify({
            'message': 'Registration initiated. Please verify your email.',
            'email': email,
            'status': 'processing',  # Indicate background tasks are running
            'verification_sent': True  # Optimistic response
        })
        
        # Add CORS headers
        origin = request.headers.get('Origin')
        if origin in ["https://dip-mandal.github.io", "http://localhost:5500", "http://127.0.0.1:5500"]:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        
        return response, 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Database error during registration: {e}")
        response = jsonify({'message': 'Registration failed. Please try again.'})
        response.status_code = 500
        
        # Add CORS headers
        origin = request.headers.get('Origin')
        if origin in ["https://dip-mandal.github.io", "http://localhost:5500", "http://127.0.0.1:5500"]:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        
        return response



# For monitoring background tasks, you might want to add an endpoint:
@app.route('/api/auth/registration-status/<email>', methods=['GET'])
def registration_status(email):
    """Check the status of background tasks for registration"""
    pending_user = PendingUser.query.filter_by(email=email.lower().strip()).first()
    if not pending_user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'email': email,
        'avatar_uploaded': pending_user.avatar is not None,
        'otp_expiry': pending_user.otp_expiry.isoformat() if pending_user.otp_expiry else None,
        'status': 'pending_verification'
    })


@app.route('/api/auth/verify-email', methods=['POST'])
def verify_email():
    """Verify email with OTP"""
    data = request.get_json()
    
    if not data.get('email') or not data.get('otp'):
        return jsonify({'message': 'Email and OTP are required'}), 400
    
    email = data['email'].lower().strip()
    otp = data['otp'].strip()
    
    try:
        # Find pending user
        pending_user = PendingUser.query.filter_by(email=email).first()
        if not pending_user:
            return jsonify({'message': 'No pending registration found'}), 404
        
        # Verify OTP
        is_valid, reason = pending_user.verify_otp(otp)
        
        if not is_valid:
            if pending_user.otp_attempts >= 5:
                db.session.delete(pending_user)
                db.session.commit()
                return jsonify({'message': 'Too many failed attempts. Please register again.'}), 400
            
            if reason == 'expired':
                db.session.commit()
                return jsonify({'message': 'OTP has expired. Please request a new one.'}), 400
            
            db.session.commit()
            return jsonify({'message': 'Invalid OTP'}), 400
        
        # Get registration data
        reg_data = pending_user.registration_data or {}
        
        # Create actual user
        user = User(
            id=str(uuid.uuid4()),
            email=pending_user.email,
            full_name=pending_user.full_name,
            role=pending_user.role,
            gender=pending_user.gender,
            avatar=pending_user.avatar,
            is_verified=True
        )
        user.password_hash = pending_user.password_hash
        
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create role-specific profile
        if pending_user.role == 'student':
            # Validate required student fields
            course = reg_data.get('course')
            year = reg_data.get('year')
            semester = reg_data.get('semester')
            
            if not all([course, year, semester]):
                db.session.rollback()
                return jsonify({'message': 'Course, year, and semester are required for students'}), 400
            
            # Generate a unique registration number (ignore any from frontend)
            reg_no = None
            max_attempts = 20  # Increased attempts
            
            for attempt in range(max_attempts):
                # Generate registration number in format: YY + 6 digits (e.g., 24123456)
                year_prefix = datetime.utcnow().strftime('%y')
                random_num = ''.join(random.choices(string.digits, k=6))
                candidate_reg_no = f"{year_prefix}{random_num}"
                
                # Check if this registration number already exists
                existing = Student.query.filter_by(registration_no=candidate_reg_no).first()
                if not existing:
                    reg_no = candidate_reg_no
                    break
            
            if not reg_no:
                # Fallback to timestamp-based registration number
                timestamp = datetime.utcnow().strftime('%y%m%d%H%M%S')
                random_suffix = ''.join(random.choices(string.digits, k=4))
                reg_no = f"{timestamp}{random_suffix}"
            
            student = Student(
                user_id=user.id,
                registration_no=reg_no,
                course=course,
                year=int(year),
                semester=int(semester),
                caste=reg_data.get('caste')
            )
            db.session.add(student)
            
            print(f"Created student with registration number: {reg_no}")  # Debug log
        
        elif pending_user.role == 'teacher':
            # Validate required teacher fields
            designation = reg_data.get('designation')
            qualification = reg_data.get('qualification')
            
            if not all([designation, qualification]):
                db.session.rollback()
                return jsonify({'message': 'Designation and qualification are required for teachers'}), 400
            
            # Generate a unique employee ID (ignore any from frontend)
            emp_id = None
            max_attempts = 20
            
            for attempt in range(max_attempts):
                candidate_emp_id = f"FAC{datetime.utcnow().strftime('%y%m%d')}{random.randint(1000, 9999)}"
                
                # Check if this employee ID already exists
                existing = Teacher.query.filter_by(employee_id=candidate_emp_id).first()
                if not existing:
                    emp_id = candidate_emp_id
                    break
            
            if not emp_id:
                # Fallback to UUID-based employee ID
                emp_id = f"FAC{uuid.uuid4().hex[:10].upper()}"
            
            teacher = Teacher(
                user_id=user.id,
                employee_id=emp_id,
                designation=designation,
                qualification=qualification,
                experience_years=int(reg_data.get('experienceYears', 0)),
                specialization=reg_data.get('specialization'),
                research_interests=reg_data.get('researchInterests'),
                bio=reg_data.get('bio'),
                office=reg_data.get('office'),
                office_hours=reg_data.get('officeHours'),
                linkedin=reg_data.get('linkedin'),
                google_scholar=reg_data.get('googleScholar')
            )
            db.session.add(teacher)
            
            # Add to faculty list (public facing)
            faculty = Faculty(
                teacher_id=teacher.id,
                name=user.full_name,
                designation=designation,
                qualification=qualification,
                image=user.avatar,
                expertise=reg_data.get('expertise', []),
                email=user.email,
                bio=reg_data.get('bio')
            )
            db.session.add(faculty)
            
            print(f"Created teacher with employee ID: {emp_id}")  # Debug log
        
        # Delete pending user
        db.session.delete(pending_user)
        db.session.commit()
        
        # Generate tokens for auto-login
        tokens = generate_tokens(user.id)
        
        # Send welcome email
        welcome_email_html = get_welcome_email(user.full_name, user.role, f"{app.config['FRONTEND_URL']}/#student-portal")
        send_email(
            user.email,
            'Welcome to CSE Department!',
            welcome_email_html
        )
        
        # Log activity
        log_activity(user.id, 'user_registered', 'user', user.id, {'email': user.email})
        
        response = jsonify({
            'message': 'Email verified successfully',
            'accessToken': tokens['accessToken'],
            'refreshToken': tokens['refreshToken'],
            'user': user.to_dict()
        })
        
        # Add CORS headers
        origin = request.headers.get('Origin')
        if origin in ["https://dip-mandal.github.io", "http://localhost:5500", "http://127.0.0.1:5500"]:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        
        return response, 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error in verify_email: {str(e)}")
        
        # Check if it's a duplicate registration number error
        if "Duplicate entry" in str(e) and "registration_no" in str(e):
            error_message = "Registration number already exists. Please try again."
        elif "Duplicate entry" in str(e) and "employee_id" in str(e):
            error_message = "Employee ID already exists. Please try again."
        else:
            error_message = "Verification failed. Please try again."
        
        response = jsonify({'message': error_message, 'error': str(e)})
        response.status_code = 500
        
        # Add CORS headers
        origin = request.headers.get('Origin')
        if origin in ["https://dip-mandal.github.io", "http://localhost:5500", "http://127.0.0.1:5500"]:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        
        return response


@app.route('/api/auth/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP verification code"""
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    email = data['email'].lower().strip()
    
    # Find pending user
    pending_user = PendingUser.query.filter_by(email=email).first()
    if not pending_user:
        return jsonify({'message': 'No pending registration found'}), 404
    
    # Check if last OTP was sent within 60 seconds
    if pending_user.updated_at and (datetime.utcnow() - pending_user.updated_at).seconds < 60:
        return jsonify({'message': 'Please wait 60 seconds before resending'}), 429
    
    # Generate new OTP
    otp = pending_user.generate_otp()
    db.session.commit()
    
    # Send OTP email - FIXED: Generate HTML first, then send
    otp_email_html = get_verification_email(pending_user.full_name, otp)
    send_email(
        email,
        'New Verification Code - CSE Department',
        otp_email_html
    )
    
    return jsonify({'message': 'OTP resent successfully'}), 200


@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password are required'}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Find user
    user = User.query.filter_by(email=email, is_deleted=False).first()
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Check password
    if not user.check_password(password):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    # Check if verified
    if not user.is_verified:
        return jsonify({'message': 'Email not verified. Please check your inbox.'}), 403
    
    # Check if active
    if not user.is_active:
        return jsonify({'message': 'Account is deactivated. Contact administrator.'}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Generate tokens
    tokens = generate_tokens(user.id)
    
    # Log activity
    log_activity(user.id, 'user_login', 'user', user.id)
    
    return jsonify({
        'message': 'Login successful',
        'accessToken': tokens['accessToken'],
        'refreshToken': tokens['refreshToken'],
        'user': user.to_dict(include_private=True)
    }), 200


@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Refresh token required'}), 401
    
    refresh_token = auth_header.split(' ')[1]
    
    try:
        # Find token in database
        token_record = RefreshToken.query.filter_by(token=refresh_token, revoked=False).first()
        if not token_record:
            return jsonify({'message': 'Invalid refresh token'}), 401
        
        # Check expiry
        if datetime.utcnow() > token_record.expires_at:
            db.session.delete(token_record)
            db.session.commit()
            return jsonify({'message': 'Refresh token expired'}), 401
        
        # Decode token
        data = jwt.decode(refresh_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        if data.get('type') != 'refresh':
            return jsonify({'message': 'Invalid token type'}), 401
        
        # Generate new access token
        access_token = jwt.encode(
            {
                'user_id': data['user_id'],
                'type': 'access',
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
            },
            app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        return jsonify({'accessToken': access_token}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Logout user (revoke refresh token)"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        refresh_token = auth_header.split(' ')[1]
        
        token_record = RefreshToken.query.filter_by(token=refresh_token).first()
        if token_record:
            token_record.revoked = True
            db.session.commit()
    
    log_activity(current_user.id, 'user_logout', 'user', current_user.id)
    
    return jsonify({'message': 'Logged out successfully'}), 200


@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token(current_user):
    """Verify token validity"""
    return jsonify({
        'valid': True,
        'user': current_user.to_dict()
    }), 200


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Initiate password reset"""
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    email = data['email'].lower().strip()
    
    # Find user
    user = User.query.filter_by(email=email, is_deleted=False).first()
    if not user:
        # Don't reveal that user doesn't exist
        return jsonify({'message': 'If email exists, reset link will be sent'}), 200
    
    # Generate OTP
    otp = ''.join(random.choices(string.digits, k=6))
    
    # Store OTP in pending
    pending = PendingUser.query.filter_by(email=email).first()
    if pending:
        pending.generate_otp()
        pending.otp_code = otp
    else:
        pending = PendingUser(
            email=email,
            full_name=user.full_name,
            role=user.role,
            password_hash=user.password_hash,
            otp_code=otp,
            otp_expiry=datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])
        )
        db.session.add(pending)
    
    db.session.commit()
    
    # Send password reset email - FIXED: Generate HTML first, then send
    forgot_password_html = get_forgot_password_email(user.full_name, otp)
    send_email(
        email,
        'Password Reset Request - CSE Department',
        forgot_password_html
    )
    
    return jsonify({'message': 'If email exists, reset link will be sent'}), 200


@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password with OTP"""
    data = request.get_json()
    
    if not data.get('email') or not data.get('otp') or not data.get('newPassword'):
        return jsonify({'message': 'Email, OTP, and new password are required'}), 400
    
    email = data['email'].lower().strip()
    otp = data['otp'].strip()
    new_password = data['newPassword']
    
    # Validate password strength
    if len(new_password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400
    
    # Find pending user
    pending = PendingUser.query.filter_by(email=email).first()
    if not pending:
        return jsonify({'message': 'Invalid request'}), 400
    
    # Verify OTP
    is_valid, reason = pending.verify_otp(otp)
    
    if not is_valid:
        if reason == 'expired':
            db.session.delete(pending)
            db.session.commit()
            return jsonify({'message': 'OTP has expired. Please request again.'}), 400
        return jsonify({'message': 'Invalid OTP'}), 400
    
    # Find actual user
    user = User.query.filter_by(email=email, is_deleted=False).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Update password
    user.set_password(new_password)
    
    # Delete pending record
    db.session.delete(pending)
    
    # Revoke all refresh tokens
    RefreshToken.query.filter_by(user_id=user.id).update({'revoked': True})
    
    db.session.commit()
    
    log_activity(user.id, 'password_reset', 'user', user.id)
    
    return jsonify({'message': 'Password reset successful'}), 200


# ==================== PUBLIC API ROUTES ====================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get department statistics"""
    stats = get_department_stats()
    return jsonify(stats), 200


@app.route('/api/about', methods=['GET'])
def get_about():
    """Get about information"""
    info = DepartmentInfo.query.get(1)
    if not info:
        return jsonify({
            'university': 'University of Technology & Sciences',
            'department': 'Department of Computer Science & Engineering',
            'vision': 'To be a center of excellence in Computer Science education and research.',
            'mission': 'To provide quality education in Computer Science, foster innovation through research.',
            'description': 'Empowering students with cutting-edge technology education and research opportunities in Data Science and MCA programs.',
            'address': 'University Campus, Tech City',
            'phone': '+91-123-456-7890',
            'email': 'cse.department@university.edu',
            'hours': 'Mon-Fri: 9:00 AM - 5:00 PM'
        }), 200
    
    return jsonify(info.to_dict()), 200


@app.route('/api/programs', methods=['GET'])
def get_programs():
    """Get all programs"""
    programs = Program.query.filter_by(is_active=True).order_by(Program.name).all()
    return jsonify([p.to_dict() for p in programs]), 200


@app.route('/api/faculty', methods=['GET'])
def get_faculty():
    """Get all faculty members"""
    faculty = Faculty.query.filter_by(is_active=True).order_by(Faculty.display_order).all()
    return jsonify([f.to_dict() for f in faculty]), 200


@app.route('/api/projects', methods=['GET'])
def get_projects():
    """Get all approved projects"""
    projects = Project.query.filter_by(is_approved=True).order_by(Project.created_at.desc()).all()
    return jsonify([p.to_dict() for p in projects]), 200


@app.route('/api/events', methods=['GET'])
def get_events():
    """Get all events"""
    events = Event.query.filter_by(is_active=True).order_by(Event.event_date).all()
    return jsonify([e.to_dict() for e in events]), 200


@app.route('/api/toppers', methods=['GET'])
def get_toppers():
    """Get academic toppers"""
    toppers = Topper.query.filter_by(is_active=True).order_by(Topper.academic_year.desc(), Topper.cgpa.desc()).all()
    return jsonify([t.to_dict() for t in toppers]), 200


@app.route('/api/contact', methods=['GET'])
def get_contact():
    """Get contact information"""
    info = DepartmentInfo.query.get(1)
    if not info:
        return jsonify({
            'address': 'University Campus, Tech City',
            'phone': '+91-123-456-7890',
            'email': 'cse.department@university.edu',
            'hours': 'Mon-Fri: 9:00 AM - 5:00 PM'
        }), 200
    
    return jsonify({
        'address': info.address,
        'phone': info.phone,
        'email': info.email,
        'hours': info.office_hours
    }), 200


@app.route('/api/contact/submit', methods=['POST'])
def submit_contact():
    """Submit contact form"""
    data = request.get_json()
    
    required_fields = ['name', 'email', 'subject', 'message']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    # Validate email
    if not validate_email(data['email']):
        return jsonify({'message': 'Invalid email format'}), 400
    
    message = ContactMessage(
        name=data['name'].strip(),
        email=data['email'].lower().strip(),
        subject=data['subject'].strip(),
        message=data['message'].strip()
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Send notification to admin
    admin_email = app.config['MAIL_USERNAME']
    if admin_email:
        try:
            msg = Message(
                subject=f"New Contact Message: {message.subject}",
                recipients=[admin_email],
                html=f"""
                <h3>New Contact Message</h3>
                <p><strong>Name:</strong> {message.name}</p>
                <p><strong>Email:</strong> {message.email}</p>
                <p><strong>Subject:</strong> {message.subject}</p>
                <p><strong>Message:</strong></p>
                <p>{message.message}</p>
                """
            )
            mail.send(msg)
        except Exception as e:
            print(f"Admin notification error: {e}")
    
    return jsonify({'message': 'Message sent successfully'}), 201


# ==================== STUDENT API ROUTES ====================

@app.route('/api/student/dashboard', methods=['GET'])
@student_required
def student_dashboard(current_user):
    """Get student dashboard data"""
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    # Get recent activities
    activities = []
    
    # Recent project submissions
    recent_projects = Project.query.filter_by(student_id=student.id).order_by(Project.created_at.desc()).limit(3).all()
    for project in recent_projects:
        activities.append({
            'id': project.id,
            'title': 'Project Submitted',
            'description': f'Project "{project.title}" submitted',
            'date': project.created_at.strftime('%Y-%m-%d') if project.created_at else None,
            'icon': 'fa-project-diagram'
        })
    
    # Event registrations
    registrations = EventRegistration.query.filter_by(user_id=current_user.id).order_by(EventRegistration.created_at.desc()).limit(3).all()
    for reg in registrations:
        event = reg.event
        if event:
            activities.append({
                'id': reg.id,
                'title': 'Event Registered',
                'description': f'Registered for "{event.title}"',
                'date': reg.created_at.strftime('%Y-%m-%d') if reg.created_at else None,
                'icon': 'fa-calendar-check'
            })
    
    # Upcoming events (registered)
    today = datetime.now().date()
    upcoming_events = db.session.query(Event).join(
        EventRegistration, Event.id == EventRegistration.event_id
    ).filter(
        EventRegistration.user_id == current_user.id,
        Event.event_date >= today,
        Event.is_active == True
    ).order_by(Event.event_date).limit(5).all()
    
    events_data = []
    for event in upcoming_events:
        events_data.append({
            'id': event.id,
            'title': event.title,
            'date': event.event_date.isoformat() if event.event_date else None,
            'time': event.event_time,
            'location': event.location
        })
    
    # Get achievements
    achievements = Achievement.query.filter_by(student_id=student.id).order_by(Achievement.created_at.desc()).limit(3).all()
    for ach in achievements:
        activities.append({
            'id': ach.id,
            'title': 'Achievement',
            'description': ach.title,
            'date': ach.date.strftime('%Y-%m-%d') if ach.date else None,
            'icon': 'fa-trophy'
        })
    
    return jsonify({
        'cgpa': student.cgpa if student.cgpa else 'N/A',
        'attendance': student.attendance if student.attendance else 0,
        'projects': Project.query.filter_by(student_id=student.id).count(),
        'events': EventRegistration.query.filter_by(user_id=current_user.id).count(),
        'activities': activities,
        'upcomingEvents': events_data
    }), 200


@app.route('/api/student/profile', methods=['GET'])
@student_required
def student_profile(current_user):
    """Get student profile"""
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    profile_data = current_user.to_dict(include_private=True)
    profile_data.update(student.to_dict())
    
    # Add achievements
    achievements = Achievement.query.filter_by(student_id=student.id).order_by(Achievement.created_at.desc()).all()
    profile_data['achievements'] = [a.to_dict() for a in achievements]
    
    return jsonify(profile_data), 200


@app.route('/api/student/profile', methods=['PUT'])
@student_required
def update_student_profile(current_user):
    """Update student profile"""
    data = request.get_json()
    
    # Update user fields
    if data.get('fullName'):
        current_user.full_name = data['fullName'].strip()
    if data.get('phone'):
        if not validate_phone(data['phone']):
            return jsonify({'message': 'Invalid phone number format'}), 400
        current_user.phone = data['phone']
    if data.get('gender'):
        current_user.gender = data['gender']
    if data.get('address'):
        current_user.address = data['address']
    if data.get('dateOfBirth'):
        try:
            current_user.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    # Update student fields
    student = Student.query.filter_by(user_id=current_user.id).first()
    if student:
        if data.get('course'):
            student.course = data['course']
        if data.get('year'):
            try:
                student.year = int(data['year'])
            except:
                return jsonify({'message': 'Year must be a number'}), 400
        if data.get('semester'):
            try:
                student.semester = int(data['semester'])
            except:
                return jsonify({'message': 'Semester must be a number'}), 400
        if data.get('caste'):
            student.caste = data['caste']
    
    # Handle avatar update
    if data.get('avatar') and data['avatar'].startswith('data:image'):
        try:
            avatar_url = process_and_upload_image(
                data['avatar'],
                'profiles',
                f"user_{current_user.email.split('@')[0]}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            if avatar_url:
                current_user.avatar = avatar_url
        except Exception as e:
            print(f"Avatar update error: {e}")
    
    db.session.commit()
    
    log_activity(current_user.id, 'profile_updated', 'user', current_user.id)
    
    return jsonify({'message': 'Profile updated successfully'}), 200


@app.route('/api/student/projects', methods=['GET'])
@student_required
def student_projects(current_user):
    """Get student's projects"""
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    projects = Project.query.filter_by(student_id=student.id).order_by(Project.created_at.desc()).all()
    
    return jsonify([p.to_dict() for p in projects]), 200


@app.route('/api/student/projects', methods=['POST'])
@student_required
def create_student_project(current_user):
    """Create new project"""
    data = request.get_json()
    
    required_fields = ['title', 'description', 'category']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    # Handle project image
    project_image = None
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            project_image = process_and_upload_image(
                data['image'],
                'projects',
                f"project_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            )
        except Exception as e:
            print(f"Project image upload error: {e}")
    
    project = Project(
        title=data['title'].strip(),
        description=data['description'].strip(),
        category=data['category'],
        image=project_image or data.get('image'),
        technologies=data.get('technologies', []),
        github=data.get('github'),
        demo=data.get('demo'),
        student_id=student.id,
        is_approved=False  # Requires admin approval
    )
    
    db.session.add(project)
    db.session.commit()
    
    log_activity(current_user.id, 'project_created', 'project', project.id, {'title': project.title})
    
    return jsonify({
        'message': 'Project created successfully. Pending approval.',
        'project': project.to_dict()
    }), 201


@app.route('/api/student/events/register/<event_id>', methods=['POST'])
@student_required
def register_for_event(current_user, event_id):
    """Register for an event"""
    event = Event.query.get(event_id)
    
    if not event:
        return jsonify({'message': 'Event not found'}), 404
    
    if not event.is_active:
        return jsonify({'message': 'Event is not active'}), 400
    
    # Check if already registered
    existing = EventRegistration.query.filter_by(event_id=event_id, user_id=current_user.id).first()
    if existing:
        return jsonify({'message': 'Already registered for this event'}), 400
    
    # Check max participants
    if event.max_participants and event.current_participants >= event.max_participants:
        return jsonify({'message': 'Event is full'}), 400
    
    # Check registration deadline
    if event.registration_deadline and datetime.now().date() > event.registration_deadline:
        return jsonify({'message': 'Registration deadline has passed'}), 400
    
    registration = EventRegistration(
        event_id=event_id,
        user_id=current_user.id,
        name=current_user.full_name,
        email=current_user.email,
        phone=current_user.phone
    )
    
    event.current_participants += 1
    
    db.session.add(registration)
    db.session.commit()
    
    # Send confirmation email - FIXED: Generate HTML first, then send
    event_date_str = event.event_date.strftime('%B %d, %Y') if event.event_date else 'TBD'
    event_email_html = get_event_notification_email(
        current_user.full_name,
        event.title,
        event_date_str,
        event.event_time,
        event.location
    )
    send_email(
        current_user.email,
        f'Registration Confirmed: {event.title}',
        event_email_html
    )
    
    log_activity(current_user.id, 'event_registered', 'event', event_id, {'event_title': event.title})
    
    return jsonify({'message': 'Successfully registered for event'}), 200


@app.route('/api/student/events/my-events', methods=['GET'])
@student_required
def my_events(current_user):
    """Get events registered by student"""
    registrations = EventRegistration.query.filter_by(
        user_id=current_user.id
    ).order_by(EventRegistration.created_at.desc()).all()
    
    events_data = []
    for reg in registrations:
        event = reg.event
        if event:
            events_data.append({
                'id': event.id,
                'title': event.title,
                'date': event.event_date.isoformat() if event.event_date else None,
                'time': event.event_time,
                'location': event.location,
                'status': reg.status,
                'registeredAt': reg.created_at.isoformat() if reg.created_at else None
            })
    
    return jsonify(events_data), 200


@app.route('/api/student/achievements', methods=['GET'])
@student_required
def student_achievements(current_user):
    """Get student achievements"""
    student = Student.query.filter_by(user_id=current_user.id).first()
    
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    achievements = Achievement.query.filter_by(student_id=student.id).order_by(Achievement.created_at.desc()).all()
    
    return jsonify([a.to_dict() for a in achievements]), 200


@app.route('/api/student/achievements', methods=['POST'])
@student_required
def add_student_achievement(current_user):
    """Add new achievement"""
    data = request.get_json()
    
    if not data.get('title'):
        return jsonify({'message': 'Achievement title is required'}), 400
    
    student = Student.query.filter_by(user_id=current_user.id).first()
    if not student:
        return jsonify({'message': 'Student profile not found'}), 404
    
    achievement = Achievement(
        student_id=student.id,
        title=data['title'].strip(),
        description=data.get('description'),
        category=data.get('category'),
        date=datetime.strptime(data['date'], '%Y-%m-%d').date() if data.get('date') else None
    )
    
    db.session.add(achievement)
    db.session.commit()
    
    log_activity(current_user.id, 'achievement_added', 'achievement', achievement.id)
    
    return jsonify({
        'message': 'Achievement added successfully',
        'achievement': achievement.to_dict()
    }), 201


# ==================== TEACHER API ROUTES ====================

@app.route('/api/faculty/dashboard', methods=['GET'])
@teacher_required
def faculty_dashboard(current_user):
    """Get faculty dashboard data"""
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    if not teacher:
        return jsonify({'message': 'Teacher profile not found'}), 404
    
    # Count students (total)
    students_count = User.query.filter_by(role='student', is_verified=True, is_active=True).count()
    
    # Count projects supervised
    projects_count = Project.query.filter_by(teacher_id=teacher.id).count()
    
    # Count publications
    publications_count = Publication.query.filter_by(teacher_id=teacher.id).count()
    
    # Recent activities
    activities = []
    
    # Recent publications
    recent_pubs = Publication.query.filter_by(teacher_id=teacher.id).order_by(Publication.created_at.desc()).limit(3).all()
    for pub in recent_pubs:
        activities.append({
            'id': pub.id,
            'title': 'Publication Added',
            'description': f'"{pub.title}" published',
            'date': pub.created_at.strftime('%Y-%m-%d') if pub.created_at else None,
            'icon': 'fa-book'
        })
    
    # Recent projects under supervision
    recent_projects = Project.query.filter_by(teacher_id=teacher.id).order_by(Project.created_at.desc()).limit(3).all()
    for proj in recent_projects:
        activities.append({
            'id': proj.id,
            'title': 'Project Supervision',
            'description': f'Project "{proj.title}" submitted',
            'date': proj.created_at.strftime('%Y-%m-%d') if proj.created_at else None,
            'icon': 'fa-project-diagram'
        })
    
    return jsonify({
        'courses': 0,  # Placeholder - can be expanded with actual courses
        'students': students_count,
        'projects': projects_count,
        'publications': publications_count,
        'activities': activities
    }), 200


@app.route('/api/faculty/profile', methods=['GET'])
@teacher_required
def faculty_profile(current_user):
    """Get faculty profile"""
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    if not teacher:
        return jsonify({'message': 'Teacher profile not found'}), 404
    
    profile_data = current_user.to_dict(include_private=True)
    profile_data.update(teacher.to_dict())
    
    # Add publications
    publications = Publication.query.filter_by(teacher_id=teacher.id).order_by(Publication.created_at.desc()).all()
    profile_data['publications'] = [p.to_dict() for p in publications]
    
    return jsonify(profile_data), 200


@app.route('/api/faculty/profile', methods=['PUT'])
@teacher_required
def update_faculty_profile(current_user):
    """Update faculty profile"""
    data = request.get_json()
    
    # Update user fields
    if data.get('fullName'):
        current_user.full_name = data['fullName'].strip()
    if data.get('phone'):
        if not validate_phone(data['phone']):
            return jsonify({'message': 'Invalid phone number format'}), 400
        current_user.phone = data['phone']
    if data.get('dateOfBirth'):
        try:
            current_user.date_of_birth = datetime.strptime(data['dateOfBirth'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    # Update teacher fields
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if teacher:
        if data.get('designation'):
            teacher.designation = data['designation']
        if data.get('qualification'):
            teacher.qualification = data['qualification']
        if data.get('experience'):
            try:
                teacher.experience_years = int(data['experience'])
            except:
                return jsonify({'message': 'Experience must be a number'}), 400
        if data.get('specialization'):
            teacher.specialization = data['specialization']
        if data.get('researchInterests'):
            teacher.research_interests = data['researchInterests']
        if data.get('bio'):
            teacher.bio = data['bio']
        if data.get('office'):
            teacher.office = data['office']
        if data.get('officeHours'):
            teacher.office_hours = data['officeHours']
        if data.get('linkedin'):
            teacher.linkedin = data['linkedin']
        if data.get('googleScholar'):
            teacher.google_scholar = data['googleScholar']
        
        # Update faculty listing
        faculty = Faculty.query.filter_by(teacher_id=teacher.id).first()
        if faculty:
            faculty.name = current_user.full_name
            faculty.designation = teacher.designation
            faculty.qualification = teacher.qualification
            faculty.bio = teacher.bio
            faculty.expertise = data.get('expertise', [])
            if data.get('linkedin'):
                faculty.linkedin = data['linkedin']
    
    # Handle avatar update
    if data.get('avatar') and data['avatar'].startswith('data:image'):
        try:
            avatar_url = process_and_upload_image(
                data['avatar'],
                'profiles',
                f"faculty_{current_user.email.split('@')[0]}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            if avatar_url:
                current_user.avatar = avatar_url
                
                # Update faculty image
                faculty = Faculty.query.filter_by(teacher_id=teacher.id).first()
                if faculty:
                    faculty.image = avatar_url
        except Exception as e:
            print(f"Avatar update error: {e}")
    
    db.session.commit()
    
    log_activity(current_user.id, 'profile_updated', 'user', current_user.id)
    
    return jsonify({'message': 'Profile updated successfully'}), 200


@app.route('/api/faculty/students', methods=['GET'])
@teacher_required
def faculty_students(current_user):
    """Get list of students (for faculty)"""
    # Get filter parameters
    course = request.args.get('course')
    year = request.args.get('year')
    
    query = db.session.query(User, Student).join(
        Student, User.id == Student.user_id
    ).filter(
        User.role == 'student',
        User.is_verified == True,
        User.is_active == True,
        User.is_deleted == False
    )
    
    if course:
        query = query.filter(Student.course == course)
    if year:
        query = query.filter(Student.year == int(year))
    
    results = query.order_by(User.full_name).all()
    
    students_data = []
    for user, student in results:
        students_data.append({
            'id': user.id,
            'name': user.full_name,
            'email': user.email,
            'registrationNo': student.registration_no,
            'course': student.course,
            'year': student.year,
            'semester': student.semester,
            'cgpa': student.cgpa,
            'attendance': student.attendance,
            'avatar': user.avatar
        })
    
    return jsonify(students_data), 200


@app.route('/api/faculty/projects', methods=['GET'])
@teacher_required
def faculty_projects(current_user):
    """Get projects supervised by faculty"""
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    if not teacher:
        return jsonify([]), 200
    
    projects = Project.query.filter_by(teacher_id=teacher.id).order_by(Project.created_at.desc()).all()
    
    return jsonify([p.to_dict() for p in projects]), 200


@app.route('/api/faculty/projects', methods=['POST'])
@teacher_required
def create_faculty_project(current_user):
    """Create new project (as supervisor)"""
    data = request.get_json()
    
    required_fields = ['title', 'description', 'category']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        return jsonify({'message': 'Teacher profile not found'}), 404
    
    # Handle project image
    project_image = None
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            project_image = process_and_upload_image(
                data['image'],
                'projects',
                f"project_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            )
        except Exception as e:
            print(f"Project image upload error: {e}")
    
    project = Project(
        title=data['title'].strip(),
        description=data['description'].strip(),
        category=data['category'],
        image=project_image or data.get('image'),
        technologies=data.get('technologies', []),
        github=data.get('github'),
        demo=data.get('demo'),
        teacher_id=teacher.id,
        is_approved=True  # Faculty projects are auto-approved
    )
    
    db.session.add(project)
    db.session.commit()
    
    log_activity(current_user.id, 'project_created', 'project', project.id, {'title': project.title})
    
    return jsonify({
        'message': 'Project created successfully',
        'project': project.to_dict()
    }), 201


@app.route('/api/faculty/publications', methods=['GET'])
@teacher_required
def faculty_publications(current_user):
    """Get faculty publications"""
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    
    if not teacher:
        return jsonify([]), 200
    
    publications = Publication.query.filter_by(teacher_id=teacher.id).order_by(Publication.created_at.desc()).all()
    
    return jsonify([p.to_dict() for p in publications]), 200


@app.route('/api/faculty/publications', methods=['POST'])
@teacher_required
def add_publication(current_user):
    """Add new publication"""
    data = request.get_json()
    
    required_fields = ['title', 'authors']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        return jsonify({'message': 'Teacher profile not found'}), 404
    
    publication = Publication(
        teacher_id=teacher.id,
        title=data['title'].strip(),
        authors=data['authors'].strip(),
        journal=data.get('journal'),
        year=int(data['year']) if data.get('year') else None,
        doi=data.get('doi'),
        link=data.get('link')
    )
    
    db.session.add(publication)
    db.session.commit()
    
    log_activity(current_user.id, 'publication_added', 'publication', publication.id)
    
    return jsonify({
        'message': 'Publication added successfully',
        'publication': publication.to_dict()
    }), 201


# ==================== ADMIN API ROUTES ====================

@app.route('/api/admin/dashboard', methods=['GET'])
@admin_required
def admin_dashboard(current_user):
    """Get admin dashboard data"""
    # Get counts
    total_students = User.query.filter_by(role='student', is_deleted=False).count()
    total_teachers = User.query.filter_by(role='teacher', is_deleted=False).count()
    total_users = User.query.filter_by(is_deleted=False).count()
    verified_users = User.query.filter_by(is_verified=True, is_deleted=False).count()
    active_users = User.query.filter_by(is_active=True, is_deleted=False).count()
    
    total_projects = Project.query.count()
    approved_projects = Project.query.filter_by(is_approved=True).count()
    pending_projects = Project.query.filter_by(is_approved=False).count()
    
    total_events = Event.query.count()
    upcoming_events = Event.query.filter(Event.event_date >= datetime.now().date()).count()
    
    unread_messages = ContactMessage.query.filter_by(is_read=False).count()
    
    # Recent students
    recent_students = db.session.query(User, Student).join(
        Student, User.id == Student.user_id
    ).filter(
        User.role == 'student',
        User.is_deleted == False
    ).order_by(
        User.created_at.desc()
    ).limit(5).all()
    
    recent_students_data = []
    for user, student in recent_students:
        recent_students_data.append({
            'id': user.id,
            'name': user.full_name,
            'email': user.email,
            'registrationNo': student.registration_no,
            'course': student.course,
            'joined': user.created_at.strftime('%Y-%m-%d') if user.created_at else None
        })
    
    # Recent activities
    recent_activities = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(10).all()
    activities_data = []
    for activity in recent_activities:
        user = User.query.get(activity.user_id) if activity.user_id else None
        activities_data.append({
            'id': activity.id,
            'user': user.full_name if user else 'System',
            'action': activity.action,
            'entityType': activity.entity_type,
            'createdAt': activity.created_at.isoformat() if activity.created_at else None
        })
    
    return jsonify({
        'stats': {
            'totalStudents': total_students,
            'totalTeachers': total_teachers,
            'totalUsers': total_users,
            'verifiedUsers': verified_users,
            'activeUsers': active_users,
            'totalProjects': total_projects,
            'approvedProjects': approved_projects,
            'pendingProjects': pending_projects,
            'totalEvents': total_events,
            'upcomingEvents': upcoming_events,
            'unreadMessages': unread_messages
        },
        'recentStudents': recent_students_data,
        'recentActivities': activities_data
    }), 200


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_users(current_user):
    """Get all users for admin"""
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Filters
    role = request.args.get('role')
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = User.query.filter_by(is_deleted=False)
    
    if role:
        query = query.filter_by(role=role)
    if status == 'verified':
        query = query.filter_by(is_verified=True)
    elif status == 'unverified':
        query = query.filter_by(is_verified=False)
    elif status == 'active':
        query = query.filter_by(is_active=True)
    elif status == 'inactive':
        query = query.filter_by(is_active=False)
    
    if search:
        query = query.filter(
            (User.full_name.ilike(f'%{search}%')) |
            (User.email.ilike(f'%{search}%'))
        )
    
    paginated = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    users_data = []
    for user in paginated.items:
        user_dict = user.to_dict()
        
        # Add role-specific info
        if user.role == 'student':
            student = Student.query.filter_by(user_id=user.id).first()
            if student:
                user_dict['registrationNo'] = student.registration_no
                user_dict['course'] = student.course
                user_dict['year'] = student.year
        elif user.role == 'teacher':
            teacher = Teacher.query.filter_by(user_id=user.id).first()
            if teacher:
                user_dict['employeeId'] = teacher.employee_id
                user_dict['designation'] = teacher.designation
        
        users_data.append(user_dict)
    
    return jsonify({
        'users': users_data,
        'total': paginated.total,
        'pages': paginated.pages,
        'currentPage': page
    }), 200


@app.route('/api/admin/users/<user_id>', methods=['GET'])
@admin_required
def get_user_detail(current_user, user_id):
    """Get detailed user information"""
    user = User.query.filter_by(id=user_id, is_deleted=False).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user_dict = user.to_dict(include_private=True)
    
    # Add role-specific details
    if user.role == 'student':
        student = Student.query.filter_by(user_id=user.id).first()
        if student:
            user_dict['studentProfile'] = student.to_dict()
            user_dict['projects'] = [p.to_dict() for p in Project.query.filter_by(student_id=student.id).all()]
            user_dict['achievements'] = [a.to_dict() for a in Achievement.query.filter_by(student_id=student.id).all()]
    
    elif user.role == 'teacher':
        teacher = Teacher.query.filter_by(user_id=user.id).first()
        if teacher:
            user_dict['teacherProfile'] = teacher.to_dict()
            user_dict['projects'] = [p.to_dict() for p in Project.query.filter_by(teacher_id=teacher.id).all()]
            user_dict['publications'] = [p.to_dict() for p in Publication.query.filter_by(teacher_id=teacher.id).all()]
    
    # Activity log
    activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.created_at.desc()).limit(20).all()
    user_dict['recentActivities'] = [{
        'action': a.action,
        'entityType': a.entity_type,
        'createdAt': a.created_at.isoformat() if a.created_at else None
    } for a in activities]
    
    return jsonify(user_dict), 200


@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(current_user, user_id):
    """Update user (admin)"""
    user = User.query.filter_by(id=user_id, is_deleted=False).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update basic fields
    if data.get('fullName'):
        user.full_name = data['fullName'].strip()
    if data.get('email'):
        new_email = data['email'].lower().strip()
        if new_email != user.email:
            existing = User.query.filter_by(email=new_email, is_deleted=False).first()
            if existing:
                return jsonify({'message': 'Email already in use'}), 400
            user.email = new_email
    if data.get('phone'):
        user.phone = data['phone']
    if data.get('gender'):
        user.gender = data['gender']
    if 'isActive' in data:
        user.is_active = data['isActive']
    if 'isVerified' in data:
        user.is_verified = data['isVerified']
    
    db.session.commit()
    
    log_activity(current_user.id, 'user_updated', 'user', user_id)
    
    return jsonify({'message': 'User updated successfully'}), 200


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    """Soft delete a user"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if user.id == current_user.id:
        return jsonify({'message': 'Cannot delete yourself'}), 400
    
    # Soft delete
    user.is_deleted = True
    user.is_active = False
    
    db.session.commit()
    
    log_activity(current_user.id, 'user_deleted', 'user', user_id, {'email': user.email})
    
    return jsonify({'message': 'User deleted successfully'}), 200


@app.route('/api/admin/faculty-members', methods=['GET'])
@admin_required
def admin_faculty_members(current_user):
    """Get all faculty members for admin"""
    faculty = Faculty.query.order_by(Faculty.display_order).all()
    return jsonify([f.to_dict() for f in faculty]), 200


@app.route('/api/admin/faculty-members', methods=['POST'])
@admin_required
def create_faculty_member(current_user):
    """Create new faculty member"""
    data = request.get_json()
    
    required_fields = ['name', 'designation', 'qualification']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    faculty = Faculty(
        name=data['name'].strip(),
        designation=data['designation'].strip(),
        qualification=data['qualification'].strip(),
        expertise=data.get('expertise', []),
        email=data.get('email'),
        linkedin=data.get('linkedin'),
        bio=data.get('bio'),
        display_order=data.get('displayOrder', 0)
    )
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'faculty',
                f"faculty_{data['name'].replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            faculty.image = image_url
        except Exception as e:
            print(f"Faculty image upload error: {e}")
    
    db.session.add(faculty)
    db.session.commit()
    
    log_activity(current_user.id, 'faculty_created', 'faculty', faculty.id)
    
    return jsonify({
        'message': 'Faculty member created successfully',
        'faculty': faculty.to_dict()
    }), 201


@app.route('/api/admin/faculty-members/<faculty_id>', methods=['PUT'])
@admin_required
def update_faculty_member(current_user, faculty_id):
    """Update faculty member"""
    faculty = Faculty.query.get(faculty_id)
    
    if not faculty:
        return jsonify({'message': 'Faculty member not found'}), 404
    
    data = request.get_json()
    
    if data.get('name'):
        faculty.name = data['name'].strip()
    if data.get('designation'):
        faculty.designation = data['designation'].strip()
    if data.get('qualification'):
        faculty.qualification = data['qualification'].strip()
    if data.get('expertise'):
        faculty.expertise = data['expertise']
    if data.get('email'):
        faculty.email = data['email']
    if data.get('linkedin'):
        faculty.linkedin = data['linkedin']
    if data.get('bio'):
        faculty.bio = data['bio']
    if data.get('displayOrder'):
        faculty.display_order = data['displayOrder']
    if 'isActive' in data:
        faculty.is_active = data['isActive']
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'faculty',
                f"faculty_{faculty.name.replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            faculty.image = image_url
        except Exception as e:
            print(f"Faculty image upload error: {e}")
    
    db.session.commit()
    
    log_activity(current_user.id, 'faculty_updated', 'faculty', faculty_id)
    
    return jsonify({'message': 'Faculty member updated successfully'}), 200


@app.route('/api/admin/faculty-members/<faculty_id>', methods=['DELETE'])
@admin_required
def delete_faculty(current_user, faculty_id):
    """Delete faculty member"""
    faculty = Faculty.query.get(faculty_id)
    
    if not faculty:
        return jsonify({'message': 'Faculty member not found'}), 404
    
    db.session.delete(faculty)
    db.session.commit()
    
    log_activity(current_user.id, 'faculty_deleted', 'faculty', faculty_id, {'name': faculty.name})
    
    return jsonify({'message': 'Faculty member deleted successfully'}), 200


@app.route('/api/admin/programs', methods=['GET'])
@admin_required
def admin_programs(current_user):
    """Get all programs for admin"""
    programs = Program.query.order_by(Program.name).all()
    return jsonify([p.to_dict() for p in programs]), 200


@app.route('/api/admin/programs', methods=['POST'])
@admin_required
def create_program(current_user):
    """Create new program"""
    data = request.get_json()
    
    required_fields = ['name', 'code', 'duration', 'seats']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    # Check if code exists
    existing = Program.query.filter_by(code=data['code']).first()
    if existing:
        return jsonify({'message': 'Program code already exists'}), 400
    
    program = Program(
        name=data['name'].strip(),
        code=data['code'].strip().upper(),
        description=data.get('description'),
        duration=data['duration'],
        seats=int(data['seats']),
        icon=data.get('icon', 'fa-laptop-code'),
        highlights=data.get('highlights', [])
    )
    
    db.session.add(program)
    db.session.commit()
    
    log_activity(current_user.id, 'program_created', 'program', program.id)
    
    return jsonify({
        'message': 'Program created successfully',
        'program': program.to_dict()
    }), 201


@app.route('/api/admin/programs/<program_id>', methods=['PUT'])
@admin_required
def update_program(current_user, program_id):
    """Update program"""
    program = Program.query.get(program_id)
    
    if not program:
        return jsonify({'message': 'Program not found'}), 404
    
    data = request.get_json()
    
    if data.get('name'):
        program.name = data['name'].strip()
    if data.get('code') and data['code'] != program.code:
        existing = Program.query.filter_by(code=data['code']).first()
        if existing and existing.id != program_id:
            return jsonify({'message': 'Program code already exists'}), 400
        program.code = data['code'].strip().upper()
    if data.get('description'):
        program.description = data['description']
    if data.get('duration'):
        program.duration = data['duration']
    if data.get('seats'):
        program.seats = int(data['seats'])
    if data.get('icon'):
        program.icon = data['icon']
    if data.get('highlights'):
        program.highlights = data['highlights']
    if 'isActive' in data:
        program.is_active = data['isActive']
    
    db.session.commit()
    
    log_activity(current_user.id, 'program_updated', 'program', program_id)
    
    return jsonify({'message': 'Program updated successfully'}), 200


@app.route('/api/admin/programs/<program_id>', methods=['DELETE'])
@admin_required
def delete_program(current_user, program_id):
    """Delete program"""
    program = Program.query.get(program_id)
    
    if not program:
        return jsonify({'message': 'Program not found'}), 404
    
    db.session.delete(program)
    db.session.commit()
    
    log_activity(current_user.id, 'program_deleted', 'program', program_id, {'name': program.name})
    
    return jsonify({'message': 'Program deleted successfully'}), 200


@app.route('/api/admin/projects', methods=['GET'])
@admin_required
def admin_projects(current_user):
    """Get all projects for admin"""
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Filters
    status = request.args.get('status')  # approved, pending, featured
    category = request.args.get('category')
    
    query = Project.query
    
    if status == 'approved':
        query = query.filter_by(is_approved=True)
    elif status == 'pending':
        query = query.filter_by(is_approved=False)
    elif status == 'featured':
        query = query.filter_by(is_featured=True)
    
    if category:
        query = query.filter_by(category=category)
    
    paginated = query.order_by(Project.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    projects_data = []
    for project in paginated.items:
        proj_dict = project.to_dict()
        # Add student/teacher info
        if project.student_id:
            student = Student.query.get(project.student_id)
            if student and student.user:
                proj_dict['submittedBy'] = {
                    'id': student.user.id,
                    'name': student.user.full_name,
                    'type': 'student'
                }
        elif project.teacher_id:
            teacher = Teacher.query.get(project.teacher_id)
            if teacher and teacher.user:
                proj_dict['submittedBy'] = {
                    'id': teacher.user.id,
                    'name': teacher.user.full_name,
                    'type': 'teacher'
                }
        projects_data.append(proj_dict)
    
    return jsonify({
        'projects': projects_data,
        'total': paginated.total,
        'pages': paginated.pages,
        'currentPage': page
    }), 200


@app.route('/api/admin/projects/<project_id>/approve', methods=['PUT'])
@admin_required
def approve_project(current_user, project_id):
    """Approve project"""
    project = Project.query.get(project_id)
    
    if not project:
        return jsonify({'message': 'Project not found'}), 404
    
    project.is_approved = True
    db.session.commit()
    
    log_activity(current_user.id, 'project_approved', 'project', project_id)
    
    return jsonify({'message': 'Project approved successfully'}), 200


@app.route('/api/admin/projects/<project_id>/feature', methods=['PUT'])
@admin_required
def feature_project(current_user, project_id):
    """Toggle featured status"""
    project = Project.query.get(project_id)
    
    if not project:
        return jsonify({'message': 'Project not found'}), 404
    
    project.is_featured = not project.is_featured
    db.session.commit()
    
    log_activity(current_user.id, 'project_featured_toggled', 'project', project_id)
    
    return jsonify({'message': f'Project {"featured" if project.is_featured else "unfeatured"} successfully'}), 200


@app.route('/api/admin/projects/<project_id>', methods=['DELETE'])
@admin_required
def delete_project(current_user, project_id):
    """Delete project"""
    project = Project.query.get(project_id)
    
    if not project:
        return jsonify({'message': 'Project not found'}), 404
    
    db.session.delete(project)
    db.session.commit()
    
    log_activity(current_user.id, 'project_deleted', 'project', project_id, {'title': project.title})
    
    return jsonify({'message': 'Project deleted successfully'}), 200


@app.route('/api/admin/events', methods=['GET'])
@admin_required
def admin_events(current_user):
    """Get all events for admin"""
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Filters
    event_type = request.args.get('type')
    status = request.args.get('status')  # upcoming, past, active
    
    query = Event.query
    
    if event_type:
        query = query.filter_by(event_type=event_type)
    
    today = datetime.now().date()
    if status == 'upcoming':
        query = query.filter(Event.event_date >= today)
    elif status == 'past':
        query = query.filter(Event.event_date < today)
    elif status == 'active':
        query = query.filter_by(is_active=True)
    
    paginated = query.order_by(Event.event_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'events': [e.to_dict() for e in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'currentPage': page
    }), 200


@app.route('/api/admin/events', methods=['POST'])
@admin_required
def create_event(current_user):
    """Create new event"""
    data = request.get_json()
    
    required_fields = ['title', 'description', 'event_type', 'event_date', 'event_time', 'location']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    try:
        event_date = datetime.strptime(data['event_date'], '%Y-%m-%d').date()
    except:
        return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
    
    event_end_date = None
    if data.get('event_end_date'):
        try:
            event_end_date = datetime.strptime(data['event_end_date'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid end date format. Use YYYY-MM-DD'}), 400
    
    registration_deadline = None
    if data.get('registration_deadline'):
        try:
            registration_deadline = datetime.strptime(data['registration_deadline'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid deadline format. Use YYYY-MM-DD'}), 400
    
    event = Event(
        title=data['title'].strip(),
        description=data['description'].strip(),
        event_type=data['event_type'],
        event_date=event_date,
        event_time=data['event_time'],
        event_end_date=event_end_date,
        event_end_time=data.get('event_end_time'),
        location=data['location'].strip(),
        max_participants=int(data['max_participants']) if data.get('max_participants') else None,
        registration_deadline=registration_deadline,
        organizer=data.get('organizer'),
        contact_email=data.get('contact_email'),
        contact_phone=data.get('contact_phone'),
        link=data.get('link')
    )
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'events',
                f"event_{data['title'].replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            event.image = image_url
        except Exception as e:
            print(f"Event image upload error: {e}")
    
    db.session.add(event)
    db.session.commit()
    
    log_activity(current_user.id, 'event_created', 'event', event.id)
    
    return jsonify({
        'message': 'Event created successfully',
        'event': event.to_dict()
    }), 201


@app.route('/api/admin/events/<event_id>', methods=['PUT'])
@admin_required
def update_event(current_user, event_id):
    """Update event"""
    event = Event.query.get(event_id)
    
    if not event:
        return jsonify({'message': 'Event not found'}), 404
    
    data = request.get_json()
    
    if data.get('title'):
        event.title = data['title'].strip()
    if data.get('description'):
        event.description = data['description'].strip()
    if data.get('event_type'):
        event.event_type = data['event_type']
    if data.get('event_date'):
        try:
            event.event_date = datetime.strptime(data['event_date'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
    if data.get('event_time'):
        event.event_time = data['event_time']
    if data.get('event_end_date'):
        try:
            event.event_end_date = datetime.strptime(data['event_end_date'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid end date format. Use YYYY-MM-DD'}), 400
    if data.get('event_end_time'):
        event.event_end_time = data['event_end_time']
    if data.get('location'):
        event.location = data['location'].strip()
    if data.get('max_participants'):
        event.max_participants = int(data['max_participants'])
    if data.get('registration_deadline'):
        try:
            event.registration_deadline = datetime.strptime(data['registration_deadline'], '%Y-%m-%d').date()
        except:
            return jsonify({'message': 'Invalid deadline format. Use YYYY-MM-DD'}), 400
    if data.get('organizer'):
        event.organizer = data['organizer']
    if data.get('contact_email'):
        event.contact_email = data['contact_email']
    if data.get('contact_phone'):
        event.contact_phone = data['contact_phone']
    if data.get('link'):
        event.link = data['link']
    if 'is_active' in data:
        event.is_active = data['is_active']
    if 'is_featured' in data:
        event.is_featured = data['is_featured']
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'events',
                f"event_{event.title.replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            event.image = image_url
        except Exception as e:
            print(f"Event image upload error: {e}")
    
    db.session.commit()
    
    log_activity(current_user.id, 'event_updated', 'event', event_id)
    
    return jsonify({'message': 'Event updated successfully'}), 200


@app.route('/api/admin/events/<event_id>', methods=['DELETE'])
@admin_required
def delete_event(current_user, event_id):
    """Delete event"""
    event = Event.query.get(event_id)
    
    if not event:
        return jsonify({'message': 'Event not found'}), 404
    
    db.session.delete(event)
    db.session.commit()
    
    log_activity(current_user.id, 'event_deleted', 'event', event_id, {'title': event.title})
    
    return jsonify({'message': 'Event deleted successfully'}), 200


@app.route('/api/admin/events/<event_id>/registrations', methods=['GET'])
@admin_required
def get_event_registrations(current_user, event_id):
    """Get registrations for an event"""
    event = Event.query.get(event_id)
    
    if not event:
        return jsonify({'message': 'Event not found'}), 404
    
    registrations = EventRegistration.query.filter_by(event_id=event_id).order_by(EventRegistration.created_at).all()
    
    return jsonify([r.to_dict() for r in registrations]), 200


@app.route('/api/admin/messages', methods=['GET'])
@admin_required
def admin_messages(current_user):
    """Get all contact messages"""
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    # Filters
    unread_only = request.args.get('unread', 'false').lower() == 'true'
    replied_only = request.args.get('replied', 'false').lower() == 'true'
    
    query = ContactMessage.query
    
    if unread_only:
        query = query.filter_by(is_read=False)
    if replied_only:
        query = query.filter_by(is_replied=True)
    
    paginated = query.order_by(ContactMessage.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    unread_count = ContactMessage.query.filter_by(is_read=False).count()
    
    return jsonify({
        'messages': [m.to_dict() for m in paginated.items],
        'unreadCount': unread_count,
        'total': paginated.total,
        'pages': paginated.pages,
        'currentPage': page
    }), 200


@app.route('/api/admin/messages/<message_id>', methods=['GET'])
@admin_required
def get_message(current_user, message_id):
    """Get single message"""
    message = ContactMessage.query.get(message_id)
    
    if not message:
        return jsonify({'message': 'Message not found'}), 404
    
    # Mark as read
    if not message.is_read:
        message.is_read = True
        db.session.commit()
    
    return jsonify(message.to_dict()), 200


@app.route('/api/admin/messages/<message_id>/read', methods=['PUT'])
@admin_required
def mark_message_read(current_user, message_id):
    """Mark message as read"""
    message = ContactMessage.query.get(message_id)
    
    if not message:
        return jsonify({'message': 'Message not found'}), 404
    
    message.is_read = True
    db.session.commit()
    
    return jsonify({'message': 'Message marked as read'}), 200


@app.route('/api/admin/messages/<message_id>/reply', methods=['POST'])
@admin_required
def reply_to_message(current_user, message_id):
    """Reply to message"""
    message = ContactMessage.query.get(message_id)
    
    if not message:
        return jsonify({'message': 'Message not found'}), 404
    
    data = request.get_json()
    
    if not data.get('reply'):
        return jsonify({'message': 'Reply message is required'}), 400
    
    message.is_replied = True
    message.replied_at = datetime.utcnow()
    message.reply_message = data['reply']
    db.session.commit()
    
    # Send reply email
    try:
        msg = Message(
            subject=f"Re: {message.subject} - CSE Department",
            recipients=[message.email],
            html=f"""
            <h3>Hello {message.name},</h3>
            <p>Thank you for contacting the Department of Computer Science & Engineering.</p>
            
            <h4>Your message:</h4>
            <p><em>{message.message}</em></p>
            
            <h4>Our response:</h4>
            <p>{data['reply']}</p>
            
            <p>If you have any further questions, please don't hesitate to contact us.</p>
            
            <p>Best regards,<br>
            CSE Department</p>
            """
        )
        mail.send(msg)
    except Exception as e:
        print(f"Reply email error: {e}")
    
    log_activity(current_user.id, 'message_replied', 'message', message_id)
    
    return jsonify({'message': 'Reply sent successfully'}), 200


@app.route('/api/admin/messages/<message_id>', methods=['DELETE'])
@admin_required
def delete_message(current_user, message_id):
    """Delete message"""
    message = ContactMessage.query.get(message_id)
    
    if not message:
        return jsonify({'message': 'Message not found'}), 404
    
    db.session.delete(message)
    db.session.commit()
    
    log_activity(current_user.id, 'message_deleted', 'message', message_id)
    
    return jsonify({'message': 'Message deleted successfully'}), 200


@app.route('/api/admin/department-info', methods=['GET'])
@admin_required
def get_department_info(current_user):
    """Get department info for admin"""
    info = DepartmentInfo.query.get(1)
    if not info:
        info = DepartmentInfo(id=1)
        db.session.add(info)
        db.session.commit()
    
    return jsonify(info.to_dict()), 200


@app.route('/api/admin/department-info', methods=['PUT'])
@admin_required
def update_department_info(current_user):
    """Update department information"""
    data = request.get_json()
    
    info = DepartmentInfo.query.get(1)
    if not info:
        info = DepartmentInfo(id=1)
        db.session.add(info)
    
    # Update fields
    if data.get('university'):
        info.university = data['university']
    if data.get('department'):
        info.department = data['department']
    if data.get('vision'):
        info.vision = data['vision']
    if data.get('mission'):
        info.mission = data['mission']
    if data.get('description'):
        info.description = data['description']
    if data.get('address'):
        info.address = data['address']
    if data.get('phone'):
        info.phone = data['phone']
    if data.get('email'):
        info.email = data['email']
    if data.get('hours'):
        info.office_hours = data['hours']
    if data.get('facebook'):
        info.facebook = data['facebook']
    if data.get('twitter'):
        info.twitter = data['twitter']
    if data.get('linkedin'):
        info.linkedin = data['linkedin']
    if data.get('youtube'):
        info.youtube = data['youtube']
    if data.get('instagram'):
        info.instagram = data['instagram']
    
    db.session.commit()
    
    log_activity(current_user.id, 'department_info_updated', 'settings', 1)
    
    return jsonify({'message': 'Department information updated successfully'}), 200


@app.route('/api/admin/toppers', methods=['GET'])
@admin_required
def admin_toppers(current_user):
    """Get all toppers for admin"""
    toppers = Topper.query.order_by(Topper.academic_year.desc(), Topper.cgpa.desc()).all()
    return jsonify([t.to_dict() for t in toppers]), 200


@app.route('/api/admin/toppers', methods=['POST'])
@admin_required
def create_topper(current_user):
    """Create new topper entry"""
    data = request.get_json()
    
    required_fields = ['name', 'course', 'year', 'cgpa', 'academicYear']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    topper = Topper(
        name=data['name'].strip(),
        course=data['course'].strip(),
        year=int(data['year']),
        semester=int(data['semester']) if data.get('semester') else None,
        cgpa=float(data['cgpa']),
        achievements=data.get('achievements'),
        linkedin=data.get('linkedin'),
        github=data.get('github'),
        email=data.get('email'),
        academic_year=data['academicYear'].strip()
    )
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'toppers',
                f"topper_{data['name'].replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            topper.image = image_url
        except Exception as e:
            print(f"Topper image upload error: {e}")
    
    db.session.add(topper)
    db.session.commit()
    
    log_activity(current_user.id, 'topper_created', 'topper', topper.id)
    
    return jsonify({
        'message': 'Topper created successfully',
        'topper': topper.to_dict()
    }), 201


@app.route('/api/admin/toppers/<topper_id>', methods=['PUT'])
@admin_required
def update_topper(current_user, topper_id):
    """Update topper entry"""
    topper = Topper.query.get(topper_id)
    
    if not topper:
        return jsonify({'message': 'Topper not found'}), 404
    
    data = request.get_json()
    
    if data.get('name'):
        topper.name = data['name'].strip()
    if data.get('course'):
        topper.course = data['course'].strip()
    if data.get('year'):
        topper.year = int(data['year'])
    if data.get('semester'):
        topper.semester = int(data['semester'])
    if data.get('cgpa'):
        topper.cgpa = float(data['cgpa'])
    if data.get('achievements'):
        topper.achievements = data['achievements']
    if data.get('linkedin'):
        topper.linkedin = data['linkedin']
    if data.get('github'):
        topper.github = data['github']
    if data.get('email'):
        topper.email = data['email']
    if data.get('academicYear'):
        topper.academic_year = data['academicYear'].strip()
    if 'is_active' in data:
        topper.is_active = data['is_active']
    
    # Handle image
    if data.get('image') and data['image'].startswith('data:image'):
        try:
            image_url = process_and_upload_image(
                data['image'],
                'toppers',
                f"topper_{topper.name.replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d')}"
            )
            topper.image = image_url
        except Exception as e:
            print(f"Topper image upload error: {e}")
    
    db.session.commit()
    
    log_activity(current_user.id, 'topper_updated', 'topper', topper_id)
    
    return jsonify({'message': 'Topper updated successfully'}), 200


@app.route('/api/admin/toppers/<topper_id>', methods=['DELETE'])
@admin_required
def delete_topper(current_user, topper_id):
    """Delete topper entry"""
    topper = Topper.query.get(topper_id)
    
    if not topper:
        return jsonify({'message': 'Topper not found'}), 404
    
    db.session.delete(topper)
    db.session.commit()
    
    log_activity(current_user.id, 'topper_deleted', 'topper', topper_id, {'name': topper.name})
    
    return jsonify({'message': 'Topper deleted successfully'}), 200


@app.route('/api/admin/generate-toppers', methods=['POST'])
@admin_required
def generate_toppers(current_user):
    """Generate toppers from student data"""
    data = request.get_json()
    
    academic_year = data.get('academicYear')
    if not academic_year:
        return jsonify({'message': 'Academic year is required'}), 400
    
    # Get top students by CGPA
    top_students = db.session.query(Student).join(User).filter(
        User.is_verified == True,
        User.is_active == True,
        User.is_deleted == False,
        Student.cgpa.isnot(None)
    ).order_by(Student.cgpa.desc()).limit(10).all()
    
    created_count = 0
    for student in top_students:
        user = User.query.get(student.user_id)
        if not user:
            continue
        
        # Check if already exists
        existing = Topper.query.filter_by(
            student_id=student.id,
            academic_year=academic_year
        ).first()
        
        if existing:
            continue
        
        topper = Topper(
            student_id=student.id,
            name=user.full_name,
            course=student.course,
            year=student.year,
            semester=student.semester,
            cgpa=student.cgpa,
            image=user.avatar,
            email=user.email,
            academic_year=academic_year
        )
        
        db.session.add(topper)
        created_count += 1
    
    db.session.commit()
    
    log_activity(current_user.id, 'toppers_generated', 'topper', None, {'count': created_count, 'year': academic_year})
    
    return jsonify({
        'message': f'Generated {created_count} toppers for {academic_year}',
        'count': created_count
    }), 200


@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def get_activity_logs(current_user):
    """Get activity logs"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    user_id = request.args.get('user_id')
    action = request.args.get('action')
    
    query = ActivityLog.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter_by(action=action)
    
    paginated = query.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    logs_data = []
    for log in paginated.items:
        user = User.query.get(log.user_id) if log.user_id else None
        logs_data.append({
            'id': log.id,
            'user': user.full_name if user else 'System',
            'userEmail': user.email if user else None,
            'action': log.action,
            'entityType': log.entity_type,
            'details': log.details,
            'ipAddress': log.ip_address,
            'createdAt': log.created_at.isoformat() if log.created_at else None
        })
    
    return jsonify({
        'logs': logs_data,
        'total': paginated.total,
        'pages': paginated.pages,
        'currentPage': page
    }), 200


# ==================== ADDITIONAL ROUTES ====================

@app.route('/api/newsletter/subscribe', methods=['POST'])
def subscribe_newsletter():
    """Subscribe to newsletter"""
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    email = data['email'].lower().strip()
    
    if not validate_email(email):
        return jsonify({'message': 'Invalid email format'}), 400
    
    # Check if already subscribed
    existing = NewsletterSubscriber.query.filter_by(email=email).first()
    if existing:
        if not existing.is_active:
            existing.is_active = True
            existing.unsubscribed_at = None
            if data.get('name'):
                existing.name = data['name']
            db.session.commit()
            return jsonify({'message': 'Successfully resubscribed'}), 200
        return jsonify({'message': 'Email already subscribed'}), 200
    
    subscriber = NewsletterSubscriber(
        email=email,
        name=data.get('name')
    )
    db.session.add(subscriber)
    db.session.commit()
    
    # Send welcome email
    try:
        msg = Message(
            subject='Welcome to CSE Department Newsletter',
            recipients=[email],
            html=f"""
            <h3>Welcome to Our Newsletter!</h3>
            <p>Thank you for subscribing to the Department of Computer Science & Engineering newsletter.</p>
            <p>You'll receive updates about events, achievements, and important announcements.</p>
            """
        )
        mail.send(msg)
    except Exception as e:
        print(f"Newsletter welcome email error: {e}")
    
    return jsonify({'message': 'Successfully subscribed to newsletter'}), 201


@app.route('/api/newsletter/unsubscribe', methods=['POST'])
def unsubscribe_newsletter():
    """Unsubscribe from newsletter"""
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'message': 'Email is required'}), 400
    
    email = data['email'].lower().strip()
    
    subscriber = NewsletterSubscriber.query.filter_by(email=email).first()
    if subscriber:
        subscriber.is_active = False
        subscriber.unsubscribed_at = datetime.utcnow()
        db.session.commit()
    
    return jsonify({'message': 'Successfully unsubscribed'}), 200


@app.route('/api/send-updates', methods=['POST'])
@admin_required
def send_updates(current_user):
    """Send update emails to all subscribers (admin only)"""
    data = request.get_json()
    
    if not data.get('updates') or not isinstance(data.get('updates'), list):
        return jsonify({'message': 'Updates list is required'}), 400
    
    subscribers = NewsletterSubscriber.query.filter_by(is_active=True).all()
    
    sent_count = 0
    for subscriber in subscribers:
        try:
            newsletter_html = get_newsletter_email(subscriber.name or subscriber.email.split('@')[0], data['updates'])
            send_email(
                subscriber.email,
                'Department Updates - CSE Department',
                newsletter_html
            )
            sent_count += 1
        except Exception as e:
            print(f"Error sending to {subscriber.email}: {e}")
    
    log_activity(current_user.id, 'newsletter_sent', 'newsletter', None, {'count': sent_count})
    
    return jsonify({
        'message': f'Updates sent to {sent_count} subscribers',
        'sent': sent_count
    }), 200


@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    """Upload file to Cloudinary"""
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    # Determine folder based on user role or purpose
    folder = 'uploads'
    if request.args.get('folder'):
        folder = request.args.get('folder')
    
    try:
        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder=f"department_portal/{folder}",
            resource_type="auto"
        )
        
        return jsonify({
            'message': 'File uploaded successfully',
            'url': upload_result.get('secure_url'),
            'publicId': upload_result.get('public_id')
        }), 200
        
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'message': 'Upload failed'}), 500


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database with required data"""
    db.create_all()
    
    # Create default department info if not exists
    info = DepartmentInfo.query.get(1)
    if not info:
        info = DepartmentInfo(
            id=1,
            university='University of Technology & Sciences',
            department='Department of Computer Science & Engineering',
            vision='To be a center of excellence in Computer Science education and research.',
            mission='To provide quality education in Computer Science, foster innovation through research, and produce industry-ready professionals.',
            description='The Department of Computer Science & Engineering offers cutting-edge programs in Data Science and MCA, preparing students for successful careers in technology.',
            address='University Campus, Tech City, State - 123456',
            phone='+91-123-456-7890',
            email='cse.department@university.edu',
            office_hours='Monday - Friday: 9:00 AM - 5:00 PM'
        )
        db.session.add(info)
    
    # Create default programs if not exists
    if Program.query.count() == 0:
        programs = [
            Program(
                name='B.Tech Computer Science (Data Science)',
                code='BTECH-DS',
                description='Four-year undergraduate program focusing on data science, machine learning, analytics, and big data technologies.',
                duration='4 Years',
                seats=60,
                icon='fa-database',
                highlights=['Machine Learning', 'Big Data Analytics', 'Python Programming', 'Statistics', 'Data Visualization']
            ),
            Program(
                name='Master of Computer Applications (MCA)',
                code='MCA',
                description='Two-year postgraduate program in computer applications with specialization in software development and system design.',
                duration='2 Years',
                seats=60,
                icon='fa-laptop-code',
                highlights=['Advanced Programming', 'Software Engineering', 'Cloud Computing', 'Project Management', 'Web Technologies']
            )
        ]
        db.session.add_all(programs)
    
    # Create default admin if not exists
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@department.edu')
    admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@123')
    
    admin = User.query.filter_by(email=admin_email, is_deleted=False).first()
    if not admin:
        admin = User(
            email=admin_email,
            full_name='System Administrator',
            role='admin',
            is_verified=True,
            is_active=True
        )
        admin.set_password(admin_password)
        db.session.add(admin)
    
    db.session.commit()
    print("Database initialized successfully")


# ==================== MAIN ENTRY POINT ====================

if __name__ == '__main__':
    # Create upload directory if not exists
    os.makedirs('uploads', exist_ok=True)
    
    # Initialize database
    with app.app_context():
        init_db()
    
    # Run app
    app.run(host='0.0.0.0', port=5000, debug=True)






