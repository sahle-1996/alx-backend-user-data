#!/usr/bin/env python3
"""Defines the User SQLAlchemy model for the users table."""
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

# Base class for declarative class definitions
Base = declarative_base()


class User(Base):
    """Represents a record in the 'users' table."""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(180), nullable=False, unique=True)
    hashed_password = Column(String(180), nullable=False)
    session_id = Column(String(120), default=None)
    reset_token = Column(String(120), default=None)
