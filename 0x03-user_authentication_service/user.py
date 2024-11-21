#!/usr/bin/env python3
"""
Module User
"""
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

# Declarative base for model definitions
Base = declarative_base()


class User(Base):
    """ SQLAlchemy model for the 'users' table. """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(128), nullable=False, unique=True)
    hashed_password = Column(String(128), nullable=False)
    session_id = Column(String(64), nullable=True)
    reset_token = Column(String(64), nullable=True)
