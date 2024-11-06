#!/usr/bin/env python3
"""Generates a salted, hashed password and verifies it"""
import bcrypt


def generate_hash(plain_text: str) -> bytes:
    """Returns a hashed byte string from plain text password"""
    return bcrypt.hashpw(plain_text.encode('utf-8'), bcrypt.gensalt())


def validate_password(stored_hash: bytes, plain_text: str) -> bool:
    """Validates the password against the stored hashed password"""
    return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash)
