#!/usr/bin/env python3
"""Database module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """Handles interactions with the database."""

    def __init__(self) -> None:
        """Initialize the database engine and session."""
        self._engine = create_engine("sqlite:///db.sqlite3")
        Base.metadata.drop_all(bind=self._engine)
        Base.metadata.create_all(bind=self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Create or retrieve the database session."""
        if self.__session is None:
            session_cls = sessionmaker(bind=self._engine)
            self.__session = session_cls()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add a new user to the database.
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **filters) -> User:
        """
        Find a user by specified filters.
        """
        try:
            user = self._session.query(User).filter_by(**filters).first()
        except TypeError as e:
            raise InvalidRequestError from e

        if user is None:
            raise NoResultFound

        return user

    def update_user(self, user_id: int, **fields) -> None:
        """Update an existing user's attributes."""
        user = self.find_user_by(id=user_id)

        for field, value in fields.items():
            if hasattr(user, field):
                setattr(user, field, value)
            else:
                raise ValueError(f"Invalid attribute: {field}")

        self._session.commit()
