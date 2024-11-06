#!/usr/bin/env python3
"""Replaces specific field values using regex"""
import re
import os
import logging
import mysql.connector
from typing import List


class SensitiveDataFormatter(logging.Formatter):
    """Custom formatter to redact sensitive data"""

    MASK = "REDACTED"
    LOG_FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEP = ";"

    def __init__(self, fields: List[str]):
        super(SensitiveDataFormatter, self).__init__(self.LOG_FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats log records by redacting sensitive fields"""
        return conceal_data(self.fields, self.MASK,
                            super().format(record), self.SEP)


SENSITIVE_FIELDS = ("name", "email", "password", "ssn", "phone")


def connect_db() -> mysql.connector.connection.MySQLConnection:
    """Establishes and returns a MySQL connection"""
    return mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME')
    )


def conceal_data(fields: List[str], mask: str, message: str,
                 sep: str) -> str:
    """Replaces sensitive data in messages using regex"""
    for field in fields:
        message = re.sub(f'{field}=(.*?){sep}',
                         f'{field}={mask}{sep}', message)
    return message


def setup_logger() -> logging.Logger:
    """Configures and returns a logger instance"""
    logger = logging.getLogger("data_security")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)

    formatter = SensitiveDataFormatter(list(SENSITIVE_FIELDS))
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger


def main() -> None:
    """Connects to database and logs user information securely"""
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    headers = [col[0] for col in cursor.description]
    logger = setup_logger()

    for row in cursor:
        log_message = ''
        for val, header in zip(row, headers):
            log_message += f'{header}={(val)}; '
        logger.info(log_message)

    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
