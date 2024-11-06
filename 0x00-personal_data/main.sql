-- Initialize MySQL database and set up permissions
CREATE DATABASE IF NOT EXISTS user_data;
CREATE USER IF NOT EXISTS 'admin'@'localhost' IDENTIFIED BY 'admin_pass';
GRANT ALL PRIVILEGES ON user_data.* TO 'admin'@'localhost';

USE user_data;

DROP TABLE IF EXISTS user_info;
CREATE TABLE user_info (
    name VARCHAR(256),
    email VARCHAR(256),
    phone VARCHAR(16),
    ssn VARCHAR(16),
    password VARCHAR(256),
    ip_address VARCHAR(64),
    last_login TIMESTAMP,
    user_agent VARCHAR(512)
);

INSERT INTO user_info (name, email, phone, ssn, password, ip_address, last_login, user_agent) 
VALUES ("Marlene Woo", "marlene@example.com", "1234567890", "111-22-3333", "pass123", "192.168.1.1", NOW(), "Mozilla/5.0");

INSERT INTO user_info (name, email, phone, ssn, password, ip_address, last_login, user_agent) 
VALUES ("Bob Cigar", "bob@example.com", "0987654321", "444-55-6666", "pass456", "10.0.0.1", NOW(), "Mozilla/5.0");
