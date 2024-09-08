CREATE TABLE aws_credentials (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    account_name VARCHAR(255),
    access_key VARCHAR(255),
    secret_key VARCHAR(255),
    is_default BOOLEAN DEFAULT FALSE
);
