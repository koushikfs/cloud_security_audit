CREATE TABLE checks (
    check_id VARCHAR(4) PRIMARY KEY,
    check_name VARCHAR(255),
    check_description TEXT,
    cli_command TEXT,
    service_name VARCHAR(255),
    sources TEXT
);