INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources) VALUES
('0001', 'S3 Bucket Check', 'Check if S3 Buckets are publicly accessible', 'aws s3 ls', 's3', 'AWS Docs');
