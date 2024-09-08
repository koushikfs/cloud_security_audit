INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0001', 'Ensure no root user account access key exists', 
'Ensure no access key is associated with the root user account.', 
'aws iam get-account-summary | grep "AccountAccessKeysPresent"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0002', 'Ensure MFA is enabled for the root user account', 
'Ensure MFA is enabled for the root user account.', 
'aws iam get-account-summary | grep "AccountMFAEnabled"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0003', 'Ensure IAM password policy requires minimum length of 14 or greater', 
'Ensure that the IAM password policy has a minimum length of 14 characters or more.', 
'aws iam get-account-password-policy --query "PasswordPolicy.MinimumPasswordLength"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0004', 'Ensure IAM password policy prevents password reuse', 
'Ensure that the IAM password policy prevents the reuse of passwords.', 
'aws iam get-account-password-policy --query "PasswordPolicy.PasswordReusePrevention"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0005', 'Ensure MFA is enabled for all IAM users with a console password', 
'Ensure that MFA is enabled for all IAM users that have a console password.', 
'aws iam generate-credential-report', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0006', 'Ensure credentials unused for 45 days or greater are disabled', 
'Ensure that IAM user credentials unused for 45 days or greater are disabled.', 
'aws iam generate-credential-report', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0007', 'Ensure only one active access key per IAM user', 
'Ensure that each IAM user has only one active access key.', 
'aws iam list-access-keys --user-name <username>', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0008', 'Ensure access keys are rotated every 90 days or less', 
'Ensure that access keys are rotated every 90 days or less.', 
'aws iam generate-credential-report', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0009', 'Ensure IAM Users Receive Permissions Only Through Groups', 
'Ensure IAM users receive permissions only through groups and not directly.', 
'aws iam list-users --query "Users[*].UserName"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0010', 'Ensure IAM policies with full "*:*" administrative privileges are not attached', 
'Ensure that IAM policies do not grant full administrative privileges.', 
'aws iam list-policies --only-attached', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0011', 'Ensure a support role has been created for AWS Support', 
'Ensure that a support role is created to manage AWS Support incidents.', 
'aws iam list-roles --query "Roles[?RoleName==\'AWSSupportAccess\']"', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0012', 'Ensure IAM instance roles are used for AWS resource access', 
'Ensure that IAM instance roles are used for AWS resource access from EC2 instances.', 
'aws ec2 describe-instances --query "Reservations[*].Instances[*].IamInstanceProfile"', 'EC2', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0013', 'Ensure expired SSL/TLS certificates are removed', 
'Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed.', 
'aws iam list-server-certificates', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0014', 'Ensure IAM Access Analyzer is enabled for all regions', 
'Ensure that IAM Access Analyzer is enabled for all regions.', 
'aws accessanalyzer list-analyzers', 'IAM', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0015', 'Ensure S3 Bucket Policy denies HTTP requests', 
'Ensure that the S3 bucket policy is set to deny HTTP requests.', 
'aws s3api get-bucket-policy --bucket <bucket_name>', 'S3', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0016', 'Ensure S3 Buckets are configured with Block public access', 
'Ensure that S3 Buckets are configured with Block public access (bucket settings).', 
'aws s3api get-bucket-policy-status --bucket <bucket_name>', 'S3', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0017', 'Ensure EBS Volume Encryption is Enabled in all Regions', 
'Ensure that EBS volume encryption is enabled in all regions.', 
'aws ec2 get-ebs-encryption-by-default', 'EC2', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0018', 'Ensure that encryption-at-rest is enabled for RDS Instances', 
'Ensure that encryption-at-rest is enabled for RDS Instances.', 
'aws rds describe-db-instances --query "DBInstances[*].StorageEncrypted"', 'RDS', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0019', 'Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances', 
'Ensure that Auto Minor Version Upgrade feature is enabled for RDS Instances.', 
'aws rds describe-db-instances --query "DBInstances[*].AutoMinorVersionUpgrade"', 'RDS', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0020', 'Ensure that public access is not given to RDS Instance', 
'Ensure that public access is not granted to RDS Instances.', 
'aws rds describe-db-instances --query "DBInstances[*].PubliclyAccessible"', 'RDS', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0021', 'Ensure that encryption is enabled for EFS file systems', 
'Ensure that encryption is enabled for EFS file systems.', 
'aws efs describe-file-systems --query "FileSystems[*].Encrypted"', 'EFS', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0022', 'Ensure CloudTrail is enabled in all regions', 
'Ensure that CloudTrail is enabled in all regions.', 
'aws cloudtrail describe-trails --query "trailList[*].IsMultiRegionTrail"', 'CloudTrail', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0023', 'Ensure CloudTrail log file validation is enabled', 
'Ensure that CloudTrail log file validation is enabled.', 
'aws cloudtrail describe-trails --query "trailList[*].LogFileValidationEnabled"', 'CloudTrail', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0024', 'Ensure AWS Config is enabled in all regions', 
'Ensure that AWS Config is enabled in all regions.', 
'aws configservice describe-configuration-recorders', 'Config', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0025', 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket', 
'Ensure that S3 bucket access logging is enabled on the CloudTrail S3 bucket.', 
'aws s3api get-bucket-logging --bucket <bucket_name>', 'S3', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0026', 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs', 
'Ensure CloudTrail logs are encrypted at rest using customer-managed KMS CMKs.', 
'aws cloudtrail describe-trails --query "trailList[*].KmsKeyId"', 'CloudTrail', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0027', 'Ensure rotation for customer-created symmetric CMKs is enabled', 
'Ensure that rotation is enabled for customer-created symmetric CMKs.', 
'aws kms list-keys | xargs -I {} aws kms get-key-rotation-status --key-id {}', 'KMS', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0028', 'Ensure VPC flow logging is enabled in all VPCs', 
'Ensure VPC flow logging is enabled for all VPCs.', 
'aws ec2 describe-flow-logs --query "FlowLogs[*].FlowLogId"', 'EC2', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0029', 'Ensure Object-level logging for write events is enabled for S3 bucket', 
'Ensure that Object-level logging for write events is enabled for the S3 bucket.', 
'aws s3api get-bucket-logging --bucket <bucket_name>', 'S3', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0030', 'Ensure Object-level logging for read events is enabled for S3 bucket', 
'Ensure that Object-level logging for read events is enabled for the S3 bucket.', 
'aws s3api get-bucket-logging --bucket <bucket_name>', 'S3', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0031', 'Ensure AWS Security Hub is enabled', 
'Ensure that AWS Security Hub is enabled.', 
'aws securityhub get-enabled-standards', 'SecurityHub', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0032', 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports', 
'Ensure that no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports.', 
'aws ec2 describe-network-acls --query "NetworkAcls[*].Entries[?CidrBlock==\'0.0.0.0/0\']"', 'VPC', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0033', 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports', 
'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.', 
'aws ec2 describe-security-groups --query "SecurityGroups[*].IpPermissions[?IpRanges[*].CidrIp==\'0.0.0.0/0\']"', 'VPC', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0034', 'Ensure no security groups allow ingress from ::/0 to remote server administration ports', 
'Ensure no security groups allow ingress from ::/0 to remote server administration ports.', 
'aws ec2 describe-security-groups --query "SecurityGroups[*].IpPermissions[?Ipv6Ranges[*].CidrIpv6==\'::/0\']"', 'VPC', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0035', 'Ensure the default security group of every VPC restricts all traffic', 
'Ensure the default security group of every VPC restricts all traffic.', 
'aws ec2 describe-security-groups --query "SecurityGroups[?GroupName==\'default\']"', 'VPC', 'CISBv3.0');

INSERT INTO checks (check_id, check_name, check_description, cli_command, service_name, sources)
VALUES ('0036', 'Ensure that EC2 Metadata Service only allows IMDSv2', 
'Ensure that EC2 Metadata Service only allows IMDSv2.', 
'aws ec2 describe-instances --query "Reservations[*].Instances[*].MetadataOptions.HttpTokens"', 'EC2', 'CISBv3.0');