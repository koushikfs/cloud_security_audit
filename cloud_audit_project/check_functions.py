import boto3

def run_root_user_access_key_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    response = client.get_account_summary()
    if response['SummaryMap']['AccountAccessKeysPresent'] > 0:
        return 'Fail'
    return 'Pass'

def run_root_user_mfa_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    response = client.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] == 1:
        return 'Pass'
    return 'Fail'

def run_iam_password_length_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    try:
        response = client.get_account_password_policy()
        if response['PasswordPolicy']['MinimumPasswordLength'] >= 14:
            return 'Pass'
    except client.exceptions.NoSuchEntityException:
        return 'Fail'
    return 'Fail'

def run_iam_password_reuse_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    try:
        response = client.get_account_password_policy()
        if response['PasswordPolicy']['PasswordReusePrevention'] >= 24:
            return 'Pass'
    except client.exceptions.NoSuchEntityException:
        return 'Fail'
    return 'Fail'

def run_iam_user_mfa_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    credential_report = client.generate_credential_report()
    report = client.get_credential_report()
    return 'Check report manually for MFA status.'

def run_iam_credentials_inactive_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    credential_report = client.generate_credential_report()
    report = client.get_credential_report()
    return 'Check report manually for unused credentials.'

def run_iam_single_access_key_check(access_key, secret_key, region, username):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    keys = client.list_access_keys(UserName=username)
    if len(keys['AccessKeyMetadata']) == 1:
        return 'Pass'
    return 'Fail'

def run_access_key_rotation_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    credential_report = client.generate_credential_report()
    report = client.get_credential_report()
    return 'Check report manually for access key rotation.'

def run_iam_user_group_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    users = client.list_users()['Users']
    for user in users:
        groups = client.list_groups_for_user(UserName=user['UserName'])
        if len(groups['Groups']) == 0:
            return 'Fail'
    return 'Pass'

def run_iam_admin_privileges_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    policies = client.list_policies(Scope='Local', OnlyAttached=True)['Policies']
    for policy in policies:
        policy_version = client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
        statements = policy_version['PolicyVersion']['Document']['Statement']
        for statement in statements:
            if statement.get('Action') == '*' and statement.get('Resource') == '*':
                return 'Fail'
    return 'Pass'

def run_aws_support_role_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    roles = client.list_roles()['Roles']
    for role in roles:
        if role['RoleName'] == 'AWSSupportAccess':
            return 'Pass'
    return 'Fail'

def run_iam_instance_role_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    instances = client.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            if 'IamInstanceProfile' not in instance:
                return 'Fail'
    return 'Pass'

def run_expired_certificates_check(access_key, secret_key, region):
    client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    certificates = client.list_server_certificates()['ServerCertificateMetadataList']
    for cert in certificates:
        if cert['Expiration'].date() < datetime.now().date():
            return 'Fail'
    return 'Pass'

def run_iam_access_analyzer_check(access_key, secret_key, region):
    client = boto3.client('accessanalyzer', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    analyzers = client.list_analyzers()['analyzers']
    for analyzer in analyzers:
        if analyzer['status'] == 'ACTIVE':
            return 'Pass'
    return 'Fail'

def run_s3_http_requests_check(access_key, secret_key, region, bucket_name):
    client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    policy = client.get_bucket_policy(Bucket=bucket_name)['Policy']
    if '"aws:SecureTransport": "false"' in policy:
        return 'Pass'
    return 'Fail'

def run_s3_block_public_access_check(access_key, secret_key, region, bucket_name):
    client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    public_access = client.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']
    if public_access['IsPublic'] is False:
        return 'Pass'
    return 'Fail'

def run_ebs_encryption_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    encryption = client.get_ebs_encryption_by_default()
    if encryption['EbsEncryptionByDefault']:
        return 'Pass'
    return 'Fail'

def run_rds_encryption_check(access_key, secret_key, region):
    client = boto3.client('rds', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    instances = client.describe_db_instances()['DBInstances']
    for instance in instances:
        if not instance['StorageEncrypted']:
            return 'Fail'
    return 'Pass'

def run_rds_auto_minor_upgrade_check(access_key, secret_key, region):
    client = boto3.client('rds', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    instances = client.describe_db_instances()['DBInstances']
    for instance in instances:
        if not instance['AutoMinorVersionUpgrade']:
            return 'Fail'
    return 'Pass'

def run_rds_public_access_check(access_key, secret_key, region):
    client = boto3.client('rds', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    instances = client.describe_db_instances()['DBInstances']
    for instance in instances:
        if instance['PubliclyAccessible']:
            return 'Fail'
    return 'Pass'

def run_efs_encryption_check(access_key, secret_key, region):
    client = boto3.client('efs', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    filesystems = client.describe_file_systems()['FileSystems']
    for fs in filesystems:
        if not fs['Encrypted']:
            return 'Fail'
    return 'Pass'

def run_cloudtrail_enabled_check(access_key, secret_key, region):
    client = boto3.client('cloudtrail', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    trails = client.describe_trails()['trailList']
    for trail in trails:
        if trail['IsMultiRegionTrail']:
            return 'Pass'
    return 'Fail'

def run_cloudtrail_log_file_validation_check(access_key, secret_key, region):
    client = boto3.client('cloudtrail', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    trails = client.describe_trails()['trailList']
    for trail in trails:
        if trail['LogFileValidationEnabled']:
            return 'Pass'
    return 'Fail'

def run_aws_config_check(access_key, secret_key, region):
    client = boto3.client('config', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    recorders = client.describe_configuration_recorders()['ConfigurationRecorders']
    if recorders:
        return 'Pass'
    return 'Fail'

def run_s3_logging_check(access_key, secret_key, region, bucket_name):
    client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    logging = client.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' in logging:
        return 'Pass'
    return 'Fail'

def run_cloudtrail_kms_encryption_check(access_key, secret_key, region):
    client = boto3.client('cloudtrail', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    trails = client.describe_trails()['trailList']
    for trail in trails:
        if trail.get('KmsKeyId'):
            return 'Pass'
    return 'Fail'

def run_kms_rotation_check(access_key, secret_key, region):
    client = boto3.client('kms', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    keys = client.list_keys()['Keys']
    for key in keys:
        rotation_status = client.get_key_rotation_status(KeyId=key['KeyId'])
        if rotation_status['KeyRotationEnabled']:
            return 'Pass'
    return 'Fail'

def run_vpc_flow_logs_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    flow_logs = client.describe_flow_logs()['FlowLogs']
    if flow_logs:
        return 'Pass'
    return 'Fail'

def run_s3_write_event_logging_check(access_key, secret_key, region, bucket_name):
    client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    logging = client.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' in logging and 'Write' in logging['LoggingEnabled']:
        return 'Pass'
    return 'Fail'

def run_s3_read_event_logging_check(access_key, secret_key, region, bucket_name):
    client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    logging = client.get_bucket_logging(Bucket=bucket_name)
    if 'LoggingEnabled' in logging and 'Read' in logging['LoggingEnabled']:
        return 'Pass'
    return 'Fail'

def run_security_hub_check(access_key, secret_key, region):
    client = boto3.client('securityhub', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    standards = client.get_enabled_standards()['StandardsSubscriptions']
    if standards:
        return 'Pass'
    return 'Fail'

def run_nacl_ingress_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    nacls = client.describe_network_acls()['NetworkAcls']
    for nacl in nacls:
        for entry in nacl['Entries']:
            if entry.get('CidrBlock') == '0.0.0.0/0':
                return 'Fail'
    return 'Pass'

def run_security_group_ingress_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    security_groups = client.describe_security_groups()['SecurityGroups']
    for sg in security_groups:
        for permission in sg['IpPermissions']:
            for ip_range in permission['IpRanges']:
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    return 'Fail'
    return 'Pass'

def run_security_group_ipv6_ingress_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    security_groups = client.describe_security_groups()['SecurityGroups']
    for sg in security_groups:
        for permission in sg['IpPermissions']:
            for ipv6_range in permission.get('Ipv6Ranges', []):
                if ipv6_range.get('CidrIpv6') == '::/0':
                    return 'Fail'
    return 'Pass'

def run_default_security_group_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    security_groups = client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']
    for sg in security_groups:
        if not sg['IpPermissions']:
            return 'Pass'
    return 'Fail'

def run_imdsv2_check(access_key, secret_key, region):
    client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    instances = client.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            if instance['MetadataOptions']['HttpTokens'] != 'required':
                return 'Fail'
    return 'Pass'
