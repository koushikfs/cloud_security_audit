from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz
from check_functions import *

app = Flask(__name__)

check_functions_map = {
    '0001': run_root_user_access_key_check,
    '0002': run_root_user_mfa_check,
    '0003': run_iam_password_length_check,
    '0004': run_iam_password_reuse_check,
    '0005': run_iam_user_mfa_check,
    '0006': run_iam_credentials_inactive_check,
    '0007': run_iam_single_access_key_check,
    '0008': run_access_key_rotation_check,
    '0009': run_iam_user_group_check,
    '0010': run_iam_admin_privileges_check,
    '0011': run_aws_support_role_check,
    '0012': run_iam_instance_role_check,
    '0013': run_expired_certificates_check,
    '0014': run_iam_access_analyzer_check,
    '0015': run_s3_http_requests_check,
    '0016': run_s3_block_public_access_check,
    '0017': run_ebs_encryption_check,
    '0018': run_rds_encryption_check,
    '0019': run_rds_auto_minor_upgrade_check,
    '0020': run_rds_public_access_check,
    '0021': run_efs_encryption_check,
    '0022': run_cloudtrail_enabled_check,
    '0023': run_cloudtrail_log_file_validation_check,
    '0024': run_aws_config_check,
    '0025': run_s3_logging_check,
    '0026': run_cloudtrail_kms_encryption_check,
    '0027': run_kms_rotation_check,
    '0028': run_vpc_flow_logs_check,
    '0029': run_s3_write_event_logging_check,
    '0030': run_s3_read_event_logging_check,
    '0031': run_security_hub_check,
    '0032': run_nacl_ingress_check,
    '0033': run_security_group_ingress_check,
    '0034': run_security_group_ipv6_ingress_check,
    '0035': run_default_security_group_check,
    '0036': run_imdsv2_check
}


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:toor@127.0.0.1:3306/cloud_checks'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

regions = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 
    'ca-central-1', 'sa-east-1', 'eu-west-1', 'eu-central-1', 
    'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 
    'eu-central-2', 'eu-south-2', 'me-south-1', 'me-central-1', 
    'af-south-1', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 
    'ap-east-1', 'ap-southeast-3', 'ap-southeast-4', 'ap-south-2',
    'ap-north-1', 'cn-north-1', 'cn-northwest-1', 'us-gov-west-1', 
    'us-gov-east-1', 'il-central-1', 'ap-southeast-5'
]

class Check(db.Model):
    __tablename__ = 'checks'
    check_id = db.Column(db.String(4), primary_key=True)
    check_name = db.Column(db.String(255))
    check_description = db.Column(db.Text)
    cli_command = db.Column(db.Text)
    service_name = db.Column(db.String(255))
    sources = db.Column(db.Text)

class AWSCredentials(db.Model):
    __tablename__ = 'aws_credentials'
    account_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    account_name = db.Column(db.String(255))
    access_key = db.Column(db.String(255))
    secret_key = db.Column(db.String(255))
    is_default = db.Column(db.Boolean, default=False)

def log_command(s_no, command, account_name, region, status):
    ist = pytz.timezone('Asia/Kolkata')
    timestamp = datetime.now(ist).strftime("%Y-%m-%d %I:%M:%S %p")

    with open("log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] Check No: {s_no} [{command}] [{region}] [{account_name}] [{status}]\n")

@app.route('/', methods=['GET'])
def index():
    aws_accounts = AWSCredentials.query.all() 
    default_account = AWSCredentials.query.filter_by(is_default=True).first()

    checks = Check.query.all()
    unique_services = list(set([check.service_name for check in checks]))
    unique_sources = list(set([check.sources for check in checks]))
    
    return render_template('checks.html', checks=checks, aws_accounts=aws_accounts, default_account=default_account, regions=regions, services=unique_services, sources = unique_sources)

@app.route('/add_aws_account', methods=['POST'])
def add_aws_account():
    account_name = request.form['account_name']
    access_key = request.form['access_key']
    secret_key = request.form['secret_key']
    is_default = 'is_default' in request.form

    new_account = AWSCredentials(account_name=account_name, access_key=access_key, secret_key=secret_key, is_default=is_default)
    db.session.add(new_account)
    db.session.commit()

    if is_default:
        AWSCredentials.query.update({'is_default': False})
        new_account.is_default = True
        db.session.commit()

    aws_accounts = AWSCredentials.query.all()
    accounts_data = [{'account_id': account.account_id, 'account_name': account.account_name, 'is_default': account.is_default} for account in aws_accounts]

    return jsonify(success=True, aws_accounts=accounts_data)

@app.route('/run_check', methods=['POST'])
def run_check():
    s_no = request.form['s_no']
    account_index = request.form['aws_account']
    

    selected_account = AWSCredentials.query.filter_by(account_id=account_index).first()
    if not selected_account:
        return jsonify(success=False, message=f"AWS Account with ID {account_index} not found")

    access_key = selected_account.access_key
    secret_key = selected_account.secret_key
    account_name = selected_account.account_name

    check = Check.query.filter_by(check_id=s_no).first()
    if not check:
        return jsonify(success=False, message="Check ID not found")

    command = check.cli_command
    selected_region = request.form.get(f'region_{s_no}') or request.form['default_region']

    check_function = check_functions_map.get(s_no)
    
    if not check_function:
        return jsonify(success=False, message="No function mapped for this check ID")

    try:
        result = check_function(access_key, secret_key, selected_region)
        status = "Pass" if result == 'Pass' else "Fail"
        log_command(s_no, command, account_name, selected_region, status)
        return jsonify(success=True, result=status)
    except Exception as e:
        return jsonify(success=False, message=str(e))


if __name__ == '__main__':
    app.run(debug=True)
