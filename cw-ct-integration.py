import boto3
import json

def get_account_id():
    sts_client = boto3.client('sts')
    return sts_client.get_caller_identity()['Account']

def create_cloudtrail_cloudwatch_logs_role(iam_client):
    print("Creating IAM role 'CloudTrail_CloudWatchLogs_Role'...")
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    # Specify the Path parameter to set the role path
    iam_client.create_role(RoleName='CloudTrail_CloudWatchLogs_Role', Path='/service-role/', AssumeRolePolicyDocument=json.dumps(assume_role_policy_document))
    print("IAM role 'CloudTrail_CloudWatchLogs_Role' created.")

def execute():
    cloudtrail_client = boto3.client('cloudtrail')
    cloudwatch_client = boto3.client('logs')
    iam_client = boto3.client('iam')
    
    try:
        print("Script execution started.")
        
        # Get the AWS account ID
        account_id = get_account_id()
        
        # Check if CloudTrail is integrated with CloudWatch Logs
        trails = cloudtrail_client.describe_trails()
        for trail in trails['trailList']:
            if 'CloudWatchLogsLogGroupArn' not in trail:
                # CloudTrail is not integrated with CloudWatch Logs, so we need to create the necessary resources
                
                # Create CloudWatch Logs log group
                log_group_name = f'/aws/cloudtrail/logs/{account_id}'
                cloudwatch_client.create_log_group(
                    logGroupName=log_group_name
                )
                
                # Get the ARN of the created log group
                response = cloudwatch_client.describe_log_groups(
                    logGroupNamePrefix=log_group_name
                )
                log_group_arn = response['logGroups'][0]['arn'] if response['logGroups'] else None
                # Create Log Stream within the Log Group
                cloudwatch_client.create_log_stream(
                    logGroupName=log_group_name,
                    logStreamName=f"{account_id}_CloudTrail_{boto3.Session().region_name}"
                )
                
                # Create IAM role with updated trust relationship policy
                create_cloudtrail_cloudwatch_logs_role(iam_client)
                
                # Apply the provided IAM policy for CloudTrail to the IAM role
                policy_document = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AWSCloudTrailCreateLogStream2014110",
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogStream"
                            ],
                            "Resource": [
                                f"arn:aws:logs:{boto3.Session().region_name}:{account_id}:log-group:{log_group_name}:log-stream:{account_id}_CloudTrail_{boto3.Session().region_name}*"
                            ]
                        },
                        {   
                            "Sid": "AWSCloudTrailCreateLogStream20141101",
                            "Effect": "Allow",
                            "Action": [
                                "logs:PutLogEvents"
                            ],
                            "Resource": [
                                f"arn:aws:logs:{boto3.Session().region_name}:{account_id}:log-group:{log_group_name}:log-stream:{account_id}_CloudTrail_{boto3.Session().region_name}*"
                            ]
                        }
                    ]
                }
                # Attach the policy to the IAM role
                iam_client.put_role_policy(
                    RoleName='CloudTrail_CloudWatchLogs_Role',
                    PolicyName='CloudTrail_CloudWatchLogs_Policy',
                    PolicyDocument=json.dumps(policy_document)
                )
                
                # Update CloudTrail to use the new log group and IAM role
                print (trail['Name'])
                print (log_group_arn)
                print (f'arn:aws:iam::{account_id}:role/service-role/CloudTrail_CloudWatchLogs_Role')
                cloudtrail_client.update_trail(
                    Name=trail['Name'],
                    CloudWatchLogsLogGroupArn=log_group_arn,
                    CloudWatchLogsRoleArn=f'arn:aws:iam::{account_id}:role/service-role/CloudTrail_CloudWatchLogs_Role'
                )
                       
    except Exception as e:
        print("Script execution failed:", e)
        return {'success': False, 'error': str(e)}

# Execute the script
execute()