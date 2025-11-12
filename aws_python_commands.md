# AWS Python Commands/Snippets (Generated 2025-11-05T01:21:08)

## 1. Setup — Create default session (profile + region)
```python
import boto3
session = boto3.Session(profile_name='default', region_name='us-east-1')
```
*Notes:* Use a named profile & region for all clients/resources.

## 2. Setup — Create client
```python
import boto3
s3 = boto3.client('s3', region_name='us-east-1')
```
*Notes:* Client-style API

## 3. Setup — Create resource
```python
import boto3
s3r = boto3.resource('s3', region_name='us-east-1')
```
*Notes:* Resource-style API

## 4. Credentials/STS — Get caller identity
```python
import boto3
sts = boto3.client('sts')
print(sts.get_caller_identity())
```

## 5. Credentials/STS — Assume role
```python
import boto3, json
sts = boto3.client('sts')
resp = sts.assume_role(RoleArn='arn:aws:iam::123456789012:role/OrgReadOnly', RoleSessionName='demo')
creds = resp['Credentials']
print(json.dumps({k: creds[k] for k in ('AccessKeyId','SecretAccessKey','SessionToken')}, indent=2))
```

## 6. S3 — List buckets
```python
import boto3
s3 = boto3.client('s3')
for b in s3.list_buckets()['Buckets']:
    print(b['Name'])
```

## 7. S3 — Create bucket (us-east-1)
```python
import boto3
s3 = boto3.client('s3', region_name='us-east-1')
s3.create_bucket(Bucket='my-demo-bucket-12345')
```
*Notes:* For other regions, include CreateBucketConfiguration.

## 8. S3 — Upload text object
```python
import boto3
s3 = boto3.client('s3')
s3.put_object(Bucket='my-demo-bucket-12345', Key='hello.txt', Body=b'hello world')
```

## 9. S3 — Download object bytes
```python
import boto3
s3 = boto3.client('s3')
obj = s3.get_object(Bucket='my-demo-bucket-12345', Key='hello.txt')
print(obj['Body'].read().decode())
```

## 10. S3 — List objects with prefix
```python
import boto3
s3 = boto3.client('s3')
resp = s3.list_objects_v2(Bucket='my-demo-bucket-12345', Prefix='logs/')
for c in resp.get('Contents', []):
    print(c['Key'], c['Size'])
```

## 11. S3 — Paginate objects
```python
import boto3
client = boto3.client('s3', region_name='us-east-1')
paginator = client.get_paginator('list_objects_v2')
for page in paginator.paginate(Bucket='my-demo-bucket-12345', Prefix=''):
    for item in page.get('Contents', []):
        print(item)
```

## 12. S3 — Set lifecycle rule (expire after 30 days)
```python
import boto3
s3 = boto3.client('s3')
s3.put_bucket_lifecycle_configuration(
    Bucket='my-demo-bucket-12345',
    LifecycleConfiguration={'Rules':[{'ID':'expire-30','Status':'Enabled','Filter':{'Prefix':''},'Expiration':{'Days':30}}]}
)
```

## 13. S3 — Attach bucket policy (readonly public GET - sample)
```python
import json, boto3
s3 = boto3.client('s3')
policy = {
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadGetObject",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-demo-bucket-12345/*"
  }]
}
s3.put_bucket_policy(Bucket='my-demo-bucket-12345', Policy=json.dumps(policy))
```
*Notes:* For public access, ensure Block Public Access settings allow it.

## 14. S3 — Enable bucket versioning
```python
import boto3
s3 = boto3.client('s3')
s3.put_bucket_versioning(Bucket='my-demo-bucket-12345', VersioningConfiguration={'Status':'Enabled'})
```

## 15. S3 — Enable default SSE-S3
```python
import boto3
s3 = boto3.client('s3')
s3.put_bucket_encryption(
    Bucket='my-demo-bucket-12345',
    ServerSideEncryptionConfiguration={'Rules':[{'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]}
)
```

## 16. EC2 — Describe instances
```python
import boto3
ec2 = boto3.client('ec2')
for r in ec2.describe_instances()['Reservations']:
    for i in r['Instances']:
        print(i['InstanceId'], i['State']['Name'])
```

## 17. EC2 — Filter by tag
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[{'Name':'tag:Env','Values':['prod']}])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```

## 18. EC2 — Start instances
```python
import boto3
ec2 = boto3.client('ec2')
ec2.start_instances(InstanceIds=['i-0123456789abcdef0'])
```

## 19. EC2 — Stop instances
```python
import boto3
ec2 = boto3.client('ec2')
ec2.stop_instances(InstanceIds=['i-0123456789abcdef0'])
```

## 20. EC2 — Tag instances
```python
import boto3
ec2 = boto3.client('ec2')
ec2.create_tags(Resources=['i-0123456789abcdef0'], Tags=[{'Key':'Env','Value':'dev'}])
```

## 21. EC2 — Describe VPCs
```python
import boto3
ec2 = boto3.client('ec2')
print(ec2.describe_vpcs()['Vpcs'])
```

## 22. EC2 — Create security group
```python
import boto3
ec2 = boto3.client('ec2')
ec2.create_security_group(GroupName='web-sg', Description='Web SG', VpcId='vpc-0123456789abcdef0')
```

## 23. EC2 — Allow SG ingress 80/tcp
```python
import boto3
ec2 = boto3.client('ec2')
ec2.authorize_security_group_ingress(
    GroupId='sg-0123456789abcdef0',
    IpPermissions=[{'IpProtocol':'tcp','FromPort':80,'ToPort':80,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]}])
```

## 24. EC2 — Describe subnets
```python
import boto3
ec2 = boto3.client('ec2')
print(ec2.describe_subnets()['Subnets'])
```

## 25. EC2 — Allocate Elastic IP
```python
import boto3
ec2 = boto3.client('ec2')
print(ec2.allocate_address(Domain='vpc'))
```

## 26. IAM — List IAM users
```python
import boto3
iam = boto3.client('iam')
for u in iam.list_users()['Users']:
    print(u['UserName'])
```

## 27. IAM — Create IAM user
```python
import boto3
iam = boto3.client('iam')
iam.create_user(UserName='demo-user')
```

## 28. IAM — Attach policy to user
```python
import boto3
iam = boto3.client('iam')
iam.attach_user_policy(UserName='demo-user', PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess')
```

## 29. IAM — Create role (trust EC2)
```python
import boto3, json
iam = boto3.client('iam')
assume = {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]}
iam.create_role(RoleName='ec2-demo-role', AssumeRolePolicyDocument=json.dumps(assume))
```

## 30. IAM — Inline role policy
```python
import boto3, json
iam = boto3.client('iam')
policy = {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['s3:ListAllMyBuckets'],'Resource':'*'}]}
iam.put_role_policy(RoleName='ec2-demo-role', PolicyName='ListBucketsOnly', PolicyDocument=json.dumps(policy))
```

## 31. LAMBDA — List Lambda functions
```python
import boto3
lam = boto3.client('lambda')
print([f['FunctionName'] for f in lam.list_functions()['Functions']])
```

## 32. LAMBDA — Invoke function (RequestResponse)
```python
import boto3, json
lam = boto3.client('lambda')
resp = lam.invoke(FunctionName='my-func', InvocationType='RequestResponse', Payload=b'{}')
print(json.loads(resp['Payload'].read()))
```

## 33. LOGS — Describe log groups
```python
import boto3
logs = boto3.client('logs')
for g in logs.describe_log_groups()['logGroups']:
    print(g['logGroupName'])
```

## 34. LOGS — Tail last 20 events
```python
import boto3
logs = boto3.client('logs')
resp = logs.get_log_events(logGroupName='/aws/lambda/my-func', logStreamName='2025/11/04/[$LATEST]abc', limit=20, startFromHead=False)
for e in resp['events']:
    print(e['message'].rstrip())
```

## 35. EVENTS — List EventBridge rules
```python
import boto3
eb = boto3.client('events')
print([r['Name'] for r in eb.list_rules()['Rules']])
```

## 36. DYNAMODB — List DynamoDB tables
```python
import boto3
ddb = boto3.client('dynamodb')
print(ddb.list_tables()['TableNames'])
```

## 37. DYNAMODB — Get item
```python
import boto3
ddb = boto3.client('dynamodb')
resp = ddb.get_item(TableName='Users', Key={'userId':{'S':'u-1'}})
print(resp.get('Item'))
```

## 38. DYNAMODB — Put item
```python
import boto3
ddb = boto3.client('dynamodb')
ddb.put_item(TableName='Users', Item={'userId':{'S':'u-1'}, 'name':{'S':'Anie'}})
```

## 39. DYNAMODB — Query by partition key
```python
import boto3
ddb = boto3.client('dynamodb')
resp = ddb.query(TableName='Orders', KeyConditionExpression='customerId = :c', ExpressionAttributeValues={':c':{'S':'c-1'}})
print(resp['Items'])
```

## 40. DYNAMODB — Scan table (limit 25)
```python
import boto3
ddb = boto3.client('dynamodb')
print(ddb.scan(TableName='Users', Limit=25)['Items'])
```

## 41. CLOUDFORMATION — List stacks
```python
import boto3
cf = boto3.client('cloudformation')
for s in cf.list_stacks(StackStatusFilter=['CREATE_COMPLETE','UPDATE_COMPLETE'])['StackSummaries']:
    print(s['StackName'], s['StackStatus'])
```

## 42. CLOUDFORMATION — Create stack
```python
import boto3, json
cf = boto3.client('cloudformation')
cf.create_stack(StackName='demo', TemplateBody='{"AWSTemplateFormatVersion":"2010-09-09"}', Capabilities=['CAPABILITY_NAMED_IAM'])
```
*Notes:* Provide a full template.

## 43. CLOUDFORMATION — Describe stack events
```python
import boto3
cf = boto3.client('cloudformation')
print(cf.describe_stack_events(StackName='demo')['StackEvents'][:5])
```

## 44. CLOUDWATCH — List metrics
```python
import boto3
cw = boto3.client('cloudwatch')
resp = cw.list_metrics(Namespace='AWS/EC2', MetricName='CPUUtilization')
print(resp.get('Metrics', [])[:3])
```

## 45. CLOUDWATCH — Get metric data (avg CPU 1h)
```python
import boto3, datetime
from datetime import timezone, timedelta
cw = boto3.client('cloudwatch')
end = datetime.datetime.now(timezone.utc)
start = end - timedelta(hours=1)
resp = cw.get_metric_statistics(Namespace='AWS/EC2', MetricName='CPUUtilization',
    Dimensions=[{'Name':'InstanceId','Value':'i-0123456789abcdef0'}],
    StartTime=start, EndTime=end, Period=300, Statistics=['Average'])
print(resp['Datapoints'])
```

## 46. RDS — Describe RDS instances
```python
import boto3
rds = boto3.client('rds')
print([d['DBInstanceIdentifier'] for d in rds.describe_db_instances()['DBInstances']])
```

## 47. ECR — Describe ECR repos
```python
import boto3
ecr = boto3.client('ecr')
print([r['repositoryName'] for r in ecr.describe_repositories()['repositories']])
```

## 48. ECR — Get ECR auth token
```python
import boto3, base64
ecr = boto3.client('ecr')
tok = ecr.get_authorization_token()['authorizationData'][0]
print(base64.b64decode(tok['authorizationToken']).decode())
```

## 49. ECS — List ECS clusters
```python
import boto3
ecs = boto3.client('ecs')
print(ecs.list_clusters()['clusterArns'])
```

## 50. ECS — List services in cluster
```python
import boto3
ecs = boto3.client('ecs')
print(ecs.list_services(cluster='default')['serviceArns'])
```

## 51. EKS — List EKS clusters
```python
import boto3
eks = boto3.client('eks')
print(eks.list_clusters()['clusters'])
```

## 52. SQS — List SQS queues
```python
import boto3
sqs = boto3.client('sqs')
print(sqs.list_queues().get('QueueUrls', []))
```

## 53. SQS — Send SQS message
```python
import boto3, json
sqs = boto3.client('sqs')
sqs.send_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MessageBody=json.dumps({'hello':'world'}))
```

## 54. SNS — List SNS topics
```python
import boto3
sns = boto3.client('sns')
print([t['TopicArn'] for t in sns.list_topics()['Topics']])
```

## 55. SNS — Publish to SNS topic
```python
import boto3
sns = boto3.client('sns')
sns.publish(TopicArn='arn:aws:sns:us-east-1:123456789012:demo', Message='Hello')
```

## 56. SECRETSMANAGER — List secrets
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['Name'] for s in sec.list_secrets()['SecretList']])
```

## 57. SECRETSMANAGER — Get secret value
```python
import boto3, json
sec = boto3.client('secretsmanager')
val = sec.get_secret_value(SecretId='my/secret')
print(val.get('SecretString') or '<binary>')
```

## 58. SSM — List SSM parameters
```python
import boto3
ssm = boto3.client('ssm')
print([p['Name'] for p in ssm.describe_parameters()['Parameters']])
```

## 59. SSM — Get parameter
```python
import boto3
ssm = boto3.client('ssm')
print(ssm.get_parameter(Name='/app/db/password', WithDecryption=True)['Parameter']['Value'])
```

## 60. SSM — Run command on instance
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(InstanceIds=['i-0123456789abcdef0'], DocumentName='AWS-RunShellScript', Parameters={'commands':['uname -a']})
```

## 61. KMS — List KMS keys
```python
import boto3
kms = boto3.client('kms')
print([k['KeyId'] for k in kms.list_keys()['Keys']])
```

## 62. KMS — Encrypt plaintext
```python
import boto3, base64
kms = boto3.client('kms')
e = kms.encrypt(KeyId='alias/my-key', Plaintext=b'secret-bytes')
print(base64.b64encode(e['CiphertextBlob']).decode())
```

## 63. ROUTE53 — List hosted zones
```python
import boto3
r53 = boto3.client('route53')
print([z['Name'] for z in r53.list_hosted_zones()['HostedZones']])
```

## 64. CLOUDFRONT — List CloudFront dists
```python
import boto3
cf = boto3.client('cloudfront')
print([d['Id'] for d in cf.list_distributions()['DistributionList'].get('Items',[])])
```

## 65. ELB — Describe ALBs/NLBs
```python
import boto3
elbv2 = boto3.client('elbv2')
for lb in elbv2.describe_load_balancers()['LoadBalancers']:
    print(lb['LoadBalancerName'], lb['Type'], lb['DNSName'])
```

## 66. VPC — Describe route tables
```python
import boto3
ec2 = boto3.client('ec2')
print(ec2.describe_route_tables()['RouteTables'])
```

## 67. ATHENA — Run Athena query
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 1',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'}
)
```

## 68. GLUE — List Glue crawlers
```python
import boto3
glue = boto3.client('glue')
print([c['Name'] for c in glue.list_crawlers()['CrawlerNames']])
```

## 69. STEPFUNCTIONS — List Step Functions
```python
import boto3
sf = boto3.client('stepfunctions')
print([sm['name'] for sm in sf.list_state_machines()['stateMachines']])
```

## 70. CLOUDTRAIL — Describe trails
```python
import boto3
ct = boto3.client('cloudtrail')
print(ct.describe_trails()['trailList'])
```

## 71. ORGANIZATIONS — List Org accounts
```python
import boto3
org = boto3.client('organizations')
print([a['Name'] for a in org.list_accounts()['Accounts']])
```

## 72. EC2 — Paginator: describe_instances
```python
import boto3
client = boto3.client('ec2', region_name='us-east-1')
paginator = client.get_paginator('describe_instances')
for page in paginator.paginate({}):
    for item in page.get('Reservations', []):
        print(item)
```
*Notes:* Use paginators for large listings.

## 73. S3 — Paginator: list_objects_v2
```python
import boto3
client = boto3.client('s3', region_name='us-east-1')
paginator = client.get_paginator('list_objects_v2')
for page in paginator.paginate(Bucket='my-demo-bucket-12345'):
    for item in page.get('Contents', []):
        print(item)
```
*Notes:* Use paginators for large listings.

## 74. IAM — Paginator: list_users
```python
import boto3
client = boto3.client('iam', region_name='us-east-1')
paginator = client.get_paginator('list_users')
for page in paginator.paginate({}):
    for item in page.get('Users', []):
        print(item)
```
*Notes:* Use paginators for large listings.

## 75. Logs — Paginator: describe_log_groups
```python
import boto3
client = boto3.client('logs', region_name='us-east-1')
paginator = client.get_paginator('describe_log_groups')
for page in paginator.paginate({}):
    for item in page.get('logGroups', []):
        print(item)
```
*Notes:* Use paginators for large listings.

## 76. CloudFront — Paginator: list_distributions
```python
import boto3
client = boto3.client('cloudfront', region_name='us-east-1')
paginator = client.get_paginator('list_distributions')
for page in paginator.paginate({}):
    for item in page.get('Items', []):
        print(item)
```
*Notes:* Use paginators for large listings.

## 77. EC2 — Wait for instance running
```python
import boto3
ec2 = boto3.client('ec2')
w = ec2.get_waiter('instance_running')
w.wait(InstanceIds=['i-0123456789abcdef0'])
```
*Notes:* Built-in waiters simplify polling.

## 78. CloudFormation — Wait for stack create complete
```python
import boto3
cf = boto3.client('cloudformation')
w = cf.get_waiter('stack_create_complete')
w.wait(StackName='demo')
```
*Notes:* Built-in waiters simplify polling.

## 79. RDS — Wait for DB available
```python
import boto3
rds = boto3.client('rds')
rds.get_waiter('db_instance_available').wait(DBInstanceIdentifier='mydb')
```
*Notes:* Built-in waiters simplify polling.

## 80. Patterns — Retry wrapper #1
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 81. Patterns — Retry wrapper #2
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 82. Patterns — Retry wrapper #3
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 83. Patterns — Retry wrapper #4
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 84. Patterns — Retry wrapper #5
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 85. Patterns — Retry wrapper #6
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 86. Patterns — Retry wrapper #7
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 87. Patterns — Retry wrapper #8
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 88. Patterns — Retry wrapper #9
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 89. Patterns — Retry wrapper #10
```python
import time, boto3, botocore
client = boto3.client('s3')
for attempt in range(5):
    try:
        client.list_buckets()
        break
    except botocore.exceptions.ClientError as e:
        if attempt == 4: raise
        time.sleep(2**attempt)
```
*Notes:* Simple exponential backoff

## 90. EC2 — Tag VPC
```python
import boto3
ec2 = boto3.client('ec2')
ec2.create_tags(Resources=['vpc-0123456789abcdef0'], Tags=[{'Key':'Name','Value':'core'}])
```

## 91. EBS — Tag volume
```python
import boto3
ec2 = boto3.client('ec2')
ec2.create_tags(Resources=['vol-0123456789abcdef0'], Tags=[{'Key':'Env','Value':'prod'}])
```

## 92. S3 (resource) — Download object via resource #1
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file1.txt', f'/tmp/file1.txt')
```

## 93. S3 (resource) — Download object via resource #2
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file2.txt', f'/tmp/file2.txt')
```

## 94. S3 (resource) — Download object via resource #3
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file3.txt', f'/tmp/file3.txt')
```

## 95. S3 (resource) — Download object via resource #4
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file4.txt', f'/tmp/file4.txt')
```

## 96. S3 (resource) — Download object via resource #5
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file5.txt', f'/tmp/file5.txt')
```

## 97. S3 (resource) — Download object via resource #6
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file6.txt', f'/tmp/file6.txt')
```

## 98. S3 (resource) — Download object via resource #7
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file7.txt', f'/tmp/file7.txt')
```

## 99. S3 (resource) — Download object via resource #8
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file8.txt', f'/tmp/file8.txt')
```

## 100. S3 (resource) — Download object via resource #9
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file9.txt', f'/tmp/file9.txt')
```

## 101. S3 (resource) — Download object via resource #10
```python
import boto3
s3r = boto3.resource('s3')
s3r.Bucket('my-demo-bucket-12345').download_file('path/file10.txt', f'/tmp/file10.txt')
```

## 102. ELBv2 — Create target group
```python
import boto3
elbv2 = boto3.client('elbv2')
elbv2.create_target_group(Name='tg-web', Protocol='HTTP', Port=80, VpcId='vpc-0123456789abcdef0', TargetType='instance')
```

## 103. ELBv2 — Register targets
```python
import boto3
elbv2 = boto3.client('elbv2')
elbv2.register_targets(TargetGroupArn='arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-web/abc', Targets=[{'Id':'i-0123456789abcdef0'}])
```

## 104. SSM — RunShellScript on instance #1
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 1', 'hostname']})
```

## 105. SSM — RunShellScript on instance #2
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 2', 'hostname']})
```

## 106. SSM — RunShellScript on instance #3
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 3', 'hostname']})
```

## 107. SSM — RunShellScript on instance #4
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 4', 'hostname']})
```

## 108. SSM — RunShellScript on instance #5
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 5', 'hostname']})
```

## 109. SSM — RunShellScript on instance #6
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 6', 'hostname']})
```

## 110. SSM — RunShellScript on instance #7
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 7', 'hostname']})
```

## 111. SSM — RunShellScript on instance #8
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 8', 'hostname']})
```

## 112. SSM — RunShellScript on instance #9
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 9', 'hostname']})
```

## 113. SSM — RunShellScript on instance #10
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 10', 'hostname']})
```

## 114. SSM — RunShellScript on instance #11
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 11', 'hostname']})
```

## 115. SSM — RunShellScript on instance #12
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 12', 'hostname']})
```

## 116. SSM — RunShellScript on instance #13
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 13', 'hostname']})
```

## 117. SSM — RunShellScript on instance #14
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 14', 'hostname']})
```

## 118. SSM — RunShellScript on instance #15
```python
import boto3
ssm = boto3.client('ssm')
ssm.send_command(
    InstanceIds=['i-0123456789abcdef0'],
    DocumentName='AWS-RunShellScript',
    Parameters={'commands':[f'echo run 15', 'hostname']})
```

## 119. Athena — Query #1
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 1',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 120. Athena — Query #2
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 2',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 121. Athena — Query #3
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 3',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 122. Athena — Query #4
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 4',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 123. Athena — Query #5
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 5',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 124. Athena — Query #6
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 6',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 125. Athena — Query #7
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 7',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 126. Athena — Query #8
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 8',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 127. Athena — Query #9
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 9',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 128. Athena — Query #10
```python
import boto3
ath = boto3.client('athena')
ath.start_query_execution(
    QueryString='SELECT 10',
    QueryExecutionContext={'Database':'default'},
    ResultConfiguration={'OutputLocation':'s3://my-demo-bucket-12345/athena/'})
```

## 129. SQS — Receive messages #1
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 130. SQS — Receive messages #2
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 131. SQS — Receive messages #3
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 132. SQS — Receive messages #4
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 133. SQS — Receive messages #5
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 134. SQS — Receive messages #6
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 135. SQS — Receive messages #7
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 136. SQS — Receive messages #8
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 137. SQS — Receive messages #9
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 138. SQS — Receive messages #10
```python
import boto3
sqs = boto3.client('sqs')
resp = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', MaxNumberOfMessages=1, WaitTimeSeconds=10)
for m in resp.get('Messages', []):
    sqs.delete_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123456789012/demo', ReceiptHandle=m['ReceiptHandle'])
```

## 139. Logs Insights — Query #1
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 140. Logs Insights — Query #2
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 141. Logs Insights — Query #3
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 142. Logs Insights — Query #4
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 143. Logs Insights — Query #5
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 144. Logs Insights — Query #6
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 145. Logs Insights — Query #7
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 146. Logs Insights — Query #8
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 147. Logs Insights — Query #9
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 148. Logs Insights — Query #10
```python
import boto3, time
logs = boto3.client('logs')
qid = logs.start_query(
    logGroupName='/aws/lambda/my-func',
    startTime=int(time.time())-3600,
    endTime=int(time.time()),
    queryString='fields @timestamp, @message | sort @timestamp desc | limit 20')['queryId']
print(logs.get_query_results(queryId=qid))
```

## 149. KMS — Generate data key #1
```python
import boto3, base64
kms = boto3.client('kms')
dk = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
print(len(dk['Plaintext']), base64.b64encode(dk['CiphertextBlob']).decode())
```

## 150. KMS — Generate data key #2
```python
import boto3, base64
kms = boto3.client('kms')
dk = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
print(len(dk['Plaintext']), base64.b64encode(dk['CiphertextBlob']).decode())
```

## 151. KMS — Generate data key #3
```python
import boto3, base64
kms = boto3.client('kms')
dk = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
print(len(dk['Plaintext']), base64.b64encode(dk['CiphertextBlob']).decode())
```

## 152. KMS — Generate data key #4
```python
import boto3, base64
kms = boto3.client('kms')
dk = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
print(len(dk['Plaintext']), base64.b64encode(dk['CiphertextBlob']).decode())
```

## 153. KMS — Generate data key #5
```python
import boto3, base64
kms = boto3.client('kms')
dk = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
print(len(dk['Plaintext']), base64.b64encode(dk['CiphertextBlob']).decode())
```

## 154. Route53 — UPSERT A record #1
```python
import boto3
r53 = boto3.client('route53')
r53.change_resource_record_sets(
    HostedZoneId='Z1234567890',
    ChangeBatch={'Changes':[{'Action':'UPSERT','ResourceRecordSet':{'Name':'app1.example.com.','Type':'A','TTL':60,'ResourceRecords':[{'Value':'203.0.113.1'}]}}]})
```

## 155. Route53 — UPSERT A record #2
```python
import boto3
r53 = boto3.client('route53')
r53.change_resource_record_sets(
    HostedZoneId='Z1234567890',
    ChangeBatch={'Changes':[{'Action':'UPSERT','ResourceRecordSet':{'Name':'app2.example.com.','Type':'A','TTL':60,'ResourceRecords':[{'Value':'203.0.113.2'}]}}]})
```

## 156. Route53 — UPSERT A record #3
```python
import boto3
r53 = boto3.client('route53')
r53.change_resource_record_sets(
    HostedZoneId='Z1234567890',
    ChangeBatch={'Changes':[{'Action':'UPSERT','ResourceRecordSet':{'Name':'app3.example.com.','Type':'A','TTL':60,'ResourceRecords':[{'Value':'203.0.113.3'}]}}]})
```

## 157. Route53 — UPSERT A record #4
```python
import boto3
r53 = boto3.client('route53')
r53.change_resource_record_sets(
    HostedZoneId='Z1234567890',
    ChangeBatch={'Changes':[{'Action':'UPSERT','ResourceRecordSet':{'Name':'app4.example.com.','Type':'A','TTL':60,'ResourceRecords':[{'Value':'203.0.113.4'}]}}]})
```

## 158. Route53 — UPSERT A record #5
```python
import boto3
r53 = boto3.client('route53')
r53.change_resource_record_sets(
    HostedZoneId='Z1234567890',
    ChangeBatch={'Changes':[{'Action':'UPSERT','ResourceRecordSet':{'Name':'app5.example.com.','Type':'A','TTL':60,'ResourceRecords':[{'Value':'203.0.113.5'}]}}]})
```

## 159. CloudFront — Create invalidation #1
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 160. CloudFront — Create invalidation #2
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 161. CloudFront — Create invalidation #3
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 162. CloudFront — Create invalidation #4
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 163. CloudFront — Create invalidation #5
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 164. CloudFront — Create invalidation #6
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 165. CloudFront — Create invalidation #7
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 166. CloudFront — Create invalidation #8
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 167. CloudFront — Create invalidation #9
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 168. CloudFront — Create invalidation #10
```python
import boto3, time
cf = boto3.client('cloudfront')
cf.create_invalidation(DistributionId='E1234567890', InvalidationBatch={'Paths':{'Quantity':1,'Items':['/index.html']},'CallerReference':str(time.time())})
```

## 169. Secrets Manager — List ARNs #1
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['ARN'] for s in sec.list_secrets()['SecretList']])
```

## 170. Secrets Manager — List ARNs #2
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['ARN'] for s in sec.list_secrets()['SecretList']])
```

## 171. Secrets Manager — List ARNs #3
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['ARN'] for s in sec.list_secrets()['SecretList']])
```

## 172. Secrets Manager — List ARNs #4
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['ARN'] for s in sec.list_secrets()['SecretList']])
```

## 173. Secrets Manager — List ARNs #5
```python
import boto3
sec = boto3.client('secretsmanager')
print([s['ARN'] for s in sec.list_secrets()['SecretList']])
```

## 174. SSM — Put parameter #1
```python
import boto3
ssm = boto3.client('ssm')
ssm.put_parameter(Name='/demo/key1', Value='value1', Type='String', Overwrite=True)
```

## 175. SSM — Put parameter #2
```python
import boto3
ssm = boto3.client('ssm')
ssm.put_parameter(Name='/demo/key2', Value='value2', Type='String', Overwrite=True)
```

## 176. SSM — Put parameter #3
```python
import boto3
ssm = boto3.client('ssm')
ssm.put_parameter(Name='/demo/key3', Value='value3', Type='String', Overwrite=True)
```

## 177. SSM — Put parameter #4
```python
import boto3
ssm = boto3.client('ssm')
ssm.put_parameter(Name='/demo/key4', Value='value4', Type='String', Overwrite=True)
```

## 178. SSM — Put parameter #5
```python
import boto3
ssm = boto3.client('ssm')
ssm.put_parameter(Name='/demo/key5', Value='value5', Type='String', Overwrite=True)
```

## 179. STS — Assume role to acct #1
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789011:role/CrossAccountRead', RoleSessionName='xacct1')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 180. STS — Assume role to acct #2
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789012:role/CrossAccountRead', RoleSessionName='xacct2')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 181. STS — Assume role to acct #3
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789013:role/CrossAccountRead', RoleSessionName='xacct3')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 182. STS — Assume role to acct #4
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789014:role/CrossAccountRead', RoleSessionName='xacct4')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 183. STS — Assume role to acct #5
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789015:role/CrossAccountRead', RoleSessionName='xacct5')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 184. STS — Assume role to acct #6
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789016:role/CrossAccountRead', RoleSessionName='xacct6')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 185. STS — Assume role to acct #7
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789017:role/CrossAccountRead', RoleSessionName='xacct7')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 186. STS — Assume role to acct #8
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789018:role/CrossAccountRead', RoleSessionName='xacct8')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 187. STS — Assume role to acct #9
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::123456789019:role/CrossAccountRead', RoleSessionName='xacct9')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 188. STS — Assume role to acct #10
```python
import boto3
sts = boto3.client('sts')
creds = sts.assume_role(RoleArn='arn:aws:iam::1234567890110:role/CrossAccountRead', RoleSessionName='xacct10')['Credentials']
print(creds['AccessKeyId'][:4] + '...')
```

## 189. S3 — Multipart upload (put_object loop)
```python
import boto3, os
s3 = boto3.client('s3')
with open('/etc/hosts','rb') as f:
    s3.upload_fileobj(f, 'my-demo-bucket-12345', 'hosts')
```
*Notes:* boto3 manages multipart under the hood for large files.

## 190. EC2/VPC — Create flow logs to CW Logs
```python
import boto3
ec2 = boto3.client('ec2')
ec2.create_flow_logs(
    ResourceIds=['vpc-0123456789abcdef0'],
    ResourceType='VPC',
    TrafficType='ALL',
    LogDestinationType='cloud-watch-logs',
    LogGroupName='/vpc/flowlogs',
    DeliverLogsPermissionArn='arn:aws:iam::123456789012:role/FlowLogsToCW')
```

## 191. EKS — Get cluster list (prep for auth)
```python
import boto3
eks = boto3.client('eks')
print(eks.list_clusters())
```
*Notes:* For kubectl auth, use aws eks update-kubeconfig (CLI).

## 192. StepFunctions — Start execution #1
```python
import boto3, json
sf = boto3.client('stepfunctions')
sf.start_execution(stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:demo', input=json.dumps({'run':1}))
```

## 193. StepFunctions — Start execution #2
```python
import boto3, json
sf = boto3.client('stepfunctions')
sf.start_execution(stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:demo', input=json.dumps({'run':2}))
```

## 194. StepFunctions — Start execution #3
```python
import boto3, json
sf = boto3.client('stepfunctions')
sf.start_execution(stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:demo', input=json.dumps({'run':3}))
```

## 195. StepFunctions — Start execution #4
```python
import boto3, json
sf = boto3.client('stepfunctions')
sf.start_execution(stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:demo', input=json.dumps({'run':4}))
```

## 196. StepFunctions — Start execution #5
```python
import boto3, json
sf = boto3.client('stepfunctions')
sf.start_execution(stateMachineArn='arn:aws:states:us-east-1:123456789012:stateMachine:demo', input=json.dumps({'run':5}))
```

## 197. Glue — Start crawler #1
```python
import boto3
glue = boto3.client('glue')
glue.start_crawler(Name='crawler1')
```

## 198. Glue — Start crawler #2
```python
import boto3
glue = boto3.client('glue')
glue.start_crawler(Name='crawler2')
```

## 199. Glue — Start crawler #3
```python
import boto3
glue = boto3.client('glue')
glue.start_crawler(Name='crawler3')
```

## 200. Glue — Start crawler #4
```python
import boto3
glue = boto3.client('glue')
glue.start_crawler(Name='crawler4')
```

## 201. Glue — Start crawler #5
```python
import boto3
glue = boto3.client('glue')
glue.start_crawler(Name='crawler5')
```

## 202. CloudTrail — Lookup events #1
```python
import boto3, datetime
ct = boto3.client('cloudtrail')
print(ct.lookup_events(MaxResults=5))
```

## 203. CloudTrail — Lookup events #2
```python
import boto3, datetime
ct = boto3.client('cloudtrail')
print(ct.lookup_events(MaxResults=5))
```

## 204. CloudTrail — Lookup events #3
```python
import boto3, datetime
ct = boto3.client('cloudtrail')
print(ct.lookup_events(MaxResults=5))
```

## 205. CloudTrail — Lookup events #4
```python
import boto3, datetime
ct = boto3.client('cloudtrail')
print(ct.lookup_events(MaxResults=5))
```

## 206. CloudTrail — Lookup events #5
```python
import boto3, datetime
ct = boto3.client('cloudtrail')
print(ct.lookup_events(MaxResults=5))
```

## 207. Organizations — List ACTIVE accounts
```python
import boto3
org = boto3.client('organizations')
print([a['Id'] for a in org.list_accounts()['Accounts'] if a['Status']=='ACTIVE'])
```

## 208. AWS CLI — List S3 buckets via CLI
```python
import subprocess, json
out = subprocess.check_output(['aws','s3api','list-buckets','--output','json'])
print(json.loads(out)['Buckets'])
```
*Notes:* Sometimes calling CLI from Python is convenient.

## 209. AWS CLI — WhoAmI via CLI
```python
import subprocess, json
out = subprocess.check_output(['aws','sts','get-caller-identity','--output','json'])
print(json.loads(out))
```
*Notes:* Sometimes calling CLI from Python is convenient.

## 210. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #1
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 211. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #2
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 212. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #3
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 213. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #4
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 214. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #5
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 215. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #6
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 216. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #7
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 217. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #8
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 218. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #9
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 219. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #10
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 220. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #11
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 221. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #12
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 222. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #13
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 223. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #14
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 224. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #15
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 225. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #16
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 226. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #17
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 227. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #18
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 228. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #19
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 229. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #20
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 230. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #21
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 231. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #22
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 232. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #23
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 233. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #24
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 234. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #25
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 235. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #26
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 236. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #27
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 237. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #28
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 238. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #29
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 239. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #30
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 240. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #31
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 241. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #32
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 242. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #33
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 243. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #34
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 244. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #35
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 245. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #36
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 246. EC2 (variants) — Describe instances filtered (state=running, tag=Env:test) #37
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['running']},
    {'Name':'tag:Env','Values':['test']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 247. EC2 (variants) — Describe instances filtered (state=stopping, tag=Env:stage) #38
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopping']},
    {'Name':'tag:Env','Values':['stage']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 248. EC2 (variants) — Describe instances filtered (state=stopped, tag=Env:prod) #39
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['stopped']},
    {'Name':'tag:Env','Values':['prod']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 249. EC2 (variants) — Describe instances filtered (state=terminated, tag=Env:qa) #40
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['terminated']},
    {'Name':'tag:Env','Values':['qa']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern

## 250. EC2 (variants) — Describe instances filtered (state=pending, tag=Env:dev) #41
```python
import boto3
ec2 = boto3.client('ec2')
resp = ec2.describe_instances(Filters=[
    {'Name':'instance-state-name','Values':['pending']},
    {'Name':'tag:Env','Values':['dev']}
])
print([i['InstanceId'] for r in resp['Reservations'] for i in r['Instances']])
```
*Notes:* Common filter pattern
