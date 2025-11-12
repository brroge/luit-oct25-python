# import AWS SDK for Python (Boto3) fist do permissions
import boto3

# client to call operations on S3
s3 = boto3.client('s3')

# load in memory file name then rb is bytes and f as file for Body
with open('hello.py', 'rb') as f:

#function for uploading files to S3 bucket
    s3.put_object(Bucket='awsbarnell', Key='hello.py', Body=f)