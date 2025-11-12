# import AWS SDK for Python (Boto3) fist do permissions
import boto3

# client to call operations on S3
s3=boto3.client('s3')

#function that is equal to aws s3 ls
response = s3.list_buckets()

# print the response
print(response)
