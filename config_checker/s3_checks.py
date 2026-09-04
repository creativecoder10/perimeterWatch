"""Checks S3 buckets for public access and missing encryption."""
import boto3
from botocore.exceptions import ClientError
from common.schema import Finding


def check_buckets(s3_client=None):
    """Returns a list of Finding objects for all S3 buckets in the account."""
    client = s3_client or boto3.client("s3")
    findings = []

    buckets = client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        findings.extend(_check_public_access(client, name))
        findings.extend(_check_encryption(client, name))

    return findings


def _check_public_access(client, bucket_name):
    findings = []
    try:
        config = client.get_public_access_block(Bucket=bucket_name)
        block_config = config["PublicAccessBlockConfiguration"]
        if not all(block_config.values()):
            findings.append(Finding(
                source="config_checker.s3",
                severity="high",
                finding=f"Bucket '{bucket_name}' does not fully block public access",
            ))
    except ClientError as e:
        # No public access block configured at all = high risk
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append(Finding(
                source="config_checker.s3",
                severity="high",
                finding=f"Bucket '{bucket_name}' has no Public Access Block configuration",
            ))
    return findings


def _check_encryption(client, bucket_name):
    findings = []
    try:
        client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(Finding(
                source="config_checker.s3",
                severity="medium",
                finding=f"Bucket '{bucket_name}' has no default encryption configured",
            ))
    return findings