import boto3
import pytest
from moto import mock_aws
from config_checker.s3_checks import check_buckets


@mock_aws
def test_flags_bucket_with_no_public_access_block():
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="insecure-bucket")

    findings = check_buckets(client)

    messages = [f.finding for f in findings]
    assert any("Public Access Block" in m for m in messages)


@mock_aws
def test_flags_bucket_with_no_encryption():
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="unencrypted-bucket")
    client.put_public_access_block(
        Bucket="unencrypted-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )

    findings = check_buckets(client)

    messages = [f.finding for f in findings]
    assert any("no default encryption" in m for m in messages)


@mock_aws
def test_clean_bucket_produces_no_findings():
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="secure-bucket")
    client.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    client.put_bucket_encryption(
        Bucket="secure-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    findings = check_buckets(client)

    assert findings == []