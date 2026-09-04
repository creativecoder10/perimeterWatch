"""
config_checker.s3_checks
=========================
Checks S3 buckets in the connected AWS account for two common
misconfigurations that map to CIS AWS Foundations Benchmark controls:

- Missing or incomplete Public Access Block settings (CIS 2.1.5-ish area)
- Missing default server-side encryption (CIS 2.1.1-ish area)

All checks are read-only: this module never modifies AWS resources.
"""

import boto3
from botocore.exceptions import ClientError
from common.schema import Finding


def check_buckets(s3_client=None):
    """
    Run all S3 checks against every bucket in the account.

    Args:
        s3_client: An optional pre-built boto3 S3 client. If omitted, a
            real client is created automatically. Tests pass in a
            moto-mocked client here instead, so this function never
            needs to touch a real AWS account during test runs.

    Returns:
        list[Finding]: One Finding per issue detected, across all buckets.
            An empty list means no issues were found.
    """
    # Fall back to a real boto3 client only if the caller didn't supply
    # one — this is what makes the function testable (dependency injection).
    client = s3_client or boto3.client("s3")
    findings = []

    # list_buckets() returns ALL buckets in the account in one call —
    # no pagination needed, S3 doesn't paginate this particular API.
    buckets = client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        # Each bucket gets checked independently; a problem in one
        # bucket doesn't stop us from checking the rest.
        findings.extend(_check_public_access(client, name))
        findings.extend(_check_encryption(client, name))

    return findings


def _check_public_access(client, bucket_name):
    """
    Check whether a single bucket fully blocks public access.

    AWS's Public Access Block feature has four independent boolean
    settings. All four must be True for a bucket to be considered
    fully protected — if even one is False, the bucket could still
    be exposed to the public internet in some way.

    Args:
        client: An active boto3 S3 client.
        bucket_name (str): Name of the bucket to check.

    Returns:
        list[Finding]: Zero or one Finding, depending on the result.
    """
    findings = []
    try:
        config = client.get_public_access_block(Bucket=bucket_name)
        block_config = config["PublicAccessBlockConfiguration"]

        # .values() gives us just the four booleans, discarding the
        # setting names. all(...) is True only if every value is True.
        if not all(block_config.values()):
            findings.append(Finding(
                source="config_checker.s3",
                severity="high",
                finding=f"Bucket '{bucket_name}' does not fully block public access",
            ))
    except ClientError as e:
        # AWS raises this specific error code when a bucket has NO
        # Public Access Block configuration at all — which is actually
        # worse than having one with a setting turned off, so it's
        # handled as its own explicit case rather than falling through.
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append(Finding(
                source="config_checker.s3",
                severity="high",
                finding=f"Bucket '{bucket_name}' has no Public Access Block configuration",
            ))
        # Any other ClientError (permissions issue, throttling, etc.)
        # is intentionally NOT caught here — it will propagate up and
        # surface as a real error rather than being silently swallowed.
    return findings


def _check_encryption(client, bucket_name):
    """
    Check whether a bucket has default server-side encryption enabled.

    Args:
        client: An active boto3 S3 client.
        bucket_name (str): Name of the bucket to check.

    Returns:
        list[Finding]: Zero or one Finding, depending on the result.
    """
    findings = []
    try:
        # get_bucket_encryption() only returns successfully if
        # encryption IS configured — we don't need to inspect its
        # contents, just whether the call succeeds or raises.
        client.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(Finding(
                source="config_checker.s3",
                severity="medium",
                finding=f"Bucket '{bucket_name}' has no default encryption configured",
            ))
    return findings