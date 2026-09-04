import boto3
import pytest
from moto import mock_aws
from config_checker.sg_checks import check_security_groups


@mock_aws
def test_flags_open_ssh_port():
    client = boto3.client("ec2", region_name="us-east-1")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = client.create_security_group(GroupName="open-ssh", Description="test", VpcId=vpc)
    client.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    findings = check_security_groups(client)

    messages = [f.finding for f in findings]
    assert any("SSH" in m and "open-ssh" in m for m in messages)


@mock_aws
def test_locked_down_sg_produces_no_findings():
    client = boto3.client("ec2", region_name="us-east-1")
    vpc = client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    client.create_security_group(GroupName="locked-down", Description="test", VpcId=vpc)

    findings = check_security_groups(client)

    assert findings == []