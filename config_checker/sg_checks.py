"""Checks EC2 Security Groups for overly permissive inbound rules."""
import boto3
from common.schema import Finding

RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}
OPEN_CIDR = "0.0.0.0/0"


def check_security_groups(ec2_client=None):
    """Returns a list of Finding objects for all EC2 security groups in the account."""
    client = ec2_client or boto3.client("ec2")
    findings = []

    response = client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        findings.extend(_check_inbound_rules(sg))

    return findings


def _check_inbound_rules(sg):
    findings = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)

    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == OPEN_CIDR:
                if from_port in RISKY_PORTS:
                    service = RISKY_PORTS[from_port]
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="critical",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows {service} "
                                f"(port {from_port}) open to the internet (0.0.0.0/0)",
                    ))
                elif from_port is None and to_port is None:
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="critical",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows ALL traffic "
                                f"open to the internet (0.0.0.0/0)",
                    ))
                else:
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="medium",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows port "
                                f"{from_port}-{to_port} open to the internet (0.0.0.0/0)",
                    ))

    return findings