"""
config_checker.sg_checks
==========================
Checks EC2 Security Groups for inbound rules that are open to the
entire internet (0.0.0.0/0), which maps to CIS AWS Foundations
Benchmark controls around restricting remote access to well-known
risky ports (SSH, RDP, common database ports).

Read-only: this module never modifies security group rules.
"""

import boto3
from common.schema import Finding

# Ports considered high-risk if exposed to the whole internet.
# Keyed by port number so lookups in _check_inbound_rules are O(1).
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}

# The CIDR block that means "anyone on the internet" in AWS's model.
OPEN_CIDR = "0.0.0.0/0"


def check_security_groups(ec2_client=None):
    """
    Run inbound-rule checks against every security group in the account.

    Args:
        ec2_client: An optional pre-built boto3 EC2 client. Tests pass
            in a moto-mocked client instead of a real one.

    Returns:
        list[Finding]: One Finding per risky inbound rule detected,
            across all security groups.
    """
    client = ec2_client or boto3.client("ec2")
    findings = []

    # describe_security_groups() with no filters returns every
    # security group in the account/region.
    response = client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        findings.extend(_check_inbound_rules(sg))

    return findings


def _check_inbound_rules(sg):
    """
    Inspect a single security group's inbound rules for open access.

    A security group's IpPermissions is a list of rules; each rule can
    have multiple IpRanges (CIDR blocks) attached to it. We only flag
    a rule if one of its CIDR blocks is exactly 0.0.0.0/0 — meaning
    truly open to the whole internet, not just a specific IP range.

    Args:
        sg (dict): A single security group dict, as returned by
            describe_security_groups()['SecurityGroups'].

    Returns:
        list[Finding]: One Finding per risky open rule found.
    """
    findings = []
    sg_id = sg["GroupId"]
    # Fall back to the ID if no friendly name is set — GroupName is
    # optional on some security groups (e.g. the default VPC one).
    sg_name = sg.get("GroupName", sg_id)

    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        for ip_range in perm.get("IpRanges", []):
            if ip_range.get("CidrIp") == OPEN_CIDR:

                # Case 1: the open port matches a known high-risk service.
                if from_port in RISKY_PORTS:
                    service = RISKY_PORTS[from_port]
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="critical",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows {service} "
                                f"(port {from_port}) open to the internet (0.0.0.0/0)",
                    ))

                # Case 2: from_port/to_port are BOTH None, which in AWS's
                # model means "all ports, all protocols" — the most
                # dangerous possible rule, so it gets its own message
                # rather than being described as a numeric port range.
                elif from_port is None and to_port is None:
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="critical",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows ALL traffic "
                                f"open to the internet (0.0.0.0/0)",
                    ))

                # Case 3: some other open port/range that isn't in our
                # explicit risky-ports list — still worth flagging, but
                # at medium rather than critical severity since it's
                # not a known high-value target like SSH or RDP.
                else:
                    findings.append(Finding(
                        source="config_checker.security_group",
                        severity="medium",
                        finding=f"Security group '{sg_name}' ({sg_id}) allows port "
                                f"{from_port}-{to_port} open to the internet (0.0.0.0/0)",
                    ))

    return findings