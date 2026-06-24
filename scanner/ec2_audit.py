import boto3
import json

ec2 = boto3.client(
    "ec2",
    region_name="ap-southeast-2"
)


def ec2_enumeration():

    findings = []

    print("\n========== EC2 AUDIT ==========\n")

    response = ec2.describe_instances()

    reservations = response["Reservations"]

    if len(reservations) == 0:

        print("No Instances Found")

        return

    for reservation in reservations:

        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            state = instance["State"]["Name"]

            instance_type = instance["InstanceType"]

            public_ip = instance.get(
                "PublicIpAddress",
                "No Public IP"
            )

            print("Instance ID :", instance_id)
            print("State :", state)
            print("Instance Type :", instance_type)
            print("Public IP :", public_ip)

            if public_ip != "No Public IP":

                findings.append(
                    f"{instance_id} has public IP exposure"
                )

                print("Exposure : YES 🚨")

            else:

                print("Exposure : NO ✅")

            print()

    print("\n========== FINDINGS ==========\n")

    if findings:

        for finding in findings:

            print("⚠️", finding)

    else:

        print("No Findings 🎉")


def security_group_enumeration():

    print("\n========== SECURITY GROUP ENUMERATION ==========\n")

    response = ec2.describe_instances()

    reservations = response["Reservations"]

    if len(reservations) == 0:

        print("No Instances Found")

        return

    for reservation in reservations:

        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            print("Instance ID :", instance_id)

            print("\nAttached Security Groups:\n")

            groups = instance["SecurityGroups"]

            for group in groups:

                print("Group ID :", group["GroupId"])

                print("Group Name :", group["GroupName"])

                print()

def ssh_exposure_audit():

    findings = []

    print("\n========== SSH EXPOSURE AUDIT ==========\n")

    response = ec2.describe_security_groups()

    groups = response["SecurityGroups"]

    for group in groups:

        group_name = group["GroupName"]

        group_id = group["GroupId"]

        for permission in group["IpPermissions"]:

            from_port = permission.get("FromPort")

            to_port = permission.get("ToPort")

            if from_port == 22 and to_port == 22:

                for ip_range in permission.get(
                    "IpRanges", []
                ):

                    cidr = ip_range["CidrIp"]

                    print(
                        "Security Group :",
                        group_name
                    )

                    print(
                        "Group ID :",
                        group_id
                    )

                    print(
                        "Port : 22"
                    )

                    print(
                        "Source :",
                        cidr
                    )

                    if cidr == "0.0.0.0/0":

                        findings.append(
                            f"{group_name} exposes SSH to the Internet"
                        )

                        print(
                            "SSH Exposure : YES 🚨"
                        )

                    else:

                        print(
                            "SSH Exposure : NO ✅"
                        )

                    print()

    print("\n========== FINDINGS ==========\n")

    if findings:

        for finding in findings:

            print("⚠️", finding)

    else:

        print("No SSH Exposure 🎉")

def dangerous_ports_audit():

    findings = []

    print("\n========== DANGEROUS PORTS AUDIT ==========\n")

    response = ec2.describe_security_groups()

    groups = response["SecurityGroups"]

    for group in groups:

        group_name = group["GroupName"]

        for permission in group["IpPermissions"]:

            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            for ip_range in permission.get(
                "IpRanges", []
            ):

                cidr = ip_range["CidrIp"]

                # RDP Exposure
                if (
                    from_port == 3389
                    and to_port == 3389
                    and cidr == "0.0.0.0/0"
                ):

                    findings.append(
                        f"{group_name} exposes RDP to Internet"
                    )

                    print(
                        "RDP Exposure 🚨"
                    )

                # All Traffic
                if (
                    from_port is None
                    and to_port is None
                    and cidr == "0.0.0.0/0"
                ):

                    findings.append(
                        f"{group_name} allows ALL traffic"
                    )

                    print(
                        "All Traffic Allowed 🚨"
                    )

    print("\n========== FINDINGS ==========\n")

    if findings:

        for finding in findings:

            print("⚠️", finding)

    else:

        print(
            "No Dangerous Ports Found 🎉"
        )

def ec2_risk_score():

    findings = []
    risk_score = 0

    # Public IP Exposure
    response = ec2.describe_instances()

    for reservation in response["Reservations"]:

        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            public_ip = instance.get(
                "PublicIpAddress"
            )

            if public_ip:

                findings.append(
                    f"{instance_id} has public IP exposure"
                )

                risk_score += 20

    # Security Groups
    groups = ec2.describe_security_groups()

    for group in groups["SecurityGroups"]:

        group_name = group["GroupName"]

        for permission in group["IpPermissions"]:

            from_port = permission.get(
                "FromPort"
            )

            to_port = permission.get(
                "ToPort"
            )

            for ip_range in permission.get(
                "IpRanges",
                []
            ):

                cidr = ip_range["CidrIp"]

                # SSH
                if (
                    from_port == 22
                    and to_port == 22
                    and cidr == "0.0.0.0/0"
                ):

                    findings.append(
                        f"{group_name} exposes SSH"
                    )

                    risk_score += 30

                # RDP
                if (
                    from_port == 3389
                    and to_port == 3389
                    and cidr == "0.0.0.0/0"
                ):

                    findings.append(
                        f"{group_name} exposes RDP"
                    )

                    risk_score += 30

                # All Traffic
                if (
                    from_port is None
                    and to_port is None
                    and cidr == "0.0.0.0/0"
                ):

                    findings.append(
                        f"{group_name} allows all traffic"
                    )

                    risk_score += 50

    print(
        "\n========== EC2 RISK SCORE ==========\n"
    )

    for finding in findings:

        print("⚠️", finding)

    print()

    print(
        "Risk Score :",
        risk_score
    )

    if risk_score < 20:

        severity = "LOW"

        print(
            "LOW RISK ✅"
        )

    elif risk_score < 50:

        severity = "MEDIUM"

        print(
            "MEDIUM RISK ⚠️"
        )

    else:

        severity = "HIGH"

        print(
            "HIGH RISK 🚨"
        )

    report = {

        "findings": findings,

        "risk_score": risk_score,

        "severity": severity

    }

    with open(
        "reports/ec2_report.json",
        "w"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(
        "\nEC2 JSON Report Generated ✅"
    )

if __name__ == "__main__":

    ec2_enumeration()

    security_group_enumeration()

    ssh_exposure_audit()

    dangerous_ports_audit()

    ec2_risk_score()