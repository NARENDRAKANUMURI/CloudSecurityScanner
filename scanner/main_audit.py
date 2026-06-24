from iam_audit import (
    iam_security_audit,
    password_policy_audit,
    account_summary,
    generate_report
)

from s3_audit import (
    public_bucket_audit,
    bucket_encryption_audit,
    versioning_audit,
    s3_risk_score,
    generate_s3_report
)

from ec2_audit import (
    ec2_enumeration,
    security_group_enumeration,
    ssh_exposure_audit,
    dangerous_ports_audit,
    ec2_risk_score
)


def run_audit():

    print("\n====================================")
    print("     CLOUD SECURITY SCANNER")
    print("====================================")

    # ================= IAM =================
    print("\n========== IAM AUDIT ==========")

    findings, risk_score, severity = iam_security_audit()

    password_policy_audit()

    account_summary()

    generate_report(
        findings,
        risk_score,
        severity
    )

    # ================= S3 =================
    print("\n========== S3 AUDIT ==========")

    public_bucket_audit()

    bucket_encryption_audit()

    versioning_audit()

    s3_risk_score()

    generate_s3_report()

    # ================= EC2 =================
    print("\n========== EC2 AUDIT ==========")

    ec2_enumeration()

    security_group_enumeration()

    ssh_exposure_audit()

    dangerous_ports_audit()

    ec2_risk_score()

    print("\n====================================")
    print("       AUDIT COMPLETED ✅")
    print("====================================")


if __name__ == "__main__":
    run_audit()