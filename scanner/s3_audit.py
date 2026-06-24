import boto3
import json

s3 = boto3.client("s3")


def public_bucket_audit():

    findings = []

    response = s3.list_buckets()

    print("\n========== S3 PUBLIC ACCESS AUDIT ==========\n")

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        print("Bucket :", bucket_name)

        try:

            status = s3.get_bucket_policy_status(
                Bucket=bucket_name
            )

            is_public = status["PolicyStatus"]["IsPublic"]

            if is_public:

                print("Public Access : YES 🚨")

                findings.append(
                    f"{bucket_name} is PUBLIC"
                )

            else:

                print("Public Access : NO ✅")

        except Exception:

            print(
                "Policy Status Not Available"
            )

        print()

    print(
        "\n========== FINDINGS ==========\n"
    )

    if findings:

        for finding in findings:

            print("⚠️", finding)

    else:

        print("No Public Buckets 🎉")

def bucket_encryption_audit():

    findings = []

    response = s3.list_buckets()

    print("\n========== BUCKET ENCRYPTION AUDIT ==========\n")

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        print("Bucket :", bucket_name)

        try:

            s3.get_bucket_encryption(
                Bucket=bucket_name
            )

            print(
                "Encryption : Enabled ✅"
            )

        except Exception:

            print(
                "Encryption : Disabled ❌"
            )

            findings.append(
                f"{bucket_name} encryption disabled"
            )

        print()

    print(
        "\n========== FINDINGS ==========\n"
    )

    if findings:

        for finding in findings:

            print(
                "⚠️",
                finding
            )

    else:

        print(
            "All Buckets Encrypted 🎉"
        )
def versioning_audit():

    findings = []

    response = s3.list_buckets()

    print("\n========== VERSIONING AUDIT ==========\n")

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        print("Bucket :", bucket_name)

        response = s3.get_bucket_versioning(
            Bucket=bucket_name
        )

        status = response.get(
            "Status",
            "Disabled"
        )

        if status == "Enabled":

            print(
                "Versioning : Enabled ✅"
            )

        else:

            print(
                "Versioning : Disabled ❌"
            )

            findings.append(
                f"{bucket_name} versioning disabled"
            )

        print()

    print(
        "\n========== FINDINGS ==========\n"
    )

    if findings:

        for finding in findings:

            print(
                "⚠️",
                finding
            )

    else:

        print(
            "Versioning Enabled Everywhere 🎉"
        )
def s3_risk_score():

    findings = []
    risk_score = 0

    response = s3.list_buckets()

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        # Public Bucket Check
        try:

            status = s3.get_bucket_policy_status(
                Bucket=bucket_name
            )

            if status["PolicyStatus"]["IsPublic"]:

                findings.append(
                    f"{bucket_name} is PUBLIC"
                )

                risk_score += 30

        except:
            pass

        # Encryption Check
        try:

            s3.get_bucket_encryption(
                Bucket=bucket_name
            )

        except:

            findings.append(
                f"{bucket_name} encryption disabled"
            )

            risk_score += 20

        # Versioning Check
        response = s3.get_bucket_versioning(
            Bucket=bucket_name
        )

        status = response.get(
            "Status",
            "Disabled"
        )

        if status != "Enabled":

            findings.append(
                f"{bucket_name} versioning disabled"
            )

            risk_score += 10

    print("\n========== S3 RISK SCORE ==========\n")

    for finding in findings:

        print("⚠️", finding)

    print()

    print("Risk Score :", risk_score)

    if risk_score < 20:

        print("LOW RISK ✅")

    elif risk_score < 50:

        print("MEDIUM RISK ⚠️")

    else:

        print("HIGH RISK 🚨")

def generate_s3_report():

    findings = []
    risk_score = 0

    response = s3.list_buckets()

    for bucket in response["Buckets"]:

        bucket_name = bucket["Name"]

        # Public Check
        try:

            status = s3.get_bucket_policy_status(
                Bucket=bucket_name
            )

            if status["PolicyStatus"]["IsPublic"]:

                findings.append(
                    f"{bucket_name} is PUBLIC"
                )

                risk_score += 30

        except:
            pass

        # Encryption Check
        try:

            s3.get_bucket_encryption(
                Bucket=bucket_name
            )

        except:

            findings.append(
                f"{bucket_name} encryption disabled"
            )

            risk_score += 20

        # Versioning
        response = s3.get_bucket_versioning(
            Bucket=bucket_name
        )

        status = response.get(
            "Status",
            "Disabled"
        )

        if status != "Enabled":

            findings.append(
                f"{bucket_name} versioning disabled"
            )

            risk_score += 10

    severity = "LOW"

    if risk_score >= 50:
        severity = "HIGH"

    elif risk_score >= 20:
        severity = "MEDIUM"

    report = {

        "risk_score": risk_score,

        "severity": severity,

        "findings": findings
    }

    with open(
        "reports/s3_report.json",
        "w"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(
        "\nS3 JSON Report Generated ✅"
    )
if __name__=="__main__":

    public_bucket_audit()

    bucket_encryption_audit()

    versioning_audit()

    s3_risk_score()

    generate_s3_report()