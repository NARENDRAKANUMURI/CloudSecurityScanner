import boto3
import json

iam = boto3.client("iam")


def iam_security_audit():

    findings = []
    risk_score = 0

    users = iam.list_users()

    print("\n========== IAM SECURITY AUDIT ==========\n")

    for user in users["Users"]:

        username = user["UserName"]

        # MFA Check
        mfa_devices = iam.list_mfa_devices(
            UserName=username
        )

        mfa_enabled = len(
            mfa_devices["MFADevices"]
        ) > 0

        # Admin Access Check
        attached_policies = iam.list_attached_user_policies(
            UserName=username
        )

        is_admin = False

        for policy in attached_policies["AttachedPolicies"]:

            if policy["PolicyName"] == "AdministratorAccess":
                is_admin = True

        # Access Key Check
        keys = iam.list_access_keys(
            UserName=username
        )

        key_count = len(
            keys["AccessKeyMetadata"]
        )

        print(f"User : {username}")
        print(f"MFA : {'Enabled ✅' if mfa_enabled else 'Disabled ❌'}")
        print(f"Admin Access : {'Yes ⚠️' if is_admin else 'No ✅'}")
        print(f"Active Keys : {key_count}")
        print()

        if not mfa_enabled:
            findings.append(
                f"{username} does not have MFA enabled"
            )
            risk_score += 20

        if is_admin:
            findings.append(
                f"{username} has AdministratorAccess"
            )
            risk_score += 30

        if key_count > 1:
            findings.append(
                f"{username} has multiple access keys"
            )
            risk_score += 10

    print("\n========== FINDINGS ==========\n")

    if findings:
        for finding in findings:
            print("⚠️", finding)
    else:
        print("No Findings 🎉")

    print("\n========== RISK SCORE ==========\n")

    print("Score :", risk_score)

    if risk_score < 20:
        severity = "LOW"
        print("LOW RISK ✅")

    elif risk_score < 50:
        severity = "MEDIUM"
        print("MEDIUM RISK ⚠️")

    else:
        severity = "HIGH"
        print("HIGH RISK 🚨")

    return findings, risk_score, severity


def password_policy_audit():

    print("\n========== PASSWORD POLICY ==========\n")

    try:

        policy = iam.get_account_password_policy()

        p = policy["PasswordPolicy"]

        print("Minimum Length :", p["MinimumPasswordLength"])

        print(
            "Require Symbols :",
            "✅" if p["RequireSymbols"] else "❌"
        )

        print(
            "Require Numbers :",
            "✅" if p["RequireNumbers"] else "❌"
        )

        print(
            "Require Uppercase :",
            "✅" if p["RequireUppercaseCharacters"] else "❌"
        )

        print(
            "Require Lowercase :",
            "✅" if p["RequireLowercaseCharacters"] else "❌"
        )

    except iam.exceptions.NoSuchEntityException:

        print("No Password Policy Found ❌")


def account_summary():

    print("\n========== ACCOUNT SUMMARY ==========\n")

    response = iam.get_account_summary()

    summary = response["SummaryMap"]

    print("Users :", summary["Users"])
    print("Groups :", summary["Groups"])
    print("Policies :", summary["Policies"])
    print("MFA Devices :", summary["MFADevices"])
    print(
        "Access Keys Per User Quota :",
        summary["AccessKeysPerUserQuota"]
    )


def generate_report(findings, risk_score, severity):

    report = {
        "findings": findings,
        "risk_score": risk_score,
        "severity": severity
    }

    with open("reports/report.json", "w") as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print("\nJSON Report Generated ✅")


if __name__ == "__main__":

    findings, risk_score, severity = iam_security_audit()

    password_policy_audit()

    account_summary()

    generate_report(
        findings,
        risk_score,
        severity
    )