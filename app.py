"""Streamlit authentication module for FranchiseOps AI - Infosys Springboard Milestone 1."""
import hmac
import os
import re
import secrets
import time

import streamlit as st

from auth_utils import (
    decode_token,
    hash_otp,
    hash_password,
    issue_token,
    normalize_answer,
    password_issues,
    send_otp_email,
    validate_email,
    verify_hash,
    verify_otp,
)
from database import (
    clear_otp,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_login,
    get_user_by_username,
    increment_otp_attempts,
    init_db,
    list_users,
    save_otp,
    update_password,
)

st.set_page_config(page_title="FranchiseOps AI | Authentication", page_icon="🏬", layout="wide")

APP_REQUIRED_SECRETS = ["JWT_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD", "EMAIL_ADDRESS", "EMAIL_PASSWORD"]
missing = [name for name in APP_REQUIRED_SECRETS if not os.environ.get(name)]
if missing:
    st.error("Missing Colab Secrets: " + ", ".join(missing) + ". Re-run the Secrets setup cell in the notebook.")
    st.stop()
if len(os.environ.get("JWT_SECRET", "")) < 32:
    st.error("JWT_SECRET must be a long random string of at least 32 characters.")
    st.stop()

init_db()

SECURITY_QUESTIONS = [
    "What was the name of your first school?",
    "What city were you born in?",
    "What was your childhood nickname?",
    "What was the first name of your best friend?",
]


def set_view(view_name):
    st.session_state["view"] = view_name


def flash(kind, message):
    st.session_state["flash_message"] = (kind, message)


def get_current_user():
    token = st.session_state.get("jwt_token")
    claims = decode_token(token)
    if not claims or claims.get("role") != "user":
        st.session_state.pop("jwt_token", None)
        return None
    try:
        user = get_user_by_id(int(claims.get("sub", "")))
    except (TypeError, ValueError):
        user = None
    if user is None:
        st.session_state.pop("jwt_token", None)
    return user


def get_current_admin():
    claims = decode_token(st.session_state.get("admin_jwt_token"))
    if claims and claims.get("role") == "admin" and claims.get("sub") == "admin":
        return claims
    st.session_state.pop("admin_jwt_token", None)
    return None


def show_password_rules():
    st.caption("Password rules: 8+ characters, uppercase, lowercase, number, and special symbol.")


def show_password_issues(password):
    issues = password_issues(password)
    if issues:
        st.error("Password must include: " + "; ".join(issues) + ".")
    return not issues


if "view" not in st.session_state:
    st.session_state["view"] = "Login"
if "jwt_token" not in st.session_state:
    st.session_state["jwt_token"] = None
if "admin_jwt_token" not in st.session_state:
    st.session_state["admin_jwt_token"] = None
if "recovery_username" not in st.session_state:
    st.session_state["recovery_username"] = None
if "otp_email" not in st.session_state:
    st.session_state["otp_email"] = None

with st.sidebar:
    st.title("🏬 FranchiseOps AI")
    st.caption("Franchise Operations Intelligence Platform")
    st.divider()
    st.button("Login", on_click=set_view, args=("Login",), use_container_width=True)
    st.button("Sign Up", on_click=set_view, args=("Sign Up",), use_container_width=True)
    st.button("Forgot Password", on_click=set_view, args=("Forgot Password",), use_container_width=True)
    st.button("Admin Login", on_click=set_view, args=("Admin Login",), use_container_width=True)
    st.divider()
    st.caption("Infosys Springboard Internship 7.0 · Batch 4 · Milestone 1")

current_user = get_current_user()
current_admin = get_current_admin()
view = st.session_state.get("view", "Login")

# A valid user JWT protects the Dashboard from direct unauthenticated access.
if current_user and view != "Admin Login":
    st.session_state["view"] = "Dashboard"
    view = "Dashboard"
elif not current_user and view == "Dashboard":
    st.session_state["view"] = "Login"
    view = "Login"

pending_flash = st.session_state.pop("flash_message", None)
if pending_flash:
    kind, message = pending_flash
    getattr(st, kind, st.info)(message)


if view == "Login":
    st.title("Welcome back")
    st.subheader("Login to FranchiseOps AI")
    st.write("Monitor franchise operations from one intelligent workspace.")
    with st.form("login_form"):
        login_identifier = st.text_input("Username or Email *")
        login_password = st.text_input("Password *", type="password")
        login_clicked = st.form_submit_button("Login", use_container_width=True)

    if login_clicked:
        if not login_identifier.strip() or not login_password:
            st.error("Please fill in both fields.")
        else:
            user = get_user_by_login(login_identifier)
            if user and verify_hash(login_password, user["password_hash"]):
                st.session_state["jwt_token"] = issue_token(
                    subject=user["id"], role="user", username=user["username"], email=user["email"]
                )
                st.session_state["view"] = "Dashboard"
                st.rerun()
            else:
                # One generic error avoids saying whether the account exists.
                st.error("Invalid username/email or password.")

    st.caption("New to FranchiseOps AI? Select Sign Up in the sidebar.")


elif view == "Sign Up":
    st.title("Create your account")
    st.write("Create a user account to access the FranchiseOps AI workspace.")
    show_password_rules()
    with st.form("signup_form"):
        username = st.text_input("Username *", max_chars=30)
        email = st.text_input("Email *")
        password = st.text_input("Password *", type="password")
        confirm_password = st.text_input("Confirm Password *", type="password")
        security_question = st.selectbox("Security Question *", SECURITY_QUESTIONS)
        security_answer = st.text_input("Security Answer *", type="password")
        signup_clicked = st.form_submit_button("Create Account", use_container_width=True)

    if signup_clicked:
        username = username.strip()
        email = email.strip().lower()
        if not all([username, email, password, confirm_password, security_question, security_answer.strip()]):
            st.error("Please fill in every required field.")
        elif len(username) < 3:
            st.error("Username must contain at least 3 characters.")
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            st.error("Use 3–30 characters for username: letters, numbers, dot, underscore, or hyphen.")
        elif not validate_email(email):
            st.error("Enter a valid email. This milestone requires at least 2 letters before @, 2 in the domain name, and 2 in the final extension.")
        elif password != confirm_password:
            st.error("Password and Confirm Password do not match.")
        elif password_issues(password):
            show_password_issues(password)
        elif get_user_by_username(username):
            st.error("That username already exists. Choose another username.")
        elif get_user_by_email(email):
            st.error("That email is already registered. Use Login or Forgot Password.")
        else:
            success, reason = create_user(
                username=username,
                email=email,
                password_hash=hash_password(password),
                security_question=security_question,
                security_answer_hash=hash_password(normalize_answer(security_answer)),
            )
            if success:
                st.session_state["recovery_username"] = None
                flash("success", "Account created successfully. Please log in.")
                st.session_state["view"] = "Login"
                st.rerun()
            elif reason == "username":
                st.error("That username already exists. Choose another username.")
            elif reason == "email":
                st.error("That email is already registered. Use Login or Forgot Password.")
            else:
                st.error("Username or email is already registered.")


elif view == "Forgot Password":
    st.title("Reset your password")
    st.write("Choose either security-question recovery or email OTP recovery.")
    recovery_method = st.radio(
        "Recovery method",
        ["Security Question", "Email OTP"],
        horizontal=True,
        key="recovery_method",
    )

    if recovery_method == "Security Question":
        st.subheader("Option A — Security question")
        with st.form("security_lookup_form"):
            lookup_username = st.text_input("Username", key="security_lookup_input")
            lookup_clicked = st.form_submit_button("Show Security Question")
        if lookup_clicked:
            st.session_state["recovery_username"] = None
            recovery_user = get_user_by_username(lookup_username) if lookup_username.strip() else None
            if recovery_user:
                st.session_state["recovery_username"] = recovery_user["username"]
                st.rerun()
            else:
                st.error("Account not found. Check the username and try again.")

        saved_username = st.session_state.get("recovery_username")
        recovery_user = get_user_by_username(saved_username) if saved_username else None
        if recovery_user:
            st.info("Security question: " + recovery_user["security_question"])
            show_password_rules()
            with st.form("security_reset_form"):
                submitted_answer = st.text_input("Your Security Answer *", type="password")
                new_password = st.text_input("New Password *", type="password")
                confirm_new_password = st.text_input("Confirm New Password *", type="password")
                reset_clicked = st.form_submit_button("Reset Password", use_container_width=True)
            if reset_clicked:
                if not all([submitted_answer.strip(), new_password, confirm_new_password]):
                    st.error("Please fill in every required field.")
                elif not verify_hash(normalize_answer(submitted_answer), recovery_user["security_answer_hash"]):
                    st.error("Security answer is incorrect.")
                elif new_password != confirm_new_password:
                    st.error("New Password and Confirm New Password do not match.")
                elif not show_password_issues(new_password):
                    pass
                else:
                    update_password(recovery_user["id"], hash_password(new_password))
                    st.session_state["recovery_username"] = None
                    flash("success", "Password updated. Please log in with your new password.")
                    st.session_state["view"] = "Login"
                    st.rerun()

    else:
        st.subheader("Option B — Email OTP")
        st.caption("OTP expires in 10 minutes. A new code can be requested once every 60 seconds.")
        with st.form("send_otp_form"):
            otp_request_email = st.text_input("Registered Email *", key="otp_request_email")
            send_otp_clicked = st.form_submit_button("Send OTP", use_container_width=True)

        if send_otp_clicked:
            email_value = otp_request_email.strip().lower()
            if not validate_email(email_value):
                st.error("Enter a valid email address.")
            else:
                st.session_state["otp_email"] = email_value
                record = get_user_by_email(email_value)
                generic_notice = "If this email is registered and can receive a code, an OTP has been sent. Check your inbox and spam folder."
                delivery_failed = False
                if record:
                    now = time.time()
                    last_sent = record.get("reset_otp_last_sent_at")
                    if last_sent is None or now - float(last_sent) >= 60:
                        otp_value = f"{secrets.randbelow(1_000_000):06d}"
                        save_otp(email_value, hash_otp(email_value, otp_value), now + 600, now)
                        try:
                            send_otp_email(email_value, otp_value)
                        except Exception:
                            clear_otp(record["id"])
                            delivery_failed = True
                if delivery_failed:
                    st.session_state["otp_send_notice"] = (
                        "The OTP email could not be sent. Check the Gmail App Password and EMAIL_ADDRESS in Colab Secrets, then try again."
                    )
                else:
                    st.session_state["otp_send_notice"] = generic_notice

        notice = st.session_state.pop("otp_send_notice", None)
        if notice:
            st.info(notice)

        target_email = st.session_state.get("otp_email")
        if target_email:
            show_password_rules()
            with st.form("verify_otp_form"):
                otp_input = st.text_input("6-digit OTP *", max_chars=6)
                otp_new_password = st.text_input("New Password *", type="password")
                otp_confirm_password = st.text_input("Confirm New Password *", type="password")
                verify_clicked = st.form_submit_button("Verify OTP and Reset Password", use_container_width=True)

            if verify_clicked:
                record = get_user_by_email(target_email)
                if not record or not record.get("reset_otp_hash"):
                    st.error("OTP is invalid or expired. Request a new code and try again.")
                elif int(record.get("reset_otp_attempts", 0)) >= 5:
                    clear_otp(record["id"])
                    st.error("Too many attempts. Request a new OTP.")
                elif not record.get("reset_otp_expires_at") or time.time() > float(record["reset_otp_expires_at"]):
                    clear_otp(record["id"])
                    st.error("OTP has expired. Request a new code.")
                elif not re.fullmatch(r"\d{6}", otp_input.strip()) or not verify_otp(
                    target_email, otp_input.strip(), record["reset_otp_hash"]
                ):
                    increment_otp_attempts(record["id"])
                    if int(record.get("reset_otp_attempts", 0)) + 1 >= 5:
                        clear_otp(record["id"])
                        st.error("Too many incorrect attempts. Request a new OTP.")
                    else:
                        st.error("OTP is incorrect. Please check the code and try again.")
                elif not all([otp_new_password, otp_confirm_password]):
                    st.error("Please enter and confirm the new password.")
                elif otp_new_password != otp_confirm_password:
                    st.error("New Password and Confirm New Password do not match.")
                elif not show_password_issues(otp_new_password):
                    pass
                else:
                    update_password(record["id"], hash_password(otp_new_password))
                    st.session_state["otp_email"] = None
                    flash("success", "Password updated. Please log in with your new password.")
                    st.session_state["view"] = "Login"
                    st.rerun()


elif view == "Dashboard":
    if not current_user:
        st.error("Please log in to access the dashboard.")
        st.session_state["view"] = "Login"
        st.rerun()
    st.title("FranchiseOps AI Dashboard")
    st.success(f"Welcome, {current_user['username']}!")
    st.write(f"Signed in as **{current_user['email']}**")
    st.info(
        "Milestone 1 is focused on secure authentication. The franchise intelligence modules "
        "will be connected in later milestones; this page does not display fabricated business metrics."
    )
    st.subheader("Project modules")
    module_cols = st.columns(3)
    modules = [
        ("Outlet Performance", "Planned"),
        ("Inventory Optimization", "Planned"),
        ("Workforce Management", "Planned"),
        ("Marketing Intelligence", "Planned"),
        ("Compliance Audit (RAG)", "Planned"),
        ("Customer Feedback", "Planned"),
        ("Weekly Digest & Alerts", "Planned"),
    ]
    for index, (module_name, status) in enumerate(modules):
        with module_cols[index % 3]:
            st.markdown(f"**{module_name}**")
            st.caption(status)
    st.divider()
    if st.button("Logout", type="primary"):
        st.session_state["jwt_token"] = None
        st.session_state["view"] = "Login"
        flash("success", "You have been logged out.")
        st.rerun()


elif view == "Admin Login":
    st.title("Admin Console")
    st.write("This separate admin login is not created through user signup.")
    if current_admin:
        st.success("Admin authentication successful.")
        st.subheader("Registered users")
        users = list_users()
        if users:
            st.dataframe(users, use_container_width=True, hide_index=True)
        else:
            st.info("No registered users yet.")
        st.caption("For privacy, passwords, password hashes, and security answers are never displayed.")
        if st.button("Admin Logout", type="primary"):
            st.session_state["admin_jwt_token"] = None
            st.session_state["view"] = "Login"
            flash("success", "Admin session ended.")
            st.rerun()
    else:
        with st.form("admin_login_form"):
            admin_username = st.text_input("Admin Username *")
            admin_password = st.text_input("Admin Password *", type="password")
            admin_login_clicked = st.form_submit_button("Admin Login", use_container_width=True)
        if admin_login_clicked:
            configured_username = os.environ.get("ADMIN_USERNAME", "")
            configured_password = os.environ.get("ADMIN_PASSWORD", "")
            username_ok = hmac.compare_digest(admin_username, configured_username)
            password_ok = hmac.compare_digest(admin_password, configured_password)
            if username_ok and password_ok:
                st.session_state["admin_jwt_token"] = issue_token(
                    subject="admin", role="admin", username=configured_username
                )
                st.rerun()
            else:
                st.error("Invalid admin username or password.")

st.caption("Educational internship prototype — do not use real customer/employee records in this public demo.")
