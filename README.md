# FranchiseOps AI — Milestone 1: User Authentication

**Infosys Springboard Internship 7.0 · Batch 4**  
**Project:** FranchiseOps AI — Agentic Franchise Operations Intelligence Platform

## 1. What this milestone does

Milestone 1 builds the secure account-access foundation for FranchiseOps AI. It includes user signup, login using username or email, signed JWT sessions, logout, two password-recovery methods (security question and email OTP), and a separate admin console that lists registered usernames and email addresses.

The first user dashboard is intentionally a project shell. It does not invent sales, inventory, staff, or customer metrics; those modules are planned for later milestones.

## 2. Features

- Signup with unique username/email, validated email, password confirmation, security question, and security answer.
- Passwords and security answers stored as bcrypt hashes.
- Login with a generic error message on failed credentials.
- Signed HS256 JWT with a two-hour expiration stored in Streamlit session state.
- Forgot password using the saved security question or a six-digit email OTP.
- OTP is stored as a keyed hash, expires after 10 minutes, allows up to five attempts, and has a 60-second resend cooldown.
- Separate admin login; registered user list never displays password or hash data.
- SQLite database; the Colab notebook stores it in a dedicated Google Drive project folder to persist across ordinary runtime resets.

## 3. Technology stack

Python, Streamlit, SQLite, bcrypt, PyJWT, Gmail SMTP SSL, Google Colab Secrets, Google Drive, and pyngrok.

## 4. Google Colab setup

1. Open `FranchiseOpsAI_Milestone1_Auth.ipynb` in Google Colab and run the notebook cells from top to bottom.
2. In Colab, click **Secrets** (key icon) and add these secrets. Enable notebook access for every one:
   - `JWT_SECRET` — a unique random string of at least 32 characters.
   - `NGROK_AUTHTOKEN` — your ngrok authtoken.
   - `EMAIL_ADDRESS` — the Gmail account that sends OTPs.
   - `EMAIL_PASSWORD` — a Gmail App Password, not your normal Google password.
   - `ADMIN_USERNAME` — a private admin username.
   - `ADMIN_PASSWORD` — a strong private admin password.
3. Run the dependency installation, Google Drive mount, and secret-loading cells.
4. Run the cells that write `database.py`, `auth_utils.py`, and `app.py`.
5. Run the database check, then the launch cell. Open the ngrok public URL printed at the end.
6. Test signup, login, both password recovery methods, user logout, and admin login.
7. When finished, run the stop cell to stop Streamlit and close the ngrok tunnel.

### Gmail App Password notes

Gmail App Passwords require 2-Step Verification. Create one in Google Account settings; store it only in Colab Secrets. Do not paste the app password into a notebook cell or commit it. If the App Password screen is unavailable, your account's security or organisation policy may restrict this feature.

## 5. Local files created by the notebook

```text
Milestone1/
├── FranchiseOpsAI_Milestone1_Auth.ipynb
├── README.md
├── app.py
├── auth_utils.py
├── database.py
├── requirements.txt
├── franchiseops_users.db       # private runtime data; do not upload
├── streamlit.log               # runtime log; do not upload
└── screenshots/
    ├── login.png
    ├── signup.png
    ├── forgot_security_question.png
    ├── forgot_otp.png
    ├── otp_email.png
    ├── user_dashboard.png
    └── admin_dashboard.png
```

## 6. Screenshots


### Login
![Login page](screenshots/login.png)

### Signup
![Signup page](screenshots/signup.png)

### Forgot Password — Security Question
![Security question recovery](screenshots/forgot_security_question.png)

### Forgot Password — Email OTP
![OTP recovery page](screenshots/forgot_otp.png)

### OTP Email
![OTP email](screenshots/otp_email.png)

### User Dashboard
![User dashboard](screenshots/user_dashboard.png)

### Admin Dashboard
![Admin dashboard](screenshots/admin_dashboard.png)

> Screenshot files are intentionally not fabricated or pre-filled. Capture them after testing the app and add the image files to this folder.

## 7. Upload to GitHub

1. Create your repository (if needed) and add a `Milestone1` folder.
2. Upload the notebook and `README.md`; upload source `.py` files if your mentor permits.
3. Upload the screenshot files after taking them.
4. **Do not upload** `franchiseops_users.db`, `streamlit.log`, credentials, app passwords, JWT tokens, OTPs, or other secrets.
5. Clear notebook cell outputs before uploading, then inspect every cell and output once more.

## 8. Important security limitations

This is an educational prototype for a controlled demo, not a production authentication service. A public ngrok URL exposes the app to people who have that URL. Use only test data and stop the tunnel after the demo. Streamlit session-state JWT storage is suitable for this milestone but does not implement a hardened production session architecture. Security questions are weaker than email-based or MFA recovery. A production app should use a managed identity provider, persistent server-side sessions, robust rate limiting, audit logging, HTTPS/domain controls, and a managed database.
