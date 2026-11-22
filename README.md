# RDRS — Ransomware Detection and Response System
All project links
- ???? Live website: rdrs.netlify.app
- ⚙️ Backend API: rdrs-5c5r.onrender.com
RDRS is a defensive, sandbox-focused ransomware detection and response system designed to monitor file activity, identify suspicious behavior, calculate risk scores, and manage security incidents.

## Features

- Sandbox-restricted file monitoring
- Suspicious file activity detection
- Risk scoring and confidence levels
- File entropy analysis
- Suspicious extension detection
- Event and alert management
- Incident tracking and status updates
- Authentication-protected API endpoints
- Secure session cookies
- Login rate limiting
- Sysmon event parsing and correlation (Windows)
- SQLite database with optional PostgreSQL support
- Web-based dashboard
- Automated test suite

## Security

- Authentication required for protected endpoints.
- Password verification uses Argon2.
- Sessions are signed using HMAC-SHA256.
- Session cookies use HttpOnly, Secure and SameSite protections.
- Login attempts are rate-limited.
- Test endpoints are disabled by default.
- File monitoring is restricted to the configured sandbox.
- User inputs are validated and bounded.
- Never commit `.env` or real credentials.

## Requirements

- Python 3
- Virtual environment
- macOS/Linux for the core development workflow
- Windows with Sysmon for Windows-specific event attribution testing

## Local Setup

Clone the repository and enter the project directory.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure environment variables using `.env.example` as a template. Never use placeholder credentials in an actual deployment.

Required authentication configuration:

- `RDRS_SESSION_SECRET`
- `RDRS_USERNAME`
- `RDRS_PASSWORD_HASH`

Optional configuration:

- `DATABASE_URL`
- `RDRS_ENABLE_TEST_ENDPOINT` (default disabled)

The session secret must be at least 32 characters.

## Running RDRS

Start the backend using the project's configured startup command:

```bash
uvicorn app.main:app
```

The API runs locally using Uvicorn. Configure the frontend to use the appropriate backend API address.

## Sandbox Safety

RDRS is intended for defensive testing only.

- Use only files inside the designated sandbox.
- Do not use real ransomware or destructive payloads.
- Do not test on personal or production data.
- Detection simulations should use harmless test files.
- File monitoring must not be pointed at sensitive directories.
- RDRS does not automatically terminate processes.

## Testing

Run the full test suite:

```bash
python -m pytest -q
```

Run the dependency security audit:

```bash
pip-audit
```

## Windows / Sysmon

Windows Sysmon integration supports parsing and correlating selected Sysmon events. Windows-specific functionality requires a Windows environment with appropriate Sysmon configuration.

Windows integration has not been fully validated on the macOS development machine.

## Project Status

RDRS is under active development. Core detection, API, database, authentication, and frontend tests are available. Windows-specific attribution requires separate Windows validation.

## Disclaimer

RDRS is an educational and defensive cybersecurity project. Use it only in authorized environments and controlled sandboxes.
