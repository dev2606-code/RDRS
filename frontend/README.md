# RDRS Frontend — Option 3

A dark navy and purple frontend prototype for the Ransomware Detection and Response System (RDRS).

## Important
This is a **frontend-only preview**. The displayed statistics and event rows are sample data. This version does not monitor files, collect process information, call a backend API, or perform security scans.

The design follows the uploaded RDRS Hands-On Build Guide: the eventual backend will use Python, Watchdog, psutil, SQLite/SQLAlchemy, and FastAPI. The guide specifies a dashboard, REST API, JSON/CSV reports, automated tests, Docker deployment, and simulation mode by default.

## Run on macOS

1. Download and extract the project ZIP.
2. Open Terminal.
3. Change into the extracted folder. For example:

   ```bash
   cd ~/Downloads/RDRS-Frontend-Option3
   ```

4. Start a local static web server:

   ```bash
   python3 -m http.server 5500
   ```

5. Open this URL in your browser:

   http://127.0.0.1:5500

6. To stop the server, return to Terminal and press `Control + C`.

No Python packages are required for this frontend preview.

## Pages included

- Overview
- Ransomware Detection
- Threat Intelligence
- Incidents
- Security Tools
- Reports
- Settings

## Next development steps

1. Create the Python virtual environment and install backend dependencies from the Hands-On Build Guide.
2. Implement configuration loading, logging, and Shannon entropy.
3. Add sandbox-only file monitoring.
4. Store events, process metadata, alerts, and incidents in SQLite.
5. Expose the API using FastAPI and connect the frontend to real API responses.
6. Implement JSON/CSV report generation and automated tests.
7. Add Docker deployment after local testing passes.

## Safety
Use a dedicated disposable sandbox directory only. Keep simulation mode enabled. Do not run real ransomware or malware. Quarantine behavior must copy evidence without modifying or deleting originals.
