# fourohfour – Project Overview

This repository contains the **fourohfour** secure file sharing system, which is split into three main components:  
- Web Client  
- Desktop Client  
- Server (REST API)  

Each component has its own detailed README in its respective directory.  
This document provides a high-level summary and quickstart for each part.

---

## Web Client

- **Location:** `src/web-client`
- **Setup:**
  - Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```
  - Run the application:
    ```sh
    python src/web-client/app.py
    ```
  - Access the app at [http://localhost:8080](http://localhost:8080)
- **More info:** See `src/web-client/README.md`

---

## Desktop Client

- **Location:** `src/desktop-client`
- **Setup:**
  - Create the following folders if they don't exist:
    ```
    src/desktop-client/include
    src/desktop-client/lib
    ```
  - **Libsodium Setup (Windows):**
    - Download from [Libsodium Releases](https://download.libsodium.org/libsodium/releases/)
    - Extract and copy `include/` and `lib/` to the above folders
    - Copy `libsodium-23.dll` to `src/desktop-client/client-404/build`
  - **Libcurl Setup (Windows):**
    - Download from [curl.se](https://curl.se/windows/)
    - Extract and copy `include/` and `lib/` to the above folders
    - Copy `libcurl-x64.dll` to `src/desktop-client/client-404/build`
  - **Building:**
    - Use Qt Creator to open the project, run CMake, and build to create the `build` directory
- **More info:** See `src/desktop-client/README.md`

---

## Server (Flask REST API)

- **Location:** `src/server`
- **Overview:**  
  Flask-based REST API for secure file sharing, user authentication, and file management.
- **Key Endpoints:**
  - User registration, login, logout, JWT verification
  - File upload, listing, download, deletion, sharing
  - All endpoints (except registration/login) require JWT authentication
  - Files are encrypted at rest and transferred securely (HTTPS in production)
- **Setup:**
  - Create and activate a Python virtual environment in the project root:
    ```sh
    python -m venv venv
    venv/Scripts/activate  # or source venv/bin/activate on Linux/Mac
    pip install -r requirements.txt
    ```
  - Set up a local MySQL database (see server README for details)
  - Apply database migrations with Alembic
  - Generate and set `SECRET_KEY` and `JWT_SECRET_KEY` in your `.env` file
  - Run the server:
    ```sh
    python -m src.server.app
    ```
    - The app runs at [http://localhost:5000](http://localhost:5000)
- **Deployment:**  
  - Use Gunicorn for production (see server README for full deployment steps)
  - Set environment variables for production database credentials
- **Testing:**  
  - Use `pytest` from the project root
  - Ensure MySQL is running and `PYTHONPATH` is set
- **Troubleshooting:**  
  - Check database connection, environment variables, and logs for issues
  - See the server README for detailed troubleshooting steps

**For full details, see `src/server/README.md`**

---

**Tip:**  
If you need more detail about a specific part of the project, check the README in that directory!