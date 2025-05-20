# Secure File Sharing Server

This is the server component of the secure file sharing platform. It provides the backend API for file operations, user authentication, and secure file sharing.

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the server directory with the following variables:
```
SECRET_KEY=your-secret-key-here
DATABASE_URL=your-database-url-here
```

4. Run the server:
```bash
python app.py
```