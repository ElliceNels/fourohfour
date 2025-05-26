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
JWT_SECRET_KEY=to-be-generated
DB_USER=your-db-username
DB_PASSWORD=your-db-password
```

4. Run the server:
```bash
python -m src.server.app
```

# Deploying to Gobbler Server

## Copying Files to Server
1. From your local machine, use scp to copy the server files. You may have to ssh in and create the directories you want to move the files to (probably on wsl):
   ```bash
   scp -i ~/.ssh/id_rsa -r "/mnt/c/Users/jeanl/College/Blocks/Block 8/fourohfour/src/server" jean@gobbler.info:~/db_test/src/
   ```

2. Set production environment variables on the server:
   ```bash
   export DB_ENVIRONMENT=production
   export DB_USER=fourohfour
   export DB_PASSWORD=fourohfour
   ```

# Running Flask App on Gobbler Server

## Starting the App
1. SSH into the server:
   ```bash
   ssh -vvv -i ~/.ssh/id_rsa  jean@gobbler.info
   ```

2. Navigate to your app directory:
   ```bash
   cd ~/db_test/src/server
   ```

3. Start Flask with nohup (so it will continue after you kill your terminal):
   ```bash
   nohup flask run --host=0.0.0.0 --port=4004 > flask.log 2>&1 &
   ```

4. Verify it's running:
   ```bash
   ps aux | grep flask
   ```
   You should see your Flask process in the output.

## Checking Logs
To see what's happening with your app:
```bash
tail -f flask.log
```

## Stopping the App
1. Find the process ID (PID):
   ```bash
   ps aux | grep flask
   ```
   Look for the line containing `flask run` and note the PID number.

2. Kill the process:
   ```bash
   kill <PID>
   ```
   Replace `<PID>` with the actual process ID number.

3. Verify it's stopped:
   ```bash
   ps aux | grep flask
   ```
   The Flask process should no longer appear.

## Troubleshooting
- If the app isn't starting, check the logs:
  ```bash
  cat flask.log
  ```
- If you can't kill the process, use force kill:
  ```bash
  kill -9 <PID>
  ```
- If port 4004 is already in use:
  ```bash
  sudo lsof -i :4004
  ```
  This will show what's using the port.

# Database Setup Guide

## Development vs Production

### Development Mode
- Uses local MySQL database
- Default credentials: `db_user`/`db_password`
- Database and tables are created automatically on first run
- Environment variable `DB_ENVIRONMENT` set to "development"

### Production Mode
- Connects to cloud MySQL database
- Requires environment variables:
  - `DB_USER`
  - `DB_PASSWORD`
  - `DB_ENVIRONMENT` set to "production"
- Database and tables are created automatically if they don't exist

## Local Development Setup

### 1. Install MySQL
1. Download MySQL Installer from: https://dev.mysql.com/downloads/installer/
2. Run installer, choose "Developer Default" or "Server only"
3. During installation:
   - Set root password (remember this!)
   - Keep default port (3306)

### 2. Add MySQL to PATH
1. Find MySQL installation (typically `C:\Program Files\MySQL\MySQL Server 8.0\bin`)
2. Add to PATH:
   - Press Windows + R
   - Type "sysdm.cpl" and press Enter
   - Go to "Advanced" tab
   - Click "Environment Variables"
   - Under "System Variables", find "Path"
   - Click "Edit" → "New"
   - Add MySQL bin directory path
   - Click "OK" on all windows
3. Restart your terminal

### 3. Create MySQL User (Required)
This step is necessary to create a MySQL user that the application will use. The username and password MUST match either:
- The default values in the code (`db_user`/`db_password`)
- Or the values you set in your `.env` file

1. Open Command Prompt as Administrator
2. Connect to MySQL:
   ```bash
   mysql -u root -p
   ```
3. Enter your root password
4. Create the application user (use the same username/password that your application will use):
   ```sql
   CREATE USER 'db_user'@'localhost' IDENTIFIED BY 'db_password';
   GRANT ALL PRIVILEGES ON *.* TO 'db_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

### 4. Start the Application
The database and tables will be created automatically on first run:
```bash
python src/server/app.py
```

## Production Deployment

### 1. Set Environment Variables
```bash
export DB_USER=your_prod_user
export DB_PASSWORD=your_prod_password
export DB_ENVIRONMENT=production
```

### 2. Start Flask Application
```bash
python src/server/app.py
```

## Database Visualization with DBeaver

### 1. Install DBeaver
1. Download from: https://dbeaver.io/download/
2. Run installer
3. Launch DBeaver

### 2. Connect to Database
1. Click "New Database Connection" (plug icon with plus)
2. Select "MySQL"
3. Fill in connection details:
   - Server Host: `127.0.0.1`
   - Port: `3306`
   - Database: `fourohfour`
   - Username: `db_user`
   - Password: `db_password`
4. Click "Test Connection"
5. If successful, click "Finish"

### 3. View Tables
1. In left panel, expand:
   - Your connection
   - "fourohfour" database
   - "Tables"
2. You'll see all tables:
   - `users`
   - `files`
   - `file_permissions`
   - `file_metadata`
   - `token_invalidation`

### 4. View Table Contents
- Right-click any table
- Select "View Data"

### 5. View Table Structure
- Right-click any table
- Select "View Table"

## Important Notes
- Local database files are in `.gitignore`
- Each developer needs their own local MySQL installation
- Production database credentials should never be committed to git
- Always use environment variables for production credentials
- The database and tables are created automatically on first run

## Troubleshooting
1. If MySQL command not found:
   - Verify PATH setup
   - Restart terminal
2. If connection fails:
   - Check MySQL service is running
   - Verify credentials
   - Check port availability
3. If tables not visible:
   - Check connection settings in DBeaver
   - Verify the application has run at least once
