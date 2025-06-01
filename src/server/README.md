
# # Server Info

## Overview
The server is a Flask-based REST API that handles secure file sharing operations. It provides endpoints for user authentication, file management, and secure file sharing.

## File Structure
```
src/server/
├── app.py              # Main application entry point
├── config.py           # Configuration settings
├── models/            # Database models
│   ├── user.py        # User model and authentication
│   └── file.py        # File and sharing models
├── routes/            # API endpoints
│   ├── auth.py        # Authentication routes
│   └── files.py       # File management routes
├── utils/             # Helper functions
└── migrations/        # Database migration files
```

## Key Endpoints
### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `GET /auth/verify` - Verify JWT token

### File Operations
- `POST /files/upload` - Upload new file
- `GET /files/list` - List user's files
- `GET /files/<file_id>` - Get file details
- `DELETE /files/<file_id>` - Delete file
- `POST /files/<file_id>/share` - Share file with other users
- `GET /files/shared` - List files shared with user

### Security
- All endpoints except registration and login require JWT authentication
- File access is controlled through granular permissions
- Files remain encrypted at rest
- Secure file transfer using HTTPS when deployed on gobbler.info as that server already has certs

## Getting Started
Assuming this is your first time running the app:
 - Set up a virtual environment at the fourohfour directory using `python -m venv venv` and activate `venv/Scripts/activate`
	 - Install dependencies `pip install -r requirements.txt`
 - **Set up local database** *(see below)*
 - Apply any pending **database migrations** *(see below)*
 - [Optional] Set `JWT_SECRET_KEY` and `SECRET_KEY` using generated values *(see "Generating Secrets" below)*
 -  Run from the `fourohfour` directory with `python -m src.server.app` 
	 - You may need to set `$env:PYTHONPATH = "C:\Users\...\fourohfour\src"` *(<- powershell syntax)*
    - Or using .env `PYTHONPATH = src`
 - The app should now run at `localhost:5000` 
	 - To diagnose issues see **Checking Logs** below

## Setting up Local Database
1. Install MySQL:
   - Download MySQL Installer from: https://dev.mysql.com/downloads/installer/
	   - Our team is using version 8.0.42
   - Choose either of the two installers
   - Run installer, choose "Developer Default" or "Server only"
   - Set root password during installation
   - Keep default port (3306)

2. Add MySQL to PATH:
   - Find MySQL installation (typically `C:\Program Files\MySQL\MySQL Server 8.0\bin`)
   - Add to Windows PATH through System Properties

3. Create MySQL User, either via command line or if prompted during setup via the GUI
	- This user can have any username and password, just remember to set these values as environment variables before running as in development mode we have defualt environment variables `DB_USER = "db_user"` and `DB_PASSWORD = "db_password"`
   ```sql
   CREATE USER 'db_user'@'localhost' IDENTIFIED BY 'db_password';
   GRANT ALL PRIVILEGES ON *.* TO 'db_user'@'localhost';
   FLUSH PRIVILEGES;
   ```
   *note: the user and password is different for production 

4. Create `.env` file in the fourohfour directory and add the values that you set above. 
	- If you have set up mySQL with the default values db_user and db_password, this is optional but good practice:
   ```
   DB_USER=db_user
   DB_PASSWORD=db_password
   ```

5. Now when you run the app, SQLAlchemy should create a database with the relevent tables automatically, and use this going forward.
   - Database connection and integration testing use different databases

## Generating Secrets
The application requires two secret keys for security:
1. `SECRET_KEY` - Used for Flask session security and CSRF protection
2. `JWT_SECRET_KEY` - Used for signing and verifying JSON Web Tokens

To generate these keys:

1. Navigate to the server directory:
   ```bash
   cd src/server
   ```

2. Generate the keys using the provided script:
   ```bash
   # Generate Flask SECRET_KEY
   python scripts/generate_secret_key.py --key SECRET_KEY

   # Generate JWT_SECRET_KEY
   python scripts/generate_secret_key.py --key JWT_SECRET_KEY
   ```

3. The script will automatically update your `.env` file with the new keys.

To manually add these keys:
1. Choose secure, random JWT and flask secret keys

2. Add these values to your .env
   ```
   JWT_SECRET_KEY=your_key_here
   SECRET_KEY=your_secret_key_here
   ```

Important Security Notes:
- Keys are stored in the `.env` file and should never be hardcoded in the application
- Keep keys consistent across server restarts
- Use different keys for development and production
- Never commit keys to version control
- Changing keys will invalidate all existing sessions/tokens

## Deploying to Gobbler.info
1. Copy files to server:
   ```bash
   rsync -avz --exclude="venv" -e "ssh -i ~/.ssh/id_rsa" "/mnt/c/Users/jeanl/College/Blocks/Block 8/fourohfour/src/server/" jean@gobbler.info:~/db_test/src/
   ```

2. Set production environment variables:
   ```bash
   export DB_ENVIRONMENT=production
   export DB_USER=fourohfour
   export DB_PASSWORD=fourohfour
   ```

3. Start the application:
   ```bash
   cd ~/db_test
   nohup gunicorn -w 4 -b 0.0.0.0:4004 src.server.app:app > gunicorn.log 2>&1 &
   ```

## Apply Database Migrations
1. Check current migration status:
   ```bash
   alembic current
   ```

2. View migration history:
   ```bash
   alembic history
   ```

3. Apply pending migrations:
   ```bash
   alembic upgrade head
   ```

4. Create new migration:
   ```bash
   alembic revision --autogenerate -m "description"
   ```

## Checking Logs
### Local (Flask App)
- Logs are output directly to the console when running in development mode
- You can also check the actual log file `app/server/logs/app.log`

### On Gobbler (Gunicorn App)
```bash
# View Gunicorn logs
tail -f gunicorn.log

# Check if process is running
ps aux | grep gunicorn
```

## Viewing DB Contents
### Local (Flask App)
1. Install DBeaver from https://dbeaver.io/download/
2. Create new MySQL connection:
   - Host: `127.0.0.1`
   - Port: `3306`
   - Database: `fourohfour`
   - Username: `db_user`
   - Password: `db_password`
3. Database files are typically stored in:
   - Windows: `C:\ProgramData\MySQL\MySQL Server 8.0\Data\fourohfour`
   - Linux: `/var/lib/mysql/fourohfour`
   - macOS: `/usr/local/mysql/data/fourohfour`
   Note: These are default locations and may vary based on your MySQL installation

### On Gobbler (Gunicorn App)
1. SSH into server:
   ```bash
   ssh -i ~/.ssh/id_rsa jean@gobbler.info
   ```
2. Connect to MySQL:
   ```bash
   mysql -u fourohfour -pfourohfour fourohfour
   ```
3. Select database and view tables:
   ```sql
   SHOW TABLES;
   SELECT * FROM table_name;
   ```

# Testing

### Prequisites
- Ensure PyTest is installed
- Ensure PYTHONPATH is set in your .env
- Ensure you have a local MySQL server running
- Ensure your pytest.ini file contains teh following:
   ```
   [pytest]
   pythonpath = src
   testpaths = tests
   ```
### Running Tests

1. From the `fourohfour` directory
   ```bash
   pytest
   ```
   If you would like to run a specific file:
   ```
   pytest file/path/from/tests/directory
   ```

# TroubleShooting
1. Database Connection Issues:
   - Verify MySQL service is running
   - Check credentials in `.env` file
   - Ensure MySQL is in PATH
   - Check port availability (3306)

2. Application Won't Start:
   - Check virtual environment is activated
   - Verify all dependencies are installed
   - Check PYTHONPATH is set correctly
   - Review error logs

3. Migration Issues:
   - Ensure database exists
   - Check alembic version table
   - Verify migration files are present
   - Try downgrading and upgrading again

4. Production Deployment Issues:
   - Check Gunicorn logs
   - Verify environment variables
   - Ensure correct permissions
   - Check port availability (4004)
