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


# Running Flask App on Gobbler Server

## Starting the App
1. SSH into the server:
   ```bash
   ssh jean@gobbler.info
   ```

2. Navigate to your app directory:
   ```bash
   cd ~/db_test/src/server
   ```

3. Start Flask with nohup:
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
