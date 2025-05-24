import mysql.connector

def test_connection():
    try:
        # Attempt to connect to the database
        print("Attempting to connect to the database...")
        cnx = mysql.connector.connect(
            user='fourohfour',
            password='fourohfour',
            host='127.0.0.1',
            port=3306,
            database='fourohfour'
        )
        
        with cnx.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print(f"Connected to MySQL Server version {version[0]}")
            
            cursor.execute("SELECT DATABASE()")
            db = cursor.fetchone()
            print(f"Connected to database: {db[0]}")
            
        cnx.close()
        print("MySQL connection is closed")
            
    except Exception as e:
        print(f"Error while connecting to MySQL: {e}")

if __name__ == "__main__":
    test_connection() 