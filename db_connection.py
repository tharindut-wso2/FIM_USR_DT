import mysql.connector
from mysql.connector import Error

def create_connection(host_name, user_name, user_password, db_name):
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password,
            database=db_name
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection

def execute_query(connection, query, data=None):
    cursor = connection.cursor()
    try:
        if data:
            cursor.executemany(query, data)
        else:
            cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except Error as e:
        print(f"The error '{e}' occurred")

# Replace with your own database credentials
connection = create_connection("localhost", "tharindu", "THEbatta@1", "mydatabase")

# Create table
create_table_query = """
CREATE TABLE Audit_Summary_Table (
    id INT AUTO_INCREMENT PRIMARY KEY,
    conclusion VARCHAR(255),
    timestamp DATETIME,
    cmd VARCHAR(255),
    syscall VARCHAR(255),
    auid VARCHAR(255),
    uid VARCHAR(255),
    path VARCHAR(255)
);
"""

execute_query(connection, create_table_query)


# execute_query(connection, create_table_query)

insert_multiple_query = """
INSERT INTO Audit_Summary_Table (conclusion, timestamp, cmd, syscall, auid, uid, path) 
VALUES (%s, %s, %s, %s, %s, %s, %s)
"""

data_to_insert = [
    ('tharindu2 has edit /home/TestDir/TestFolder/test1.txt file', '2024-07-26 15:12:42', 'Open the file', 'Openat', 'tharindu2', 'tharindu2', '/home/TestDir/TestFolder/test1.txt'),
]

execute_query(connection, insert_multiple_query, data_to_insert)
