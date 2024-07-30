import mysql.connector

# Establish the database connection
con = mysql.connector.connect(
    host="localhost",
    user="tharindu",
    password="THEbatta@1",
    database="mydatabase"
)

# Create a cursor object
cursor = con.cursor()

# SQL query to create the table
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

# Execute the query
cursor.execute(create_table_query)

# Commit the changes to the database
con.commit()

# Close the cursor and connection
cursor.close()
con.close()

print("Table created successfully.")
