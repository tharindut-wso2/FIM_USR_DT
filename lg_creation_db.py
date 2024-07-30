import re
import time
from datetime import datetime
import mysql.connector
from mysql.connector import Error

def process_log_line(line, syscall_info, capture, buffer, connection):
    
    # Tracking the openat syscall using the number (openat)
    if re.search(r'syscall=56', line):

        global openat 
        openat = 0
        capture = True
        buffer.append(line)

        # Extract timestamp, auid, and uid
        timestamp = re.search(r'audit\((\d+\.\d+)', line).group(1)

        # To get the name of the user
        auid = re.search(r' AUID="([^"]+)"', line).group(1)
        uid = re.search(r' UID="([^"]+)"', line).group(1)
        
        syscall_info['cmd'] = 'Write the file'
        syscall_info['Syscall'] = 'Openat'
        openat = 1

        syscall_info.update({
            'timestamp': timestamp,
            'auid': auid,
            'uid': uid
        })

    elif capture and re.match(r'^type=PATH', line):
        buffer.append(line)
        # Extract file path
        path_match = re.search(r'name="([^"]+)"', line)
        if path_match:
            path = path_match.group(1)
            if re.search(r'nametype=PARENT', line):
                if path == "./":
                    capture = 0
                syscall_info['parent_path'] = path
            elif re.search(r'nametype=NORMAL', line):
                syscall_info['file_path'] = path
    
    elif capture and re.match(r'^type=PROCTITLE', line):
        buffer.append(line)
        # Process the complete information and reset
        if 'parent_path' in syscall_info and 'file_path' in syscall_info:
            full_path = f"{syscall_info['parent_path']}/{syscall_info['file_path']}"

            syscall_info['conclusion'] = 'Switch User'

            # Create a conclusion with IDs
            if openat == 1:
                if syscall_info['auid'] != syscall_info['uid']:
                    syscall_info['conclusion'] = f"{syscall_info['auid']} has edited {full_path} file as {syscall_info['uid']}"
                else:
                    syscall_info['conclusion'] = f"{syscall_info['auid']} has edited {full_path} file"

            # Convert the timestamp to a human-readable format
            human_readable_timestamp = datetime.fromtimestamp(float(syscall_info['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')


            insert_multiple_query = """
            INSERT INTO Audit_Summary_Table (conclusion, timestamp, cmd, syscall, auid, uid, path) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

            data_to_insert = [
                (syscall_info['conclusion'], human_readable_timestamp, syscall_info['cmd'], syscall_info['Syscall'], syscall_info['auid'], syscall_info['uid'], full_path),
            ]

            execute_query(connection, insert_multiple_query, data_to_insert)


        buffer.clear()
        capture = False    

    else:
        buffer.append(line)

    return syscall_info, capture, buffer

def create_connection(host_name, user_name, user_password, db_name):
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password,
            database=db_name,
            ssl_disabled=True
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


def follow_log(input_file):
    syscall_info = {}
    buffer = []
    capture = False

    connection = create_connection("localhost", "tharindu", "THEbatta@1", "mydatabase")

    with open(input_file, 'r') as infile:
        # Seek to the end of the file
        infile.seek(0, 2)
        
        while True:
            line = infile.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            syscall_info, capture, buffer = process_log_line(line, syscall_info, capture, buffer, connection)
    
    # cursor.close()
    # cnx.close()

input_file = '/var/log/audit/audit.log'  

# Call the function to process logs in real-time
follow_log(input_file)
