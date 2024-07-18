import re
import time
# from datetime import datetime
import datetime

def process_log_line(line, syscall_info, capture, buffer):
    if re.search(r'syscall=56', line):
        capture = True
        buffer.append(line)
        # Extract timestamp, auid, and uid
        timestamp = re.search(r'audit\((\d+\.\d+)', line).group(1)
        auid = re.search(r' auid=(\d+)', line).group(1)
        uid = re.search(r' uid=(\d+)', line).group(1)
        syscall_info.update({
            'timestamp': timestamp,
            'auid': auid,
            'uid': uid
        })

    elif capture and re.match(r'^type=CWD', line):
        buffer.append(line)
        # Extract current working directory
        cwd = re.search(r'cwd="([^"]+)"', line).group(1)
        syscall_info['cwd'] = cwd

    elif capture and re.match(r'^type=PATH', line):
        buffer.append(line)
        # Extract file path
        path_match = re.search(r'name="([^"]+)"', line)
        if path_match:
            path = path_match.group(1)
            if path.startswith('/'):
                syscall_info['path'] = path

    elif capture and re.match(r'^type=PROCTITLE', line):
        buffer.append(line)
        # Process the complete information and reset
        if 'path' in syscall_info:
            full_path = syscall_info['cwd'] + syscall_info['path'] if 'cwd' in syscall_info else syscall_info['path']
	    dt_object = datetime.datetime.fromtimestamp(timestamp)
            with open(output_file, 'a') as outfile:
                outfile.write(f"Timestamp: {syscall_info['dt_object']}, AUID: {syscall_info['auid']}, UID: {syscall_info['uid']}, Path: {full_path}\n")
        buffer.clear()
        capture = False

    else:
        buffer.append(line)

    return syscall_info, capture, buffer

def follow_log(input_file, output_file):
    syscall_info = {}
    buffer = []
    capture = False
    
    with open(input_file, 'r') as infile:
        # Seek to the end of the file
        infile.seek(0, 2)
        
        while True:
            line = infile.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly to wait for new data
                continue
            
            syscall_info, capture, buffer = process_log_line(line, syscall_info, capture, buffer)

# Specify the input and output file paths
input_file = '/var/log/audit/audit.log'  # Change this to your actual audit log path
output_file = 'filtered_info.txt'

# Call the function to process logs in real-time
follow_log(input_file, output_file)
