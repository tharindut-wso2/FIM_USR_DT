import re
import time
from datetime import datetime

def process_log_line(line, syscall_info, capture, buffer, output_file):
    
    #trackiung the openat syscall using the number (openat and the execve)
    if re.search(r'syscall=(56|221)', line):

        global openat 
        openat = 0
        capture = True
        buffer.append(line)

        # Extract timestamp, auid, and uid
        timestamp = re.search(r'audit\((\d+\.\d+)', line).group(1)

        #to get the ID number of the user
        # auid = re.search(r'\bauid=(\d+)\b', line).group(1)
        # uid = re.search(r'\buid=(\d+)\b', line).group(1)

        #to get the name of the user
        auid = re.search(r' AUID="([^"]+)"', line).group(1)
        uid = re.search(r' UID="([^"]+)"', line).group(1)
        
        if re.search(r'syscall=221', line):  #for the track the cmd 
            syscall_info['Syscall'] = 'Execve'
            
        else:
            syscall_info['cmd'] = 'Open the file'
            syscall_info['Syscall'] = 'Openat'
            openat = 1


        syscall_info.update({
            'timestamp': timestamp,
            'auid': auid,
            'uid': uid
        })

    elif capture and re.match(r'^type=EXECVE', line):
        buffer.append(line)

        # Extract command
        cmd_parts = []
        for match in re.finditer(r'a\d+="([^"]+)"', line):
            cmd_parts.append(match.group(1))
        syscall_info['cmd'] = ' '.join(cmd_parts)

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
            full_path = syscall_info['path']

            syscall_info['conclusion'] = 'Switch User'

            #create a conclusion with IDs
            if openat == 1:
                if syscall_info['auid'] != syscall_info['uid']:
                    syscall_info['conclusion'] = syscall_info['auid'] + ' has open ' + syscall_info['path'] + ' file as ' + syscall_info['uid']
                else:
                    syscall_info['conclusion'] = syscall_info['auid'] + ' has open ' + syscall_info['path'] + ' file'

            # Convert the timestamp to a human-readable format
            human_readable_timestamp = datetime.fromtimestamp(float(syscall_info['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')

            with open(output_file, 'a') as outfile:
                #outfile.write(f"Command: {syscall_info['cmd']}, Syscall:{syscall_info['Syscall']}, Timestamp: {human_readable_timestamp}, AUID: {syscall_info['auid']}, UID: {syscall_info['uid']}, Path: {full_path}, Conclusion: {syscall_info['conclusion']}\n")
                outfile.write(f"Conclusion: {syscall_info['conclusion']}, Command: {syscall_info['cmd']}, Syscall:{syscall_info['Syscall']}, Timestamp: {human_readable_timestamp}, AUID: {syscall_info['auid']}, UID: {syscall_info['uid']}, Path: {full_path}\n")
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
                time.sleep(0.1)  
                continue
            
            syscall_info, capture, buffer = process_log_line(line, syscall_info, capture, buffer, output_file)

input_file = '/var/log/audit/audit.log'  
output_file = '/home/tharindu2/FIM_repo/FIM_single_file/filtered_info.xlsx'  

# Call the function to process logs in real-time
follow_log(input_file, output_file)
