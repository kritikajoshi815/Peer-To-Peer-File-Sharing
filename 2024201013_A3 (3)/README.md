Running instuctions:
Compilation:
Client file: g++ client.cpp -o client -lcrypto
Tracker file: g++ tracker.cpp -o tracker

Execution:
Client file: ./client_test <IP>:<PORT> ../tracker/tracker_info.txt
Tracker file: ./tracker tracker_info.txt tracker_no

The following commands are implemented by the code:
Run Tracker: ./tracker tracker_info.txt tracker_no


Run Client: ./client <IP>:<PORT> tracker_info.txt
Create User Account: create_user <user_id> <passwd>
Login: login <user_id> <passwd>
Create Group: create_group <group_id>
Join Group: join_group <group_id>
Leave Group: leave_group <group_id>
List pending join: list_requests <group_id>
Accept Group Joining Request: accept_request <group_id> <user_id>
List All Group In Network: list_groups
List All sharable Files In Group: list_files <group_id>
Upload File: upload_file <file_path> <group_id>
Download File: download_file <group_id> <file_name> <destination_path>
