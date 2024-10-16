#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <map>

using namespace std;

#define MAX_CLIENTS 10
#define BUFFER_SIZE 512

int client_count = 0;
bool running = true;

struct port_client_map
{
    int sockfd;
    int new_sockfd;
    struct sockaddr_in client_address_para;
    socklen_t client_length;
};

class Client_info
{
private:
    string password;

public:
    string id;

    Client_info() {};
    Client_info(string id, string password)
    {
        this->id = id;
        this->password = password;
    };
};

class Files
{
public:
    string path;
    string sha_val;
    string owner;
    string ip_owner;
    string port_owner;
    Files() {}

    Files(const string &path, const string &sha_val, const string &owner, const string &ip_owner, const string &port_owner)
    {
        this->path = path;
        this->sha_val = sha_val;
        this->owner = owner;
        this->ip_owner = ip_owner;
        this->port_owner = port_owner;
    }
};

// class group to keep infomration about a group
class Groups
{
public:
    string group_id;                   // ID of the group
    string owner;                      // Owner of the group (client who created it)
    map<string, bool> peers_connected; // Map for storing all the clients within the group along with client info.
    map<string, bool> peers_requesting;
    map<string, vector<Files>> files_owner_info;
    map<string, vector<string>> file_peers_containing; // give name of file and fetch the owners(ip and port and user_name) who have that file
    vector<string> sharable_files;
    Groups() {}

    Groups(const string &group_id, const string &owner)
    {
        this->group_id = group_id;
        this->owner = owner;
    }
};

// map to store password and user_id
map<string, string> user_db;
// map<string, Groups> groups;
map<string, bool> login_user_map;
map<string, Groups> all_groups;

// creating thread
pthread_mutex_t client_count_mutex;
pthread_mutex_t user_db_mutex;

// Function to handle creating a user
bool createUser(const string &user_id, const string &passwd)
{

    if (user_db.find(user_id) != user_db.end())
    {
        return false; // User already exists
    }
    user_db[user_id] = passwd;
    Client_info client(user_id, passwd);
    return true; // User created successfully
}
int UserLogin(const string &user_id, const string &passwd)
{
    if (login_user_map[user_id] == true)
    {
        // cout << "User with id=" << user_id << " is already logged in." << endl;
        return 4;
    }
    if (user_db.find(user_id) != user_db.end())
    {
        // If user exists, verify the password
        if (user_db[user_id] == passwd)
        {
            // cout << "User with user_id=" << user_id << "has successfully logged in" << endl;
            login_user_map[user_id] = true;
            return 1;
        }
        else
        {
            // cout << "Invalid password" << endl;
            return 2;
        }
    }

    else
    {
        // If user doesn't exist
        // cout << "User does not exist, first create User Account" << endl;
        return 3;
    }
}

string createGroup(const string &owner, const string &group_id)
{
    string reply;
    if (all_groups.find(group_id) != all_groups.end())
    {
        reply = "Group id=" + group_id + " already exists";
        // cout << "in tracker creategroup reply: " << reply << endl;
        return reply;
    }

    // check if owner is logged in
    if (login_user_map.find(owner) == login_user_map.end())
    {
        reply = "Owner id=" + owner + " is not logged in";
        return reply;
    }

    // make a group and assign its owner

    Groups group(group_id, owner);
    all_groups[group_id] = group;
    all_groups[group_id].peers_connected[owner] = true;
    reply = "Group with id=" + group_id + " with owner id=" + owner + " created successfully";
    // cout << reply << endl;
    return reply;
    // return true;
}

string joinGroup(const string &client, const string &group_id)
{
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (login_user_map.find(client) == login_user_map.end())
    {
        reply = "User is not logged in";
        return reply;
    }
    all_groups[group_id].peers_requesting[client] = true;
    // cout << endl;
    // cout << "size fo requesting que:" << all_groups[group_id].peers_requesting.size() << endl;
    //  for (auto it = all_groups.begin(); it != all_groups.end(); it++)
    //  {
    //      cout << "key=" << all_groups[group_id].peers_requesting.first << " val=" << all_groups[group_id].peers_requesting->second;
    //  }
    reply = "Request received by the group owner";
    return reply;
}

string leaveGroup(const string &client, const string &group_id)
{
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (login_user_map.find(client) == login_user_map.end())
    {
        reply = "User is not logged in";
        return reply;
    }
    if (all_groups[group_id].peers_connected.find(client) == all_groups[group_id].peers_connected.end())
    {
        reply = "User is not present in the group";
        return reply;
    }
    if (all_groups[group_id].peers_connected.size() == 1)
    {
        all_groups.erase(group_id); // erase the entire group in this case
        reply = "Last client left the group";
        return reply;
    }
    string owner = all_groups[group_id].owner; // then make a new group owner
    if (client == owner)
    {
        auto it = all_groups[group_id].peers_connected.begin();

        // Retrieve the first element
        if (it != all_groups[group_id].peers_connected.end())
        {
            if (it->first == owner)
                ++it;
        }
        string new_owner = it->first;
        all_groups[group_id].owner = new_owner;
        cout << "Group id=" << group_id << " owner changed to id=" << new_owner << endl;
    }

    all_groups[group_id].peers_connected.erase(client);
    reply = "Client with id= " + client + " left the group with id= " + group_id;
    return reply;
}

string list_Requests(const string &client, const string &group_id)
{
    string reply = "";
    map<string, bool> maap = all_groups[group_id].peers_requesting;
    for (auto it = maap.begin(); it != maap.end(); it++)
    {
        // string reply_sub;
        reply = reply + it->first;
        // reply.push_back(reply_sub);
        reply += " , ";
        // cout << "key=" << it->first;
    }

    return reply;
}

string accept_Request(const string &client_toaccetp_id, const string &group_id, const string &predicted_owner_id)
{
    // cout << "stage 2" << endl;
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (login_user_map.find(client_toaccetp_id) == login_user_map.end())
    {
        reply = "User is not logged in";
        return reply;
    }
    if (all_groups[group_id].peers_requesting.find(client_toaccetp_id) == all_groups[group_id].peers_requesting.end())
    {
        reply = "User has never requested to enter in the group";
        return reply;
    }
    if (all_groups[group_id].owner != predicted_owner_id)
    {
        reply = "ERROR: Only owner of the group can accept the request";
        return reply;
    }
    // cout << "stage 3" << endl;
    all_groups[group_id].peers_requesting.erase(client_toaccetp_id);
    all_groups[group_id].peers_connected[client_toaccetp_id] = true;
    // cout << endl;
    // cout << "stage 4" << endl;
    // cout << "size fo connected que:" << all_groups[group_id].peers_connected.size() << endl;
    //  for (auto it = all_groups.begin(); it != all_groups.end(); it++)
    //  {
    //      cout << "key=" << all_groups[group_id].peers_requesting.first << " val=" << all_groups[group_id].peers_requesting->second;
    //  }
    reply = "Owner has accepted the group join request";
    return reply;
}

string list_Groups()
{
    string reply = "";
    for (auto it = all_groups.begin(); it != all_groups.end(); it++)
    {
        reply = reply + it->first;
        // reply.push_back(reply_sub);
        // cout << "key=" << it->first << endl;
        reply += " , ";
    }

    return reply;
}

string upload_File(const string &file_owner_id, const string &group_id, const string &file_path, const string &sha_val, const string &peer_ip, const string &peer_port)
{
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (login_user_map.find(file_owner_id) == login_user_map.end())
    {
        reply = "User is not logged in";
        return reply;
    }
    if (all_groups[group_id].peers_connected.find(file_owner_id) == all_groups[group_id].peers_connected.end())
    {
        reply = "User is not present in the group";
        return reply;
    }
    // adding file path to the map within Group class
    string ip_port_user = peer_ip + ":" + peer_port + ":" + file_owner_id;
    Files file_provided(file_path, sha_val, file_owner_id, peer_ip, peer_port);
    all_groups[group_id].files_owner_info[file_owner_id].push_back(file_provided);
    all_groups[group_id].sharable_files.push_back(file_path);
    all_groups[group_id].file_peers_containing[file_path].push_back(ip_port_user);
    // it is map
    for (auto it = all_groups[group_id].files_owner_info.begin(); it != all_groups[group_id].files_owner_info.end(); it++)
    {
        // cout << "key= " << it->first;
        for (int i = 0; i < it->second.size(); i++)
        {
            // cout << it->second[i].path << " ";
        }
        // cout << endl;
    }
    for (string a : all_groups[group_id].sharable_files)
    {
        //  cout << a << endl;
    }
    // cout << endl;
    // cout << "size fo requesting que:" << all_groups[group_id].peers_requesting.size() << endl;
    //  for (auto it = all_groups.begin(); it != all_groups.end(); it++)
    //  {
    //      cout << "key=" << all_groups[group_id].peers_requesting.first << " val=" << all_groups[group_id].peers_requesting->second;
    //  }
    reply = "File is uploaded by client " + file_owner_id;
    return reply;
}

string download_File(const string &group_id, const string &file_name)
{
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (all_groups[group_id].file_peers_containing.find(file_name) == all_groups[group_id].file_peers_containing.end())
    {
        reply = "Group does not contain the file";
        return reply;
    }
    else
    {
        reply = all_groups[group_id].file_peers_containing[file_name][0];
    }
    return reply;
}

string list_Files(const string &group_id, const string &requesting_client_id)
{
    // client requesting must be in group
    string reply;
    if (all_groups.find(group_id) == all_groups.end())
    {
        reply = "Group does not exists";
        return reply;
    }
    if (login_user_map.find(requesting_client_id) == login_user_map.end())
    {
        reply = "User is not logged in";
        return reply;
    }
    if (all_groups[group_id].peers_connected.find(requesting_client_id) == all_groups[group_id].peers_connected.end())
    {
        reply = "User is not present in the group";
        return reply;
    }
    vector<string> files_list = all_groups[group_id].sharable_files;
    for (int i = 0; i < files_list.size(); i++)
    {
        reply += files_list[i] + " , ";
    }
    return reply;
}

int stringToVector(string &msg, vector<string> &msg_vector, char delimiter)
{
    msg_vector.clear();
    string msg_chunk;

    for (auto ch : msg)
    {
        if (ch == delimiter)
        {
            if (!msg_chunk.empty())
            {
                msg_vector.push_back(msg_chunk);
                msg_chunk.clear();
            }
        }
        else
        {
            msg_chunk.push_back(ch);
        }
    }

    if (!msg_chunk.empty())
    {
        msg_vector.push_back(msg_chunk);
    }

    return msg_vector.size();
}

void *handleClient(void *arg)
{
    port_client_map *client_socket_obj = (port_client_map *)arg;
    // int client_socket = *(int *)arg;
    char buffer[BUFFER_SIZE];

    pthread_mutex_lock(&client_count_mutex);
    client_count++;
    cout << "A new client is connected. Total number of connected clients: " << client_count << endl;
    pthread_mutex_unlock(&client_count_mutex);

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        int read_size = read(client_socket_obj->new_sockfd, buffer, sizeof(buffer) - 1);

        if (read_size <= 0)
        {
            cout << "Client disconnected." << endl;
            break;
        }
        // else
        // {
        //     buffer[read_size] = '\0';
        //     cout << "Client Message: " << buffer << endl;
        // }

        string client_msg(buffer);
        vector<string> msg_vector;
        stringToVector(client_msg, msg_vector, ' ');
        // cout << "client message is " << client_msg << endl;

        // cout << "hii1" << endl;
        // for (int i = 0; i < msg_vector.size(); i++)
        // {
        //     cout << "msg_vector:" << msg_vector[0] << endl;
        // }
        // Check for 'create_user' command
        if (msg_vector[0] == "create_user")
        {
            string user_id = msg_vector[1];
            string passwd = msg_vector[2];

            bool user_created = createUser(user_id, passwd);
            string reply;

            if (user_created)
            {
                reply = "User with login_id=" + user_id + " created successfully.";
            }
            else
            {
                reply = "User already exists.";
            }
            // map_port_info_obj->new_sockfd
            cout << reply << endl;
            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
            continue;
        }

        if (msg_vector[0] == "login")
        {
            string user_id = msg_vector[1];
            string passwd = msg_vector[2];

            int login_succ = UserLogin(user_id, passwd);
            // cout << "login_succ=" << login_succ;
            string reply;

            if (login_succ == 1)
            {
                reply = "User with user_id=" + user_id + " logged in successfully";
            }
            else if (login_succ == 2)
            {
                reply = "Invalid password for user_id=" + user_id;
            }
            else if (login_succ == 3)
            {
                reply = "Client does not exist!";
            }
            else if (login_succ == 4)
            {
                reply = "User with user_id=" + user_id + " is already logged in";
            }
            cout << reply << endl;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
            continue;
        }

        if (msg_vector[0] == "create_group")
        {
            string group_id = msg_vector[1];
            string owner_id = msg_vector[2]; // we are sending the client owner id to create the group owner

            string reply = createGroup(owner_id, group_id);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "join_group")
        {
            string group_id = msg_vector[1];
            string client_id = msg_vector[2]; // we are sending the client owner id to create the group owner

            string reply = joinGroup(client_id, group_id);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "leave_group")
        {
            string group_id = msg_vector[1];
            string client_id = msg_vector[2]; // we are sending the client owner id to create the group owner

            string reply = leaveGroup(client_id, group_id);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "list_requests")
        {
            string group_id = msg_vector[1];
            string client_id = msg_vector[2]; // we are sending the client owner id to create the group owner

            string reply = list_Requests(client_id, group_id);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "accept_request")
        {
            // cout << "stage1" << endl;
            string group_id = msg_vector[1];
            string client_toaccept_id = msg_vector[2]; // we are sending the client owner id to create the group owner
            string predicted_owner_id = msg_vector[3];
            string reply = accept_Request(client_toaccept_id, group_id, predicted_owner_id);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "list_groups")
        {
            string reply = list_Groups();
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "upload_file")
        {
            string group_id = msg_vector[1];
            string file_path = msg_vector[2];
            string file_owner_id = msg_vector[3]; // we are sending the client owner id to create the group owner
            string sha_val = msg_vector[4];
            string peer_ip = msg_vector[5];
            string peer_port = msg_vector[6];
            string reply = upload_File(file_owner_id, group_id, file_path, sha_val, peer_ip, peer_port);
            cout << reply << endl;
            // string reply;

            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "list_files")
        {
            string group_id = msg_vector[1];
            string requesting_client_id = msg_vector[2];
            string reply = list_Files(group_id, requesting_client_id);
            cout << reply << endl;
            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }

        if (msg_vector[0] == "download_file")
        {
            string group_id = msg_vector[1];
            string file_name = msg_vector[2];
            string destination_path = msg_vector[3];
            string reply = download_File(group_id, file_name);
            cout << reply << endl;
            send(client_socket_obj->new_sockfd, reply.c_str(), reply.size(), 0);
        }
    }

    pthread_mutex_lock(&client_count_mutex);
    client_count--;
    pthread_mutex_unlock(&client_count_mutex);

    close(client_socket_obj->new_sockfd);
    pthread_exit(NULL);
}

void startTracker(const string &ip, int port)
{
    int tracker_socket, client_dummy_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t client_threads[MAX_CLIENTS];

    // Create socket
    tracker_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tracker_socket < 0)
    {
        cerr << "Error opening socket" << endl;
        exit(EXIT_FAILURE);
    }
    // Setting the socket option SO_REUSEADDR
    int yes = 1; // This enables the reuse of the address
    if (setsockopt(tracker_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    {
        cout << "ERROR: setsockopt failed" << endl;
        exit(1);
    }

    // Setup address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    server_addr.sin_port = htons(port);

    // Bind
    if (bind(tracker_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cout << "Error in binding to the created tracker socket" << endl;
        close(tracker_socket);
        exit(1);
    }

    // Listen
    if (listen(tracker_socket, MAX_CLIENTS) < 0)
    {
        cout << "ERROR: In listening on socket" << endl;
        // close(tracker_socket);
        exit(EXIT_FAILURE);
    }

    cout << "Tracker listening on " << ip << ":" << port << endl;

    int thread_count = 0;
    while (running)
    {
        client_dummy_socket = accept(tracker_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_dummy_socket < 0)
        {
            cerr << "Error accepting client connection" << endl;
            continue;
        }
        char buffer[BUFFER_SIZE] = {0};
        int valread = read(client_dummy_socket, buffer,
                           1024 - 1);
        printf("%s\n", buffer);
        char *mssg = "This message is from server";
        send(client_dummy_socket, mssg, strlen(mssg), 0);
        // printf("Hello message sent\n");

        port_client_map *map_port_info_obj = new port_client_map;
        map_port_info_obj->sockfd = tracker_socket;
        map_port_info_obj->new_sockfd = client_dummy_socket;
        map_port_info_obj->client_address_para = client_addr;
        map_port_info_obj->client_length = client_len;

        int val = pthread_create(&client_threads[thread_count++], NULL, handleClient, (void *)map_port_info_obj);

        if (val < 0)
        {
            perror("ERROR: In creating in thread");
        }
        // pthread_detach(client_threads[thread_count - 1]);

        if (thread_count >= MAX_CLIENTS)
        {
            cout << "Reached max client limit." << endl;
            break;
        }
    }

    close(tracker_socket);
    pthread_exit(NULL);
    // pthread_mutex_destroy(&client_count_mutex);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cout << "Input correct number of arguments" << endl;
        return 1;
    }

    // Reading about the trackers details from the tracker_info.txt file provided in the command line args.
    string tracker_info_file_path = argv[1];

    vector<string> ip_port_vect;
    FILE *tracker_info_file_ptr = fopen(tracker_info_file_path.c_str(), "r");

    char ch;
    string tracker_info_str;
    while ((ch = fgetc(tracker_info_file_ptr)) != EOF)
    {
        // cout << ch << endl;
        tracker_info_str.push_back(ch);
    }

    fclose(tracker_info_file_ptr);
    // cout << "file closed" << endl;

    stringToVector(tracker_info_str, ip_port_vect, ' ');
    // cout << "port is " << ip_port_vect[1] << endl;
    string ip = ip_port_vect[0];
    int port = stoi(ip_port_vect[1]);

    int tracker_no = stoi(argv[2]);

    if (ip.empty())
    {
        cout << "Invalid tracker number" << endl;
        return 1;
    }

    // Start tracker
    startTracker(ip, port);

    return 0;
}