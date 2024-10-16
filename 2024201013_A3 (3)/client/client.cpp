#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>

using namespace std;
#define BUFFER_SIZE 512
#define CHUNK_SIZE 512 // 512 KB

struct sockaddr_in server_addr; // tracker socket info like ip and port no
int sockfd;                     // tracker socket file descriptor
string ip;
string port;

string connectToTracker(const string &ip, int port, int *sockfd)
{
    // int sockfd;
    // struct sockaddr_in server_addr;

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd < 0)
    {
        cout << "Error in opening the socket" << endl;
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    server_addr.sin_port = htons(port);

    if (connect(*sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cout << "Error connecting to tracker at " << ip << ":" << port << endl;
        close(*sockfd);
        // exit(EXIT_FAILURE);
    }

    // cout << "Connected to tracker at " << ip << ":" << port << endl;
    string mssg_to_server = "Client with has send this message";
    send(*sockfd, mssg_to_server.c_str(), strlen(mssg_to_server.c_str()), 0);
    char buffer[1024] = {0};
    int valread = read(*sockfd, buffer, BUFFER_SIZE - 1);

    string reply = buffer;
    printf("%s\n", buffer);
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

    // After the loop, add the last chunk (if any) to the vector
    if (!msg_chunk.empty())
    {
        msg_vector.push_back(msg_chunk);
    }

    // Return the size of the resulting vector
    return msg_vector.size();
}

void createUser(int tracker_socket, const string &user_id, const string &passwd)
{
    string create_user_command = "create_user " + user_id + " " + passwd;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void loginUser(int tracker_socket, const string &user_id, const string &passwd)
{
    // cout << "within loginUser function" << endl;
    string create_user_command = "login " + user_id + " " + passwd;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);
    // cout << "from loginUser login request sent to tracker" << endl;
    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Login Status: Failed to receive response from tracker." << endl;
    }
}

void createGroup(int tracker_socket, const string &group_id, const string &group_owner_id)
{

    string create_user_command = "create_group " + group_id + " " + group_owner_id;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void joinGroup(int tracker_socket, const string &group_id, const string &client_id)
{
    string create_user_command = "join_group " + group_id + " " + client_id;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void leaveGroup(int tracker_socket, const string &group_id, const string &client_id)
{
    string create_user_command = "leave_group " + group_id + " " + client_id;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void listRequests(int tracker_socket, const string &group_id, const string &client_id)
{
    string create_user_command = "list_requests " + group_id + " " + client_id;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}
void acceptRequest(int tracker_socket, const string &group_id, const string &client_toaccept_id, const string &owner_id)
{
    string create_user_command = "accept_request " + group_id + " " + client_toaccept_id + " " + owner_id;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void listFiles(int tracker_socket, const string &group_id, const string &client_id_list_files)
{
    string create_user_command = "list_files " + group_id + " " + client_id_list_files;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

void listGroups(int tracker_socket)
{
    string create_user_command = "list_groups ";
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

string toHexString(const unsigned char *hash, unsigned int hashLength)
{
    ostringstream oss;
    for (unsigned int i = 0; i < hashLength; ++i)
    {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// Function to compute full file and piecewise SHA-1 hashes
string sha_val_calc(const string &filePath, size_t pieceSize, string &fullFileHash, vector<string> &piecewiseHashes)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;
    EVP_MD_CTX *fullMdctx = EVP_MD_CTX_new();
    EVP_MD_CTX *pieceMdctx = EVP_MD_CTX_new();

    string reply;
    if (fullMdctx == nullptr || pieceMdctx == nullptr)
    {
        reply = "ERROR: Failed to create EVP_MD_CTX";
        return reply;
    }

    if (EVP_DigestInit_ex(fullMdctx, EVP_sha1(), nullptr) != 1 ||
        EVP_DigestInit_ex(pieceMdctx, EVP_sha1(), nullptr) != 1)
    {
        EVP_MD_CTX_free(fullMdctx);
        EVP_MD_CTX_free(pieceMdctx);
        reply = "ERROR: Failed to initialize digest context";
        return reply;
    }

    // Open the file using system calls
    int fileDescriptor = open(filePath.c_str(), O_RDONLY);
    if (fileDescriptor < 0)
    {
        EVP_MD_CTX_free(fullMdctx);
        EVP_MD_CTX_free(pieceMdctx);
        reply = "ERROR: Could not open file: " + filePath;
        return reply;
    }

    char buffer[512 * 1024]; // Buffer for reading file
    ssize_t bytesRead;
    size_t bytesInCurrentPiece = 0;

    while ((bytesRead = read(fileDescriptor, buffer, sizeof(buffer))) > 0)
    {

        if (EVP_DigestUpdate(fullMdctx, buffer, bytesRead) != 1)
        {
            close(fileDescriptor);
            EVP_MD_CTX_free(fullMdctx);
            EVP_MD_CTX_free(pieceMdctx);
            reply = "ERROR: updating the full file digest";
            return reply;
        }

        // Update the piece hash
        if (EVP_DigestUpdate(pieceMdctx, buffer, bytesRead) != 1)
        {
            close(fileDescriptor);
            EVP_MD_CTX_free(fullMdctx);
            EVP_MD_CTX_free(pieceMdctx);
            reply = "ERROR: updating the piecewise digest";
            return reply;
        }

        bytesInCurrentPiece += bytesRead;
        if (bytesInCurrentPiece >= pieceSize)
        {

            if (EVP_DigestFinal_ex(pieceMdctx, hash, &hashLength) != 1)
            {
                close(fileDescriptor);
                EVP_MD_CTX_free(fullMdctx);
                EVP_MD_CTX_free(pieceMdctx);
                reply = "ERROR: finalizing the piecewise digest";
                return reply;
            }

            piecewiseHashes.push_back(toHexString(hash, hashLength));
            EVP_DigestInit_ex(pieceMdctx, EVP_sha1(), nullptr);
            bytesInCurrentPiece = 0;
        }
    }

    if (bytesInCurrentPiece > 0)
    {
        if (EVP_DigestFinal_ex(pieceMdctx, hash, &hashLength) != 1)
        {
            close(fileDescriptor);
            EVP_MD_CTX_free(fullMdctx);
            EVP_MD_CTX_free(pieceMdctx);
            reply = "ERROR: finalizing the last piecewise digest";
            return reply;
        }
        piecewiseHashes.push_back(toHexString(hash, hashLength));
    }

    if (EVP_DigestFinal_ex(fullMdctx, hash, &hashLength) != 1)
    {
        close(fileDescriptor);
        EVP_MD_CTX_free(fullMdctx);
        EVP_MD_CTX_free(pieceMdctx);
        reply = "ERROR: finalizing the full file digest";
        return reply;
    }

    fullFileHash = toHexString(hash, hashLength);

    close(fileDescriptor);
    EVP_MD_CTX_free(fullMdctx);
    EVP_MD_CTX_free(pieceMdctx);
    return "";
}
void uploadFile(int tracker_socket, const string &file_path, const string &group_id, const string &file_owner_id, const string &ip_client, const string &port_client)
{
    // check if file exists and is readable in system
    const char *filePath = file_path.c_str();
    struct stat fileStat;
    if (stat(filePath, &fileStat) != 0)
    {
        cout << "ERROR: File does not exist";
        return;
    }
    else
    {
        if (S_ISREG(fileStat.st_mode))
        {
        }
        else
        {
            cout << "ERROR: File is not regular";
            return;
        }

        // Check if the file is readable by the user
        if (fileStat.st_mode & S_IRUSR)
        {
        }
        else
        {
            cout << "File is not readable." << endl;
            return;
        }
    }

    const size_t pieceSize = 512 * 1024;

    string fullFileHash;
    vector<string> piecewiseHashes;
    // string piecewiseHas

    // Compute the full file and piecewise hashes
    string reply = sha_val_calc(file_path, pieceSize, fullFileHash, piecewiseHashes);
    if (reply != "")
    {
        cout << reply << endl;
        return;
    }

    // Display the full file hash
    // cout << "SHA-1 hash of the complete file: " << fullFileHash << endl;

    // Display the piecewise hashes
    // cout << "Piecewise SHA-1 hashes: " << endl;
    for (size_t i = 0; i < piecewiseHashes.size(); ++i)
    {
        // cout << "Piece " << i + 1 << ": " << piecewiseHashes[i] << endl;
    }

    string create_user_command = "upload_file " + group_id + " " + file_path + " " + file_owner_id + " " + fullFileHash + " " + ip_client + " " + port_client;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }
}

// Function to read from file using system calls
void readFileChunks(const string &filePath, vector<vector<char>> &fileChunks)
{
    // cout << "reading from file" << endl;
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd == -1)
    {
        cout << "Error opening file for reading: " << filePath << endl;
        return;
    }

    char buffer[CHUNK_SIZE];
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buffer, sizeof(buffer))) > 0)
    {
        vector<char> chunk(buffer, buffer + bytesRead);
        fileChunks.push_back(chunk);
    }
    cout << "File completely read" << endl;

    close(fd);
}
// Function to write to file using system calls
void writeFileChunks(const string &filePath, const vector<vector<char>> &fileChunks)
{
    // cout << "writing to file" << endl;
    int fd = open(filePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        cout << "Error opening file for writing: " << filePath << endl;
        return;
    }
    // cout << "opened file " << fd << endl;

    for (const auto &chunk : fileChunks)
    {
        if (write(fd, chunk.data(), chunk.size()) == -1)
        {
            cerr << "Error writing chunk to file." << endl;
            close(fd);
            return;
        }
    }
    cout << "File completely written" << endl;

    close(fd);
}
// Function for the server to listen for incoming connections
void connect_to_desired_peer(const string &ip_server, int serverPort, const string &group_id_downlod, const string &destination_path, const string &source_file_path)
{
    // Create a socket
    int socket_fd_desired_peer = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_desired_peer < 0)
    {
        cerr << "Error creating socket for " << ip_server << ":" << serverPort << endl;
        return;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip_server.c_str());
    server_addr.sin_port = htons(serverPort); // Convert port number to network byte order

    // Convert IP address from text to binary form
    if (inet_pton(AF_INET, ip_server.c_str(), &server_addr.sin_addr) <= 0)
    {
        cerr << "Invalid address/Address not supported for " << ip_server << ":" << serverPort << endl;
        close(socket_fd_desired_peer);
        return;
    }

    // Connect to the server
    if (connect(socket_fd_desired_peer, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << "Connection failed to " << ip_server << ":" << serverPort << endl;
        close(socket_fd_desired_peer);
        return;
    }

    cout << "Connected to server " << ip_server << ":" << serverPort << endl;

    // fetch file from client
    string str_message = "download_file " + source_file_path; // here we will send the name of file like f1.txt
    const char *message = str_message.c_str();

    // const char *message = "download_file " + source_file_path;
    // cout << "send to tracker" << endl;
    send(socket_fd_desired_peer, message, strlen(message), 0);
    // cout << "yes send" << endl;
    //  handleClientConnection(socket_fd_desired_peer, "f1.txt");
    char buffer_peer[1024] = {0};

    int valread = read(socket_fd_desired_peer, buffer_peer, sizeof(buffer_peer));
    cout << "Server " << ip << ":" << serverPort << " says: " << buffer_peer << endl;

    vector<vector<char>> receivedChunks;
    char buffer[CHUNK_SIZE];
    ssize_t bytesRead;
    // cout << "stage1" << endl;
    while ((bytesRead = recv(socket_fd_desired_peer, buffer, sizeof(buffer), 0)) > 0)
    {
        vector<char> chunk(buffer, buffer + bytesRead);
        receivedChunks.push_back(chunk);
    }
    // cout << "stage2" << endl;
    writeFileChunks(destination_path, receivedChunks); // Save received chunks to file
    // cout << "stage3" << endl;
    //  Close the socket after the exchange
    //  close(sock);

    // Close the socket when done
    close(socket_fd_desired_peer);
    // cout << "stage4" << endl;
}

void downloadFile(int tracker_socket, const string &group_id, const string &file_name, const string &destination_path)
{
    string create_user_command = "download_file " + group_id + " " + file_name + " " + destination_path;
    // cout << "command for tracker:" << create_user_command << endl;
    send(tracker_socket, create_user_command.c_str(), create_user_command.size(), 0);

    char buffer[BUFFER_SIZE] = {0};
    int read_size = read(tracker_socket, buffer, sizeof(buffer) - 1);

    // all of the above code is good, fetch the ip and port and piece which will be asked to the server(peer who have it).
    if (read_size > 0)
    {
        cout << "Response from tracker: " << buffer << endl;
        vector<string> cmd_from_requesting_peer;
        string source = buffer;
        int return_val = stringToVector(source, cmd_from_requesting_peer, ':');
        string ip_of_peer_containing_piece = cmd_from_requesting_peer[0];
        int port_of_peer_containing_piece = stoi(cmd_from_requesting_peer[1]);
        // cout << "stage 1" << endl;
        //  string ip_of_peer_containing_piece = "127.0.0.1";
        //  int port_of_peer_containing_piece = stoi("8001");

        // thread server_client_Thread_collection(connect_to_desired_peer, std::cref(ip_of_peer_containing_piece), port_of_peer_containing_piece, std::cref(destination_path)); // so that this client can connect to various servers
        std::thread server_client_Thread_collection(
            connect_to_desired_peer,
            ip_of_peer_containing_piece,
            port_of_peer_containing_piece,
            group_id,
            destination_path,
            file_name);

        server_client_Thread_collection.detach();
    }
    else
    {
        cout << "Failed to receive response from tracker." << endl;
    }

    // from here connect to the peer
}

void handleClientConnection(int clientSocket, const string &filePath)
{
    // cout << "within handlClientconnection" << endl;
    vector<vector<char>> fileChunks;
    readFileChunks(filePath, fileChunks); // Read the file in chunks

    for (const auto &chunk : fileChunks)
    {
        send(clientSocket, chunk.data(), chunk.size(), 0); // Send chunks
    }

    close(clientSocket);
}

void downloadFileFromServer(const string &serverIp, int serverPort, const string &downloadPath)
{
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        cout << "Failed to create socket." << endl;
        return;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        cout << "Connection failed." << endl;
        close(clientSocket);
        return;
    }

    vector<vector<char>> receivedChunks;
    char buffer[CHUNK_SIZE];
    ssize_t bytesRead;

    while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
    {
        vector<char> chunk(buffer, buffer + bytesRead);
        receivedChunks.push_back(chunk);
    }

    writeFileChunks(downloadPath, receivedChunks); // Save received chunks to file

    close(clientSocket);
}

bool readFileContent(int fd, string &content)
{
    const size_t bufferSize = 1024; // 1 KB buffer
    char buffer[bufferSize];
    ssize_t bytesRead;

    // Clear content string before reading
    content.clear();

    // Read file in chunks
    while ((bytesRead = read(fd, buffer, bufferSize)) > 0)
    {
        content.append(buffer, bytesRead);
    }

    if (bytesRead < 0)
    {
        cout << "Error: Could not read file - " << strerror(errno) << endl;
        return false;
    }

    return true;
}

// Function to process each line and extract IP and port
string processLine(const string &line)
{
    size_t spacePos = line.find(' '); // Find the space separating IP and port
    string reply;
    // Check if space was found and line has valid format
    if (spacePos != string::npos)
    {
        string ip_tracker = line.substr(0, spacePos);
        string port_tracker_string = line.substr(spacePos + 1);

        try
        {
            int port_tracker = stoi(port_tracker_string); // Convert port string to an integer
            // cout << "IP: " << ip << ", Port: " << port << endl;
            if (connectToTracker(ip_tracker, port_tracker, &sockfd) == "This message is from server")
            {
                // thread clientThread(conection_with_peers, client_socket_fd);

                reply = "connected";
                // cout << reply << endl;
                return reply;
            }
        }
        catch (const invalid_argument &)
        {
            cerr << "Error: Invalid port in line: " << line << endl;
        }
        catch (const out_of_range &)
        {
            cerr << "Error: Port out of range in line: " << line << endl;
        }
    }
    else
    {
        cerr << "Error: Invalid format in line: " << line << endl;
    }
    reply = "not connected";
    // cout << reply << endl;
    return reply;
}

// Function to process the entire file content
void processFileContent(const string &content)
{
    size_t start = 0;
    size_t end = content.find('\n'); // Find the first newline

    // Process each line
    while (end != string::npos)
    {
        string line = content.substr(start, end - start); // Extract the line
        if (processLine(line) == "connected")
        {
            return;
        } // Process the extracted line

        start = end + 1;                 // Move start position to the next line
        end = content.find('\n', start); // Find the next newline
    }

    // Process the last line (if the file doesn't end with a newline)
    if (start < content.length())
    {
        processLine(content.substr(start));
    }
}

int creating_socket_this_client_bind(string ip_addr1, string port1)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        cout << "Error: Unable to create socket";
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(stoi(port1));

    // Bind the socket to the address and port
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(server_fd);
        cout << "Error: Unable to bind socket to port";
        return -1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 10) < 0)
    {
        close(server_fd);
        cout << "Error: Unable to listen on socket";
        return -1;
    }

    // Return the file descriptor for the server socket
    return server_fd;
}

void conection_with_peers(int client_socket_fd)
{
    char buffer[8192];

    string message = "client with sockeid=" + to_string(client_socket_fd) + " connected";
    size_t message_length = message.size();

    // Send the message
    ssize_t bytes_sent = send(client_socket_fd, message.c_str(), message_length, 0);

    ssize_t bytes_received = read(client_socket_fd, buffer, sizeof(buffer) - 1);

    // Check if data was received successfully
    if (bytes_received > 0)
    {
        cout << "Received: " << buffer << endl;
        vector<string> cmd_from_requesting_peer;
        string source = buffer;
        int return_val = stringToVector(source, cmd_from_requesting_peer, ' ');

        string command_one = cmd_from_requesting_peer[0];
        // cout << command_one << endl;
        string file_path_in_server = cmd_from_requesting_peer[1];
        // cout << "down_laodfile" << endl;
        if (command_one == "download_file")
        {
            // cout << "within if boock" << endl;
            handleClientConnection(client_socket_fd, file_path_in_server);
        }
        // here from file path provided send the file to the client
    }
    else if (bytes_received == 0)
    {
        // Connection was closed by the peer
        cout << "Client closed the connection." << endl;
    }
    else
    {
        // An error occurred
        perror("read() failed");
    }
}

void this_client_listen(int this_client_socket_fd)
{
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    cout << "This client is ready to accept request from other clients..." << endl;

    while (true)
    {
        // Accept a new connection
        int client_socket_fd_dummy = accept(this_client_socket_fd, (sockaddr *)&client_addr, &client_len);
        if (client_socket_fd_dummy < 0)
        {
            perror("Error accepting client connection");
            break;
        }

        // cout << "Client " << client_socket_fd_dummy << " connected, starting file transfer..." << endl;

        // Handle each client in a new thread
        thread clientThread(conection_with_peers, client_socket_fd_dummy);
        // conection_with_peers(client_socket_fd_dummy);
        clientThread.detach(); // Detach the thread so it can run independently
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        cout << "Pass valid number of arguments" << endl;
        return 1;
    }
    const char *filePath = argv[2];
    string ip_port = argv[1];
    size_t colon_pos = ip_port.find(':');
    if (colon_pos == string::npos)
    {
        cerr << "Invalid format for IP:PORT" << endl;
        return EXIT_FAILURE;
    }
    ip = ip_port.substr(0, colon_pos);
    port = (ip_port.substr(colon_pos + 1));
    cout << ip << ":" << port << endl;

    // creting a socket for this client so that in future it could act as server
    int this_client_socket_fd = creating_socket_this_client_bind(ip, port);
    thread clientThread(this_client_listen, this_client_socket_fd);
    clientThread.detach();

    int fd = open(filePath, O_RDONLY);
    if (fd < 0)
    {
        cerr << "Error: Could not open file - " << strerror(errno) << endl;
        return 1;
    }

    string fileContent;

    // Read the content of the file
    if (!readFileContent(fd, fileContent))
    {
        close(fd);
        return 1;
    }

    close(fd);

    processFileContent(fileContent);

    string global_user_id;

    string recv_msg;
    string send_msg;
    string serv_msg;

    string choice_str;

    int choice;
    bool flag = true;

    // SETUP

    vector<string> cmd_input;
    string raw_input;
    // char raw_input_chr[2048];

    // WORKING
    while (flag)
    {

        getline(cin, raw_input);

        int return_val = stringToVector(raw_input, cmd_input, ' ');

        string command = cmd_input[0];
        // cout << "within client " << command << endl;
        if (cmd_input.size() == 3 && command == "create_user")
        {
            // cout << "hii" << endl;
            string user_id = cmd_input[1];
            string password = cmd_input[2];
            global_user_id = user_id;
            createUser(sockfd, user_id, password);
        }
        if (cmd_input.size() == 3 && command == "login")
        {
            // cout << "within login if condition" << endl;
            string user_id = cmd_input[1];
            string password = cmd_input[2];
            loginUser(sockfd, user_id, password);
        }
        if (cmd_input.size() == 2 && command == "create_group")
        {
            string group_id = cmd_input[1];
            // cout << "within create_group" << endl;
            createGroup(sockfd, group_id, global_user_id);
        }
        if (cmd_input.size() == 2 && command == "join_group")
        {
            string group_id = cmd_input[1];
            // cout << "within join_group" << endl;
            joinGroup(sockfd, group_id, global_user_id);
        }
        if (cmd_input.size() == 2 && command == "leave_group")
        {
            string group_id = cmd_input[1];
            // cout << "within leave_group" << endl;
            leaveGroup(sockfd, group_id, global_user_id);
        }
        if (cmd_input.size() == 2 && command == "list_requests")
        {
            string group_id = cmd_input[1];
            // cout << "within leave_group" << endl;
            listRequests(sockfd, group_id, global_user_id);
        }
        if (cmd_input.size() == 1 && command == "list_groups")
        {
            listGroups(sockfd);
        }
        if (cmd_input.size() == 3 && command == "accept_request")
        {
            string group_id = cmd_input[1];
            string user_id = cmd_input[2];
            acceptRequest(sockfd, group_id, user_id, global_user_id);
        }
        if (cmd_input.size() == 2 && command == "list_files")
        {
            string group_id = cmd_input[1];
            listFiles(sockfd, group_id, global_user_id);
        }
        if (cmd_input.size() == 3 && command == "upload_file")
        {
            string file_path = cmd_input[1];
            string group_id = cmd_input[2];
            uploadFile(sockfd, file_path, group_id, global_user_id, ip, port);
        }
        if (cmd_input.size() == 4 && command == "download_file")
        {
            string group_id = cmd_input[1];
            string file_name = cmd_input[2];
            string destination_path = cmd_input[3];
            downloadFile(sockfd, group_id, file_name, destination_path);
        }
    }
    return 0;
}
