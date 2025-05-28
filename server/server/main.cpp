#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <cstring>          
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")

constexpr int SERVER_PORT = 9000;
constexpr int MAX_ROOMS = 10;   
constexpr int MAX_CLIENTS_PER_ROOM = 40;

struct Client {
    SOCKET sock;              
    std::string nick;     
    int room_id;           

    Client(SOCKET s = INVALID_SOCKET, const std::string& n = "", int r = -1)
        : sock(s), nick(n), room_id(r) {
    }
};

struct Room {
    std::string name;
    std::set<SOCKET> clients;
};

static std::vector<Room>        rooms;
static std::map<SOCKET, Client> clients;
static std::mutex               mtx;
static std::map<SOCKET, SSL*>   client_ssl_map;

void broadcast(int room_id, const std::string& msg, SOCKET sender_sock) {
    std::vector<SOCKET> targets;
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (SOCKET s : rooms[room_id].clients) {
            targets.push_back(s);
        }
    }
    for (SOCKET s : targets) {
        SSL* ssl = nullptr;
        {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = client_ssl_map.find(s);
            if (it != client_ssl_map.end()) ssl = it->second;
        }
        if (ssl) {
            std::string out_msg = (s == sender_sock) ? ("me: " + msg.substr(msg.find(":") + 1)) : msg;
            SSL_write(ssl, out_msg.data(), out_msg.size());
        }
    }
}

// Levenshtein distance for command suggestion
int levenshtein(const std::string& s1, const std::string& s2) {
    const size_t m = s1.size(), n = s2.size();
    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
    for (size_t i = 0; i <= m; ++i) dp[i][0] = i;
    for (size_t j = 0; j <= n; ++j) dp[0][j] = j;
    for (size_t i = 1; i <= m; ++i) {
        for (size_t j = 1; j <= n; ++j) {
            if (s1[i - 1] == s2[j - 1]) dp[i][j] = dp[i - 1][j - 1];
            else {
                int a = dp[i - 1][j];
                int b = dp[i][j - 1];
                int c = dp[i - 1][j - 1];
                int min_val = a < b ? (a < c ? a : c) : (b < c ? b : c);
                dp[i][j] = 1 + min_val;
            }
        }
    }
    return dp[m][n];
}

void handleClient(SOCKET sock, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mtx);
        client_ssl_map[sock] = ssl;
    }
    std::cout << "New client thread started: " << sock << std::endl;
    char buf[1024];

    const char* prompt = "Enter /nick <name> to set nickname\n";
    SSL_write(ssl, prompt, strlen(prompt));

    while (true) {
        int len = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (len <= 0) break;
        buf[len] = '\0';

        std::istringstream iss(buf);
        std::string cmd;
        iss >> cmd;

        if (cmd == "/nick") {
            std::string name;
            iss >> name;
            if (name.empty()) {
                const char* msg =
                    "====================\n"
                    "Invalid nickname\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
                continue;
            }
            std::lock_guard<std::mutex> lock(mtx);
            bool exists = false;
            for (auto& p : clients) {
                if (p.second.nick == name) {
                    exists = true;
                    break;
                }
            }
            if (exists) {
                const char* msg =
                    "====================\n"
                    "Nickname in use\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
            }
            else {
                clients[sock].nick = name;
                const char* msg =
                    "====================\n"
                    "Nickname set\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
                // Show room list after setting nickname
                std::ostringstream out;
                out << "====================\nRooms:\n";
                for (int i = 0; i < (int)rooms.size(); ++i) {
                    out << i << ". " << rooms[i].name
                        << " (" << rooms[i].clients.size()
                        << "/" << MAX_CLIENTS_PER_ROOM << ")\n";
                }
                out << "====================\n";
                auto s = out.str();
                SSL_write(ssl, s.data(), s.size());
            }
        }
        else if (cmd == "/list") {
            std::lock_guard<std::mutex> lock(mtx);
            std::ostringstream out;
            out << "====================\nRooms:\n";
            for (int i = 0; i < (int)rooms.size(); ++i) {
                out << i << ". " << rooms[i].name
                    << " (" << rooms[i].clients.size()
                    << "/" << MAX_CLIENTS_PER_ROOM << ")\n";
            }
            out << "====================\n";
            auto s = out.str();
            SSL_write(ssl, s.data(), s.size());
        }
        else if (cmd == "/create") {
            std::string rname;
            iss >> rname;
            std::lock_guard<std::mutex> lock(mtx);
            if ((int)rooms.size() >= MAX_ROOMS) {
                const char* msg =
                    "====================\n"
                    "Max rooms reached\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
            }
            else {
                rooms.push_back({ rname, {} });
                const char* msg =
                    "====================\n"
                    "Room created\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
            }
        }
        else if (cmd == "/join") {
            int id;
            if (!(iss >> id)) {
                const char* msg =
                    "====================\n"
                    "Usage: /join <room_id>\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
                continue;
            }
            int prev = -1;
            std::string leaveMsg, joinMsg;
            bool sendJoinMsg = false;
            {
                std::lock_guard<std::mutex> lock(mtx);
                std::cout << "sock " << sock << " tries to join room    " << id << std::endl;
                if (id < 0 || id >= (int)rooms.size()) {
                    const char* msg =
                        "====================\n"
                        "No such room\n"
                        "====================\n";
                    SSL_write(ssl, msg, strlen(msg));
                    continue;
                }
                else if (rooms[id].clients.size() >= MAX_CLIENTS_PER_ROOM) {
                    const char* msg =
                        "====================\n"
                        "Room full\n"
                        "====================\n";
                    SSL_write(ssl, msg, strlen(msg));
                    continue;
                }
                else {
                    prev = clients[sock].room_id;
                    if (prev >= 0) {
                        rooms[prev].clients.erase(sock);
                        leaveMsg = clients[sock].nick + " left room " + std::to_string(prev) + "\n";
                    }
                    clients[sock].room_id = id;
                    rooms[id].clients.insert(sock);
                    joinMsg = clients[sock].nick + " joined room " + std::to_string(id) + "\n";
                    const char* msg =
                        "====================\n"
                        "Joined room\n"
                        "====================\n";
                    SSL_write(ssl, msg, strlen(msg));
                    sendJoinMsg = !clients[sock].nick.empty();
                }
            }
        }
        else if (cmd == "/w") {
            std::string target;
            iss >> target;
            std::string msg;
            getline(iss, msg);
            std::lock_guard<std::mutex> lock(mtx);
            for (auto& p : clients) {
                if (p.second.nick == target) {
                    std::string out = "==== 시스템 메시지 ====\n(whisper) " + clients[sock].nick + ":" + msg + "\n====================\n";
                    SSL* target_ssl = client_ssl_map[p.first];
                    if (target_ssl) {
                        SSL_write(target_ssl, out.data(), out.size());
                    }
                    break;
                }
            }
        }
        else if (cmd == "/exit") {
            std::lock_guard<std::mutex> lock(mtx);
            int rid = clients[sock].room_id;
            if (rid >= 0) {
                rooms[rid].clients.erase(sock);
                clients[sock].room_id = -1;
                const char* msg =
                    "====================\n"
                    "Left room\n"
                    "====================\n";
                SSL_write(ssl, msg, strlen(msg));
            }
        }
        else if (cmd == "/help") {
            const char* help_msg =
                "====================\n"
                "Available commands:\n"
                "/help - Show this help message\n"
                "/nick <name> - Set your nickname\n"
                "/list - Show list of available rooms\n"
                "/create <room_name> - Create a new room\n"
                "/join <room_id> - Join a room\n"
                "/w <nickname> <message> - Send a whisper to a user\n"
                "/exit - Leave current room\n"
                "/quit - Exit the program\n"
                "====================\n";
            SSL_write(ssl, help_msg, strlen(help_msg));
        }
        else if (cmd == "/quit") {
            break;
        }
        else {
            if (!cmd.empty() && cmd[0] == '/') {
                // 명령어 추천
                const char* commands[] = {"/help","/nick","/list","/create","/join","/w","/exit","/quit"};
                int minDist = 100, idx = -1;
                for (int i = 0; i < 8; ++i) {
                    int d = levenshtein(cmd, commands[i]);
                    if (d < minDist) { minDist = d; idx = i; }
                }
                std::ostringstream out;
                out << "====================\nUnknown command. Please try again.\n";
                if (minDist <= 3) {
                    out << "Did you mean: " << commands[idx] << " ?\n";
                }
                out << "====================\n";
                auto s = out.str();
                SSL_write(ssl, s.data(), s.size());
            } else {
                int rid = clients[sock].room_id;
                if (rid >= 0 && !clients[sock].nick.empty()) {
                    std::string out = clients[sock].nick + ": " + buf;
                    broadcast(rid, out, sock);
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(mtx);
        int rid = clients[sock].room_id;
        if (rid >= 0) rooms[rid].clients.erase(sock);
        clients.erase(sock);
        client_ssl_map.erase(sock);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed" << std::endl;
        WSACleanup();
        return 1;
    }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "SSL_CTX_use_certificate_file failed" << std::endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "SSL_CTX_use_PrivateKey_file failed" << std::endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(ls);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    if (listen(ls, 5) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(ls);
        SSL_CTX_free(ctx);
        WSACleanup();
        return 1;
    }

    std::cout << "Server on port " << SERVER_PORT << "\n";

    while (true) {
        SOCKET cs = accept(ls, nullptr, nullptr);
        if (cs == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;  
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            clients.emplace(cs, Client(cs, "", -1));
        }
        std::thread(handleClient, cs, ctx).detach();
    }

    closesocket(ls);
    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}
