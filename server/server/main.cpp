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

void broadcast(int room_id, const std::string& msg, SOCKET except = INVALID_SOCKET) {
    std::vector<SOCKET> targets;
    {
        std::lock_guard<std::mutex> lock(mtx);
        for (SOCKET s : rooms[room_id].clients) {
            if (s != except) targets.push_back(s);
        }
    }
    for (SOCKET s : targets) {
        send(s, msg.data(), msg.size(), 0);
    }
}

void handleClient(SOCKET sock) {
    std::cout << "New client thread started: " << sock << std::endl;
    char buf[1024];

    const char* prompt = "Enter /nick <name> to set nickname\n";
    send(sock, prompt, strlen(prompt), 0);

    while (true) {
        int len = recv(sock, buf, sizeof(buf) - 1, 0);
        if (len <= 0) break;
        buf[len] = '\0';

        std::istringstream iss(buf);
        std::string cmd;
        iss >> cmd;

        if (cmd == "/nick") {
            std::string name;
            iss >> name;
            if (name.empty()) {
                send(sock, "Invalid nickname\n", strlen("Invalid nickname\n"), 0);
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
                send(sock, "Nickname in use\n", strlen("Nickname in use\n"), 0);
            }
            else {
                clients[sock].nick = name;
                send(sock, "Nickname set\n", strlen("Nickname set\n"), 0);
                
                // Show room list after setting nickname
                std::ostringstream out;
                out << "Rooms:\n";
                for (int i = 0; i < (int)rooms.size(); ++i) {
                    out << i << ". " << rooms[i].name
                        << " (" << rooms[i].clients.size()
                        << "/" << MAX_CLIENTS_PER_ROOM << ")\n";
                }
                auto s = out.str();
                send(sock, s.data(), s.size(), 0);
            }
        }
        else if (cmd == "/list") {
            std::lock_guard<std::mutex> lock(mtx);
            std::ostringstream out;
            out << "Rooms:\n";
            for (int i = 0; i < (int)rooms.size(); ++i) {
                out << i << ". " << rooms[i].name
                    << " (" << rooms[i].clients.size()
                    << "/" << MAX_CLIENTS_PER_ROOM << ")\n";
            }
            auto s = out.str();
            send(sock, s.data(), s.size(), 0);
        }
        else if (cmd == "/create") {
            std::string rname;
            iss >> rname;
            std::lock_guard<std::mutex> lock(mtx);
            if ((int)rooms.size() >= MAX_ROOMS) {
                send(sock, "Max rooms reached\n", strlen("Max rooms reached\n"), 0);
            }
            else {
                rooms.push_back({ rname, {} });
                send(sock, "Room created\n", strlen("Room created\n"), 0);
            }
        }
        else if (cmd == "/join") {
            int id;
            if (!(iss >> id)) {
                send(sock, "Usage: /join <room_id>\n", strlen("Usage: /join <room_id>\n"), 0);
                continue;
            }

            int prev = -1;
            std::string leaveMsg, joinMsg;
            bool sendJoinMsg = false;
            {
                std::lock_guard<std::mutex> lock(mtx);
                std::cout << "sock " << sock << " tries to join room " << id << std::endl;
                if (id < 0 || id >= (int)rooms.size()) {
                    send(sock, "No such room\n", strlen("No such room\n"), 0);
                    continue;
                }
                else if (rooms[id].clients.size() >= MAX_CLIENTS_PER_ROOM) {
                    send(sock, "Room full\n", strlen("Room full\n"), 0);
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
                    send(sock, "Joined room\n", strlen("Joined room\n"), 0);
                    sendJoinMsg = !clients[sock].nick.empty();
                }
            }
            if (prev >= 0 && !leaveMsg.empty()) {
                broadcast(prev, leaveMsg, sock);
            }
            if (sendJoinMsg && !joinMsg.empty()) {
                broadcast(id, joinMsg, sock);
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
                    std::string out = "(whisper) " + clients[sock].nick + ":" + msg + "\n";
                    send(p.first, out.data(), out.size(), 0);
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
                send(sock, "Left room\n", strlen("Left room\n"), 0);
            }
        }
        else if (cmd == "/help") {
            const char* help_msg = 
                "Available commands:\n"
                "/help - Show this help message\n"
                "/nick <name> - Set your nickname\n"
                "/list - Show list of available rooms\n"
                "/create <room_name> - Create a new room\n"
                "/join <room_id> - Join a room\n"
                "/w <nickname> <message> - Send a whisper to a user\n"
                "/exit - Leave current room\n"
                "/quit - Exit the program\n";
            send(sock, help_msg, strlen(help_msg), 0);
        }
        else if (cmd == "/quit") {
            break;
        }
        else {
            if (!cmd.empty() && cmd[0] == '/') {
                const char* unknown_cmd = "Unknown command. Please try again.\n";
                send(sock, unknown_cmd, strlen(unknown_cmd), 0);
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
    }
    closesocket(sock);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
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
        WSACleanup();
        return 1;
    }

    if (listen(ls, 5) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(ls);
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
        std::thread(handleClient, cs).detach();
    }

    closesocket(ls);
    WSACleanup();
    return 0;
}
