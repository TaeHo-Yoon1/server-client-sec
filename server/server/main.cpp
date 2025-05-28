#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <cstring>            // strlen, memset 등 C 문자열 함수
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

constexpr int SERVER_PORT = 9000;  // 서버 리스닝 포트
constexpr int MAX_ROOMS = 10;    // 최대 방 개수
constexpr int MAX_CLIENTS_PER_ROOM = 40;    // 방당 최대 인원

// 클라이언트 정보 구조체
struct Client {
    SOCKET sock;              // 소켓 fd
    std::string nick;      // 닉네임 (빈 문자열이면 미설정)
    int room_id;           // 현재 속한 방 번호 (-1: 없음)

    Client(SOCKET s = INVALID_SOCKET, const std::string& n = "", int r = -1)
        : sock(s), nick(n), room_id(r) {
    }
};

// 방 정보 구조체
struct Room {
    std::string name;      // 방 이름
    std::set<SOCKET> clients; // 방에 속한 클라이언트 소켓 목록
};

// 전역 변수
static std::vector<Room>        rooms;    // 방 목록
static std::map<SOCKET, Client> clients;  // 소켓→클라이언트 정보 매핑
static std::mutex               mtx;      // 동기화용 뮤텍스

// 방(room_id)에 속한 모든 클라이언트에게 msg 전송 (except는 제외)
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

// 클라이언트 소켓을 처리하는 스레드 함수
void handleClient(SOCKET sock) {
    std::cout << "New client thread started: " << sock << std::endl;
    char buf[1024];

    // 1) 접속 직후 닉네임 설정 안내
    const char* prompt = "Enter /nick <name> to set nickname\n";
    send(sock, prompt, strlen(prompt), 0);

    // 2) 명령/메시지 수신 루프
    while (true) {
        int len = recv(sock, buf, sizeof(buf) - 1, 0);
        if (len <= 0) break;        // 연결 종료 또는 오류
        buf[len] = '\0';            // 널 종단

        std::istringstream iss(buf);
        std::string cmd;
        iss >> cmd;

        if (cmd == "/nick") {
            // 닉네임 설정
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
            }
        }
        else if (cmd == "/list") {
            // 방 목록 출력
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
            // 새 방 생성
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
            // 뮤텍스 밖에서 브로드캐스트
            if (prev >= 0 && !leaveMsg.empty()) {
                broadcast(prev, leaveMsg, sock);
            }
            if (sendJoinMsg && !joinMsg.empty()) {
                broadcast(id, joinMsg, sock);
            }
        }
        else if (cmd == "/w") {
            // 귓속말
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
            // 방 나가기
            std::lock_guard<std::mutex> lock(mtx);
            int rid = clients[sock].room_id;
            if (rid >= 0) {
                rooms[rid].clients.erase(sock);
                clients[sock].room_id = -1;
                send(sock, "Left room\n", strlen("Left room\n"), 0);
            }
        }
        else if (cmd == "/quit") {
            // 클라이언트 종료
            break;
        }
        else {
            // 일반 메세지 브로드캐스트
            int rid = clients[sock].room_id;
            if (rid >= 0 && !clients[sock].nick.empty()) {
                std::string out = clients[sock].nick + ": " + buf;
                broadcast(rid, out, sock);
            }
        }
    }

    // 접속 종료 시 자원 정리
    {
        std::lock_guard<std::mutex> lock(mtx);
        int rid = clients[sock].room_id;
        if (rid >= 0) rooms[rid].clients.erase(sock);
        clients.erase(sock);
    }
    closesocket(sock);
}

int main() {
    // Winsock 초기화
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    // 1) 듣기 소켓 생성
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

    // 2) 바인드 & 리슨
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

    // 3) 클라이언트 접속 무한 루프
    while (true) {
        SOCKET cs = accept(ls, nullptr, nullptr);
        if (cs == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;  // 에러 시 재시도
        }

        // 신규 클라이언트 등록
        {
            std::lock_guard<std::mutex> lock(mtx);
            clients.emplace(cs, Client(cs, "", -1));
        }
        // 스레드로 처리 분리
        std::thread(handleClient, cs).detach();
    }

    // 프로그램 종료 시 정리
    closesocket(ls);
    WSACleanup();
    return 0;
}
