#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

constexpr int SERVER_PORT = 9000;
constexpr int BUFFER_SIZE = 1024;

// 전역 변수
static std::atomic<bool> running{ true };
static SOCKET client_socket = INVALID_SOCKET;

// 유틸리티 함수: 에러 로그
void log_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
}

// 서버로부터 메시지를 받는 스레드 함수
void receive_messages() {
    char buffer[BUFFER_SIZE];

    while (running) {
        int len = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

        if (len <= 0) {
            if (running) {
                log_error("Server disconnected");
                running = false;
            }
            break;
        }

        buffer[len] = '\0';
        std::cout << buffer << std::flush;
    }
}

// SIGINT (Ctrl+C) 핸들러
void signal_handler(int) {
    running = false;
    if (client_socket != INVALID_SOCKET) {
        // 종료 메시지 전송
        const char* quit_msg = "/quit\n";
        send(client_socket, quit_msg, strlen(quit_msg), 0);
        closesocket(client_socket);
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    // Winsock 초기화
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_error("WSAStartup failed");
        return 1;
    }

    // SIGINT 핸들러 등록
    signal(SIGINT, signal_handler);

    // 서버 주소 (기본값: localhost)
    std::string server_ip = "127.0.0.1";
    if (argc > 1) {
        server_ip = argv[1];
    }

    // 소켓 생성
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        log_error("Failed to create socket");
        WSACleanup();
        return 1;
    }

    // 서버 주소 설정
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        log_error("Invalid address");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // 서버 연결
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // 수신 스레드 시작
    std::thread receive_thread(receive_messages);
    receive_thread.detach();

    // 사용자 입력 처리
    std::string input;
    while (running && std::getline(std::cin, input)) {
        if (input.empty()) continue;

        // /quit 명령어 처리
        if (input == "/quit") {
            running = false;
            break;
        }

        // 입력 문자열 끝에 개행 추가
        input += '\n';

        // 메시지 전송
        if (send(client_socket, input.c_str(), input.length(), 0) < 0) {
            log_error("Failed to send message");
            break;
        }
    }

    // 종료
    running = false;
    closesocket(client_socket);
    WSACleanup();

    return 0;
}