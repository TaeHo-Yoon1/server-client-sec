#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <signal.h>
#include <atomic>
#include <conio.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

constexpr int SERVER_PORT = 9000;
constexpr int BUFFER_SIZE = 1024;

static std::atomic<bool> running{ true };
static SOCKET client_socket = INVALID_SOCKET;

void log_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << std::endl;
}

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

void signal_handler(int) {
    running = false;
    if (client_socket != INVALID_SOCKET) {

        const char* quit_msg = "/quit\n";
        send(client_socket, quit_msg, strlen(quit_msg), 0);
        closesocket(client_socket);
    }
    exit(0);
}

int main(int argc, char* argv[]) {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_error("WSAStartup failed");
        return 1;
    }

    signal(SIGINT, signal_handler);

    std::string server_ip = "127.0.0.1";
    if (argc > 1) {
        server_ip = argv[1];
    }

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        log_error("Failed to create socket");
        WSACleanup();
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        log_error("Invalid address");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("Connection failed");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    std::thread receive_thread(receive_messages);
    receive_thread.detach();

    std::vector<std::string> commands = {
        "/help", "/nick", "/list", "/create", "/join", "/w", "/exit", "/quit"
    };

    std::string input;
    while (running) {
        input.clear();
        std::cout << "> ";
        char ch;
        while (running && (ch = _getch()) != '\r') { // Enter key
            if (ch == '\b' || ch == 127) { // Backspace
                if (!input.empty()) {
                    input.pop_back();
                    std::cout << "\b \b" << std::flush;
                }
            } else if (ch == '\t') { // Tab key for auto-completion
                if (!input.empty() && input[0] == '/') {
                    std::vector<std::string> matches;
                    for (const auto& cmd : commands) {
                        if (cmd.find(input) == 0) matches.push_back(cmd);
                    }
                    if (matches.size() == 1) {
                        // Complete the command
                        std::string completion = matches[0].substr(input.size());
                        input += completion;
                        std::cout << completion << std::flush;
                    } else if (matches.size() > 1) {
                        std::cout << "\n[Auto-complete] Candidates: ";
                        for (const auto& m : matches) std::cout << m << " ";
                        std::cout << "\n> " << input << std::flush;
                    } else {
                        std::cout << "\n[Auto-complete] No candidates.\n> " << input << std::flush;
                    }
                }
            } else if (isprint(static_cast<unsigned char>(ch))) {
                input += ch;
                std::cout << ch << std::flush;
            }
        }
        std::cout << std::endl;
        if (input.empty()) continue;
        if (input == "/quit") {
            running = false;
            break;
        }
        input += '\n';
        if (send(client_socket, input.c_str(), input.length(), 0) < 0) {
            log_error("Failed to send message");
            break;
        }
    }

    running = false;
    closesocket(client_socket);
    WSACleanup();

    return 0;
}