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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <chrono>
#include <regex>
#include <unordered_set>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

constexpr int SERVER_PORT = 9000;
constexpr int BUFFER_SIZE = 1024;

// 안티 디버깅 관련 상수
constexpr DWORD DEBUG_CHECK_INTERVAL = 1000; // 1초
constexpr DWORD MAX_EXECUTION_TIME = 100;    // 100ms

static std::atomic<bool> running{ true };
static SOCKET client_socket = INVALID_SOCKET;

HHOOK g_hKeyboardHook = NULL;
std::atomic<bool> g_blockAbnormalInput{false};

// 알려진 악성 도메인 목록
const std::vector<std::string> malicious_domains = {
    "malicious-site.com",
    "phishing-site.net",
    "scam-site.org",
    "fake-login.com",
    "steal-password.net"
};

// 의심스러운 키워드 목록
const std::vector<std::string> suspicious_keywords = {
    "login",
    "password",
    "account",
    "verify",
    "confirm",
    "secure",
    "bank",
    "paypal",
    "amazon",
    "ebay"
};

bool isValidInputSource(KBDLLHOOKSTRUCT* p) {
    // 예시: 정상 입력만 허용 (추가 검증 로직 필요시 여기에)
    // 예: 스캔코드, 플래그, 타이밍 등 분석 가능
    return true; // 기본은 모두 허용, 필요시 조건 추가
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        if (!isValidInputSource(p) || g_blockAbnormalInput) {
            // 비정상 입력 차단
            return 1;
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void InstallKeyboardHook() {
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
}

void UninstallKeyboardHook() {
    if (g_hKeyboardHook) {
        UnhookWindowsHookEx(g_hKeyboardHook);
        g_hKeyboardHook = NULL;
    }
}

void StartInputBypassDetection() {
    std::thread([]() {
        while (true) {
            // DirectInput 등 비정상 입력 감지
            HMODULE dinput = GetModuleHandle(L"dinput8.dll");
            if (dinput) {
                g_blockAbnormalInput = true;
            } else {
                g_blockAbnormalInput = false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }).detach();
}

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

void KillSuspiciousProcesses() {
    const std::vector<std::wstring> suspicious_keywords = {
        L"keylogger", L"logger", L"spy", L"hook", L"capture", L"sniffer", L"record", L"monitor"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            std::wstring procName = pe.szExeFile;
            std::wstring lowerProcName = procName;
            std::transform(lowerProcName.begin(), lowerProcName.end(), lowerProcName.begin(), ::towlower);

            for (const auto& keyword : suspicious_keywords) {
                if (lowerProcName.find(keyword) != std::wstring::npos) {
                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

void StartSuspiciousProcessMonitor() {
    std::thread([]() {
        while (true) {
            KillSuspiciousProcesses();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }).detach();
}

bool containsSuspiciousKeywords(const std::string& url) {
    std::string lowerUrl = url;
    std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(), ::tolower);
    
    for (const auto& keyword : suspicious_keywords) {
        if (lowerUrl.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool isUrl(const std::string& str) {
    try {
        static const std::regex url_pattern(
            R"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
        );
        return std::regex_search(str, url_pattern);
    } catch (const std::regex_error& e) {
        std::cerr << "Regex error: " << e.what() << std::endl;
        return false;
    }
}

std::string extractDomain(const std::string& url) {
    try {
        static const std::regex domain_pattern(R"(https?:\/\/(?:www\.)?([^\/]+))");
        std::smatch matches;
        if (std::regex_search(url, matches, domain_pattern) && matches.size() > 1) {
            return matches[1].str();
        }
    } catch (const std::regex_error& e) {
        std::cerr << "Regex error: " << e.what() << std::endl;
    }
    return "";
}

bool isMaliciousUrl(const std::string& message) {
    // URL이 아닌 경우 검사하지 않음
    if (!isUrl(message)) {
        return false;
    }

    // 도메인 추출
    std::string domain = extractDomain(message);
    if (domain.empty()) {
        return false;
    }

    // 알려진 악성 도메인 검사
    for (const auto& malicious : malicious_domains) {
        if (domain.find(malicious) != std::string::npos) {
            return true;
        }
    }

    // 의심스러운 키워드 검사
    if (containsSuspiciousKeywords(message)) {
        // 추가 검증이 필요한 경우 여기에 구현
        return true;
    }

    // IP 주소로 된 URL 차단
    if (std::regex_search(domain, std::regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"))) {
        return true;
    }

    return false;
}

// 안티 디버깅 함수들
bool isBeingDebugged() {
    // IsDebuggerPresent API 체크
    if (IsDebuggerPresent()) {
        return true;
    }

    // PEB 디버그 플래그 검사
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) {
        return true;
    }

    // 하드웨어 브레이크포인트 감지
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }

    return false;
}

bool checkDebuggerProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            std::wstring processName = pe32.szExeFile;
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

            // 디버거 프로세스 검사
            if (processName == L"ollydbg.exe" || 
                processName == L"x64dbg.exe" || 
                processName == L"ida.exe" || 
                processName == L"ida64.exe" ||
                processName == L"windbg.exe" ||
                processName == L"immunitydebugger.exe") {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool checkExecutionTime() {
    static LARGE_INTEGER frequency;
    static LARGE_INTEGER start;
    static bool initialized = false;

    if (!initialized) {
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        initialized = true;
        return false;
    }

    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);

    double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / frequency.QuadPart;
    if (elapsed > MAX_EXECUTION_TIME) {
        return true;
    }

    return false;
}

void StartAntiDebugging() {
    std::thread([]() {
        while (true) {
            if (isBeingDebugged() || checkDebuggerProcesses() || checkExecutionTime()) {
                // 디버깅 감지 시 프로그램 종료
                ExitProcess(0);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(DEBUG_CHECK_INTERVAL));
        }
    }).detach();
}

int main(int argc, char* argv[]) {
    // 안티 디버깅 시작
    StartAntiDebugging();
    
    KillSuspiciousProcesses();
    StartSuspiciousProcessMonitor();
    // OpenSSL initialization
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

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

    // SSL context and connection
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_error("SSL_CTX_new failed");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        log_error("SSL_new failed");
        SSL_CTX_free(ctx);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL_connect failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    std::thread receive_thread([&ssl]() {
        char buffer[BUFFER_SIZE];
        while (running) {
            int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
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
    });
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

        // URL 검사
        if (isMaliciousUrl(input)) {
            std::cout << "[WARNING] Suspicious URL detected and blocked." << std::endl;
            std::cout << "Blocked reason: " << std::endl;
            if (containsSuspiciousKeywords(input)) {
                std::cout << "- Contains suspicious keywords" << std::endl;
            }
            if (std::regex_search(extractDomain(input), std::regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"))) {
                std::cout << "- IP address-based URL" << std::endl;
            }
            continue;
        }

        input += '\n';
        if (SSL_write(ssl, input.c_str(), input.length()) <= 0) {
            log_error("Failed to send message");
            break;
        }
    }

    running = false;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(client_socket);
    WSACleanup();
    EVP_cleanup();
    ERR_free_strings();

    InstallKeyboardHook();
    StartInputBypassDetection();

    return 0;
}