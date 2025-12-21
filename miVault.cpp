#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <commdlg.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <cctype>
#include <cstring>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")

static const uint32_t MPEE_MAGIC = 0x4D504545u;
static const size_t FILENAME_SIZE = 256;

struct Footer {
    uint64_t payload_size;
    char filename[FILENAME_SIZE];
    uint32_t magic;
};

static const std::string HARDCODED_KEY = "supersecretkey1337";

static const std::unordered_set<std::string> SUPPORTED_EXTS = {
    ".mp3", ".wav", ".m4a", ".aac", ".wma", ".flac", ".ogg", ".opus",
    ".mp4", ".avi", ".wmv", ".mkv", ".mov", ".m4v", ".3gp", ".m4p", ".webm",
    ".jpg", ".jpeg", ".png", ".bmp", ".gif"
};

bool has_supported_extension(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });
    return SUPPORTED_EXTS.count(ext);
}

void xor_buffer(std::vector<uint8_t>& data, const std::string& key) {
    size_t klen = key.size();
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= static_cast<uint8_t>(key[i % klen]);
    }
}

bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto pos = f.tellg();
    if (pos < 0) return false;
    std::streamsize size = static_cast<std::streamsize>(pos);
    if (size > 2e9) return false;
    out.resize(static_cast<size_t>(size));
    f.seekg(0, std::ios::beg);
    if (!out.empty()) f.read(reinterpret_cast<char*>(out.data()), out.size());
    return f.good();
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

std::string get_filename_no_path(const std::string& path) {
    size_t slash1 = path.find_last_of('/');
    size_t slash2 = path.find_last_of('\\');
    size_t start = (slash1 != std::string::npos ? slash1 : 0);
    start = (slash2 > start ? slash2 : start) + 1;
    return path.substr(start);
}

std::string get_file_size_str(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return "0 B";
    auto size = f.tellg();
    if (size < 1024) return std::to_string(size) + " B";
    if (size < 1024 * 1024) return std::to_string(size / 1024) + " KB";
    if (size < 1024LL * 1024 * 1024) return std::to_string(size / (1024 * 1024)) + " MB";
    return std::to_string(size / (1024LL * 1024 * 1024)) + " GB";
}

std::string get_extension(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return "";
    return path.substr(dot);
}

std::string get_directory(const std::string& path) {
    size_t slash1 = path.find_last_of('/');
    size_t slash2 = path.find_last_of('\\');
    size_t last_slash = max(slash1, slash2);
    if (last_slash == std::string::npos) return "";
    return path.substr(0, last_slash + 1);
}

std::string get_filename_no_ext(const std::string& path) {
    std::string fname = get_filename_no_path(path);
    size_t dot = fname.find_last_of('.');
    if (dot == std::string::npos) return fname;
    return fname.substr(0, dot);
}

bool embed_file(const std::string& cover_file, const std::string& input_file, const std::string& output_file) {
    if (!has_supported_extension(cover_file)) return false;

    std::vector<uint8_t> cover, payload;
    if (!read_file(cover_file, cover)) return false;
    if (!read_file(input_file, payload)) return false;
    if (payload.empty()) return false;

    std::string orig_filename = get_filename_no_path(input_file);
    if (orig_filename.size() >= FILENAME_SIZE) {
        orig_filename.resize(FILENAME_SIZE - 1);
    }

    xor_buffer(payload, HARDCODED_KEY);

    Footer footer;
    std::memset(&footer, 0, sizeof(footer));
    footer.payload_size = payload.size();
    std::strncpy(footer.filename, orig_filename.c_str(), FILENAME_SIZE - 1);
    footer.magic = MPEE_MAGIC;

    std::ofstream out(output_file, std::ios::binary);
    if (!out) return false;

    if (!cover.empty()) {
        out.write(reinterpret_cast<const char*>(cover.data()), cover.size());
    }

    out.write(reinterpret_cast<const char*>(payload.data()), payload.size());
    out.write(reinterpret_cast<const char*>(&footer), sizeof(footer));

    return out.good();
}

bool extract_file(const std::string& stego_file, const std::string& output_dir = ".\\") {
    std::ifstream in(stego_file, std::ios::binary | std::ios::ate);
    if (!in) return false;

    std::streamoff file_size = static_cast<std::streamoff>(in.tellg());
    if (file_size < static_cast<std::streamoff>(sizeof(Footer))) return false;

    std::streamoff footer_pos = file_size - static_cast<std::streamoff>(sizeof(Footer));
    in.seekg(footer_pos, std::ios::beg);

    Footer footer;
    in.read(reinterpret_cast<char*>(&footer), sizeof(footer));

    if (footer.magic != MPEE_MAGIC) return false;
    if (footer.payload_size == 0 || footer.payload_size > 1e8) return false;

    std::streamoff payload_pos = footer_pos - static_cast<std::streamoff>(footer.payload_size);
    if (payload_pos < 0) return false;

    in.seekg(payload_pos, std::ios::beg);
    std::vector<uint8_t> payload(static_cast<size_t>(footer.payload_size));
    in.read(reinterpret_cast<char*>(payload.data()), payload.size());

    if (!in.good()) return false;

    xor_buffer(payload, HARDCODED_KEY);

    std::string orig_filename = footer.filename;
    if (orig_filename.empty()) orig_filename = "recovered.bin";

    std::string output_path = output_dir;
    if (!output_dir.empty() && output_dir.back() != '/' && output_dir.back() != '\\') {
        output_path += "\\";
    }
    output_path += orig_filename;

    return write_file(output_path, payload);
}

HWND hMainWindow, hLogEdit;
HWND hCoverLabel, hCoverEdit, hCoverBtn;
HWND hPayloadLabel, hPayloadEdit, hPayloadBtn;
HWND hOutputLabel, hOutputEdit, hOutputBtn;
HWND hStegoLabel, hStegoEdit, hStegoBtn;
HWND hDirLabel, hDirEdit, hDirBtn;
HWND hEmbedBtn, hExtractBtn, hClearBtn1, hClearBtn2;
int currentTab = 0;

std::string browse_file(HWND parent) {
    OPENFILENAMEA ofn = { 0 };
    char szFile[MAX_PATH] = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parent;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) return std::string(szFile);
    return "";
}

std::string save_file(HWND parent) {
    OPENFILENAMEA ofn = { 0 };
    char szFile[MAX_PATH] = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parent;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameA(&ofn)) return std::string(szFile);
    return "";
}

std::string browse_folder(HWND parent) {
    BROWSEINFOA bi = { 0 };
    char path[MAX_PATH];
    bi.hwndOwner = parent;
    bi.lpszTitle = "Select Output Folder";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl != 0) {
        SHGetPathFromIDListA(pidl, path);
        CoTaskMemFree(pidl);
        return std::string(path);
    }
    return "";
}

void log_msg(const std::string& msg) {
    int len = GetWindowTextLengthA(hLogEdit);
    SetFocus(hLogEdit);
    SendMessageA(hLogEdit, EM_SETSEL, len, len);
    SendMessageA(hLogEdit, EM_REPLACESEL, 0, (LPARAM)(msg + "\r\n").c_str());
}

void show_tab(int tab) {
    currentTab = tab;

    if (tab == 0) {
        // EMBED TAB
        ShowWindow(hCoverLabel, SW_SHOW);
        ShowWindow(hCoverEdit, SW_SHOW);
        ShowWindow(hCoverBtn, SW_SHOW);
        ShowWindow(hPayloadLabel, SW_SHOW);
        ShowWindow(hPayloadEdit, SW_SHOW);
        ShowWindow(hPayloadBtn, SW_SHOW);
        ShowWindow(hOutputLabel, SW_SHOW);
        ShowWindow(hOutputEdit, SW_SHOW);
        ShowWindow(hOutputBtn, SW_SHOW);
        ShowWindow(hEmbedBtn, SW_SHOW);
        ShowWindow(hClearBtn1, SW_SHOW);

        ShowWindow(hStegoLabel, SW_HIDE);
        ShowWindow(hStegoEdit, SW_HIDE);
        ShowWindow(hStegoBtn, SW_HIDE);
        ShowWindow(hDirLabel, SW_HIDE);
        ShowWindow(hDirEdit, SW_HIDE);
        ShowWindow(hDirBtn, SW_HIDE);
        ShowWindow(hExtractBtn, SW_HIDE);
        ShowWindow(hClearBtn2, SW_HIDE);
    }
    else {
        // EXTRACT TAB
        ShowWindow(hCoverLabel, SW_HIDE);
        ShowWindow(hCoverEdit, SW_HIDE);
        ShowWindow(hCoverBtn, SW_HIDE);
        ShowWindow(hPayloadLabel, SW_HIDE);
        ShowWindow(hPayloadEdit, SW_HIDE);
        ShowWindow(hPayloadBtn, SW_HIDE);
        ShowWindow(hOutputLabel, SW_HIDE);
        ShowWindow(hOutputEdit, SW_HIDE);
        ShowWindow(hOutputBtn, SW_HIDE);
        ShowWindow(hEmbedBtn, SW_HIDE);
        ShowWindow(hClearBtn1, SW_HIDE);

        ShowWindow(hStegoLabel, SW_SHOW);
        ShowWindow(hStegoEdit, SW_SHOW);
        ShowWindow(hStegoBtn, SW_SHOW);
        ShowWindow(hDirLabel, SW_SHOW);
        ShowWindow(hDirEdit, SW_SHOW);
        ShowWindow(hDirBtn, SW_SHOW);
        ShowWindow(hExtractBtn, SW_SHOW);
        ShowWindow(hClearBtn2, SW_SHOW);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // TAB BUTTONS
        CreateWindowA("BUTTON", "VAULT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 10, 190, 35, hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
        CreateWindowA("BUTTON", "EXTRACT", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            210, 10, 190, 35, hwnd, (HMENU)2, GetModuleHandle(NULL), NULL);

        int y = 60;

        // COVER
        hCoverLabel = CreateWindowA("STATIC", "Input Media File:", WS_CHILD | WS_VISIBLE,
            10, y, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        y += 22;
        hCoverEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY,
            10, y, 310, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hCoverBtn = CreateWindowA("BUTTON", "Browse", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            325, y, 90, 25, hwnd, (HMENU)10, GetModuleHandle(NULL), NULL);

        y += 45;
        // PAYLOAD
        hPayloadLabel = CreateWindowA("STATIC", "File To Embed:", WS_CHILD | WS_VISIBLE,
            10, y, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        y += 22;
        hPayloadEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY,
            10, y, 310, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hPayloadBtn = CreateWindowA("BUTTON", "Browse", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            325, y, 90, 25, hwnd, (HMENU)11, GetModuleHandle(NULL), NULL);

        y += 45;
        // OUTPUT FILE
        hOutputLabel = CreateWindowA("STATIC", "Output File:", WS_CHILD | WS_VISIBLE,
            10, y, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        y += 22;
        hOutputEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER,
            10, y, 310, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hOutputBtn = CreateWindowA("BUTTON", "Browse", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            325, y, 90, 25, hwnd, (HMENU)12, GetModuleHandle(NULL), NULL);

        y += 50;
        // BUTTONS
        hEmbedBtn = CreateWindowA("BUTTON", "EMBED FILE", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, y, 200, 40, hwnd, (HMENU)20, GetModuleHandle(NULL), NULL);
        hClearBtn1 = CreateWindowA("BUTTON", "CLEAR", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            215, y, 200, 40, hwnd, (HMENU)21, GetModuleHandle(NULL), NULL);

        // EXTRACT TAB
        y = 60;
        hStegoLabel = CreateWindowA("STATIC", "Target File:", WS_CHILD,
            10, y, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        y += 22;
        hStegoEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_BORDER | ES_READONLY,
            10, y, 310, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hStegoBtn = CreateWindowA("BUTTON", "Browse", WS_CHILD | BS_PUSHBUTTON,
            325, y, 90, 25, hwnd, (HMENU)30, GetModuleHandle(NULL), NULL);

        y += 45;
        hDirLabel = CreateWindowA("STATIC", "Output Directory:", WS_CHILD,
            10, y, 120, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
        y += 22;
        hDirEdit = CreateWindowA("EDIT", ".\\", WS_CHILD | WS_BORDER,
            10, y, 310, 25, hwnd, NULL, GetModuleHandle(NULL), NULL);
        hDirBtn = CreateWindowA("BUTTON", "Browse", WS_CHILD | BS_PUSHBUTTON,
            325, y, 90, 25, hwnd, (HMENU)31, GetModuleHandle(NULL), NULL);

        y += 50;
        hExtractBtn = CreateWindowA("BUTTON", "EXTRACT FILE", WS_CHILD | BS_PUSHBUTTON,
            10, y, 200, 40, hwnd, (HMENU)40, GetModuleHandle(NULL), NULL);
        hClearBtn2 = CreateWindowA("BUTTON", "CLEAR", WS_CHILD | BS_PUSHBUTTON,
            215, y, 200, 40, hwnd, (HMENU)41, GetModuleHandle(NULL), NULL);

 
        y = 317;
        hLogEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            10, y, 415, 140, hwnd, NULL, GetModuleHandle(NULL), NULL);

        show_tab(0);
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);

        if (id == 1) {
            show_tab(0);
            log_msg("[*] EMBED mode");
        }
        else if (id == 2) {
            show_tab(1);
            log_msg("[*] EXTRACT mode");
        }
        else if (id == 10) {
            std::string f = browse_file(hwnd);
            if (!f.empty()) {
                SetWindowTextA(hCoverEdit, f.c_str());
                log_msg("[+] Cover: " + get_filename_no_path(f));

                // Auto-generate output path with same extension
                std::string dir = get_directory(f);
                std::string name_no_ext = get_filename_no_ext(f);
                std::string ext = get_extension(f);
                std::string output_path = dir + name_no_ext + "_vault" + ext;

                SetWindowTextA(hOutputEdit, output_path.c_str());
                log_msg("[+] Output: " + get_filename_no_path(output_path));
            }
        }
        else if (id == 11) {
            std::string f = browse_file(hwnd);
            if (!f.empty()) {
                SetWindowTextA(hPayloadEdit, f.c_str());
                log_msg("[+] Payload: " + get_filename_no_path(f));
            }
        }
        else if (id == 12) {
            std::string f = save_file(hwnd);
            if (!f.empty()) {
                SetWindowTextA(hOutputEdit, f.c_str());
                log_msg("[+] Output: " + get_filename_no_path(f));
            }
        }
        else if (id == 20) {
            char cover[MAX_PATH], payload[MAX_PATH], output[MAX_PATH];
            GetWindowTextA(hCoverEdit, cover, MAX_PATH);
            GetWindowTextA(hPayloadEdit, payload, MAX_PATH);
            GetWindowTextA(hOutputEdit, output, MAX_PATH);

            if (strlen(cover) == 0 || strlen(payload) == 0 || strlen(output) == 0) {
                MessageBoxA(hwnd, "Select all files!", "Error", MB_ICONERROR);
            }
            else {
                log_msg("[*] Embedding...");
                if (embed_file(cover, payload, output)) {
                    log_msg("[+] SUCCESS!");
                    MessageBoxA(hwnd, "Done!", "Success", MB_ICONINFORMATION);
                }
                else {
                    log_msg("[-] FAILED!");
                    MessageBoxA(hwnd, "Failed!", "Error", MB_ICONERROR);
                }
            }
        }
        else if (id == 21) {
            SetWindowTextA(hCoverEdit, "");
            SetWindowTextA(hPayloadEdit, "");
            SetWindowTextA(hOutputEdit, "");
        }
        else if (id == 30) {
            std::string f = browse_file(hwnd);
            if (!f.empty()) {
                SetWindowTextA(hStegoEdit, f.c_str());
                log_msg("[+] Stego: " + get_filename_no_path(f));
            }
        }
        else if (id == 31) {
            std::string d = browse_folder(hwnd);
            if (!d.empty()) {
                SetWindowTextA(hDirEdit, d.c_str());
            }
        }
        else if (id == 40) {
            char stego[MAX_PATH], dir[MAX_PATH];
            GetWindowTextA(hStegoEdit, stego, MAX_PATH);
            GetWindowTextA(hDirEdit, dir, MAX_PATH);

            if (strlen(stego) == 0) {
                MessageBoxA(hwnd, "Select stego file!", "Error", MB_ICONERROR);
            }
            else {
                log_msg("[*] Extracting...");
                if (extract_file(stego, strlen(dir) > 0 ? dir : ".\\")) {
                    log_msg("[+] SUCCESS!");
                    MessageBoxA(hwnd, "Done!", "Success", MB_ICONINFORMATION);
                }
                else {
                    log_msg("[-] FAILED!");
                    MessageBoxA(hwnd, "Failed!", "Error", MB_ICONERROR);
                }
            }
        }
        else if (id == 41) {
            SetWindowTextA(hStegoEdit, "");
            SetWindowTextA(hDirEdit, ".\\");
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "miVaultGUI";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassA(&wc);

    hMainWindow = CreateWindowA(
        "miVaultGUI", "miVault",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        100, 100, 450, 500,
        NULL, NULL, hInstance, NULL
    );

    if (!hMainWindow) return 1;

    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);
    log_msg("[+] Ready");

    MSG msg = { 0 };
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
