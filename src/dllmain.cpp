#include "dllmain.h"
#include "Hook/HookManager.h"
#include "Utils/FileWatcher.h"
#include "Utils/WinHttp.h"

// BUG-13 FIX: Derive Steam install path from the loaded module itself
// instead of GetCurrentDirectoryA(), which returns the process working
// directory and may not match the Steam installation directory.
bool LoadDiversion()
{
    HMODULE hSelf = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&LoadDiversion), &hSelf);
    if (!hSelf || !GetModuleFileNameA(hSelf, SteamInstallPath, MAX_PATH)) {
        return false;
    }
    // Strip the filename, keeping only the directory.
    char* lastSlash = strrchr(SteamInstallPath, '\\');
    if (lastSlash) *lastSlash = '\0';

    sprintf_s(SteamclientPath, MAX_PATH, "%s\\steamclient64.dll",  SteamInstallPath);
    sprintf_s(DiversionPath,   MAX_PATH, "%s\\bin\\diversion.dll", SteamInstallPath);
    sprintf_s(LuaDir,          MAX_PATH, "%s\\config\\lua",        SteamInstallPath);
    sprintf_s(ConfigPath,      MAX_PATH, "%s\\opensteamtool.toml", SteamInstallPath);
    // ensure bin\ directory exists before copying
    char binDir[MAX_PATH];
    sprintf_s(binDir, MAX_PATH, "%s\\bin", SteamInstallPath);
    CreateDirectoryA(binDir, nullptr);  // no-op if already exists
    if (!CopyFileA(SteamclientPath, DiversionPath, FALSE)) {
        LOG_ERROR("CopyFileA failed: {} -> {} (err={})",
                  SteamclientPath, DiversionPath, GetLastError());
        return false;
    }
    diversion_hModule = LoadLibraryA(DiversionPath);
    if (!diversion_hModule) {
        LOG_ERROR("LoadLibraryA failed: {} (err={})", DiversionPath, GetLastError());
        return false;
    }
    LOG_INFO("Loaded diversion.dll from {}", DiversionPath);
    return true;
}

// Resolve the current Steam build id from steam.exe!GetBootstrapperVersion
// once at startup. ByteSearch uses this string as the preferred-match
// label so it picks the Sigs[] entry built for the running build before
// falling back to try-all order (see Utils/ByteSearch.cpp).
static void DetectSteamBuildId() {
    using GetBootstrapperVersion_t = int64_t (*)();
    HMODULE hSteam = GetModuleHandleA("steam.exe");
    if (!hSteam) {
        LOG_WARN("SteamVersion: steam.exe module not loaded; build id unavailable");
        return;
    }
    auto fn = reinterpret_cast<GetBootstrapperVersion_t>(
        GetProcAddress(hSteam, "GetBootstrapperVersion"));
    if (!fn) {
        LOG_WARN("SteamVersion: steam.exe!GetBootstrapperVersion not exported");
        return;
    }
    g_steamBuildId = std::to_string(fn());
    LOG_INFO("SteamVersion: build id = {}", g_steamBuildId);
}

// BUG-01 FIX: Track the init thread handle so DLL_PROCESS_DETACH can
// wait for it to finish before tearing down hooks.
static HANDLE g_InitThread = nullptr;

// All initialisation that touches the filesystem, calls LoadLibrary, scans
// memory, or installs detours runs here on a worker thread — we MUST NOT do
// any of that from inside DllMain (loader lock).
static DWORD WINAPI InitThread(LPVOID param) {
    if (g_Shutdown.load()) return 0;
    HMODULE selfModule = static_cast<HMODULE>(param);
    Log::Init(selfModule);
    LOG_INFO("OpenSteamTool init thread started");

    if (g_Shutdown.load()) {
        g_HooksInstalled.store(true);
        return 0;
    }

    DetectSteamBuildId();

    if (g_Shutdown.load()) {
        g_HooksInstalled.store(true);
        return 0;
    }

    if (!LoadDiversion()) {
        LOG_ERROR("LoadDiversion failed");
        g_HooksInstalled.store(true); // unblock detach even on failure
        return 1;
    }

    if (g_Shutdown.load()) {
        g_HooksInstalled.store(true);
        return 0;
    }

    Config::Load(ConfigPath);
    Log::InitModules();

    std::vector<std::string> watchDirs = Config::luaPaths;
    watchDirs.push_back(std::string(LuaDir));
    for (const auto& dir : watchDirs)
        LuaConfig::ParseDirectory(dir);

    if (g_Shutdown.load()) {
        g_HooksInstalled.store(true);
        return 0;
    }

    FileWatcher::Start(watchDirs);

    if (g_Shutdown.load()) {
        FileWatcher::Stop();
        g_HooksInstalled.store(true);
        return 0;
    }

    SteamUI::CoreHook();
    if (!g_Shutdown.load())
        SteamClient::CoreHook();
    g_HooksInstalled.store(true);
    LOG_INFO("OpenSteamTool init complete");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        // Hand off all real work to a worker thread to avoid running file I/O,
        // LoadLibrary, and detour transactions under the loader lock.
        g_InitThread = CreateThread(nullptr, 0, InitThread, hModule, 0, nullptr);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        // Shutdown must be visible before any other detach work.  This prevents
        // Steam from sitting on stacked timeout waits while the cursor spins.
        g_Shutdown.store(true);

        // Abort any synchronous WinHTTP request that may be blocked in another
        // thread before waiting on that thread.
        WinHttp::AbortAll();
        FileWatcher::Stop();

        // BUG-01 follow-up: keep the race protection, but poll in small chunks
        // and stop immediately once global shutdown is active.
        if (g_InitThread) {
            if (!g_Shutdown.load()) {
                for (int i = 0; i < 50; ++i) {
                    DWORD wait = WaitForSingleObject(g_InitThread, 100);
                    if (wait != WAIT_TIMEOUT || g_Shutdown.load()) break;
                }
            } else {
                WaitForSingleObject(g_InitThread, 0);
            }
            CloseHandle(g_InitThread);
            g_InitThread = nullptr;
        }
        if (g_HooksInstalled.load()) {
            SteamUI::CoreUnhook();
            SteamClient::CoreUnhook();
        }
    }

    return TRUE;
}
