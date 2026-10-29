/* chain-probe.c: three-arm AMSI probe with the dev provider registered.
 * Reads the raw payload bytes INLINE so there is no file-scan path.
 * Scans each buffer through AmsiScanBuffer and prints the aggregator result.
 * No Add-Type, no managed compile, no CLR AMSI gate.
 *
 * Build (host):
 *   x86_64-w64-mingw32-gcc -O2 chain-probe.c -o chain-probe.exe \
 *     -ladvapi32 -lole32 -luuid
 * Expectation on current Defender with AmsiDevProvider registered:
 *   ctrl_start (EICAR)           result=32768 or 32769 (both reach malware)
 *   A_mimikatz_alone             result>=32768 (MpOav or sibling)
 *   B_marker_alone               result=32769 (only sibling fires)
 *   C_mimi_plus_marker           result>=32768
 *   ctrl_end (EICAR)             result=32768 or 32769
 */

#include <windows.h>
#include <stdio.h>

typedef HRESULT (WINAPI *AmsiInitializeFn)(LPCWSTR, void**);
typedef HRESULT (WINAPI *AmsiScanBufferFn)(void*, void*, ULONG, LPCWSTR, void*, int*);
typedef HRESULT (WINAPI *AmsiUninitializeFn)(void*);

static AmsiInitializeFn   p_init;
static AmsiScanBufferFn   p_scan;
static AmsiUninitializeFn p_uninit;

static void scan(const char *label, const unsigned char *bytes, size_t n) {
    void *ctx = NULL;
    WCHAR appname[64];
    _snwprintf(appname, 64, L"ch-%hs", label);
    HRESULT hr = p_init(appname, &ctx);
    int r = 0;
    if (SUCCEEDED(hr) && ctx) {
        WCHAR cn[64]; _snwprintf(cn, 64, L"%hs", label);
        p_scan(ctx, (void*)bytes, (ULONG)n, cn, NULL, &r);
        p_uninit(ctx);
    }
    printf("%-24s result=%d\n", label, r);
}

int main(void) {
    HMODULE h = LoadLibraryW(L"amsi.dll");
    if (!h) { printf("amsi.dll load failed: 0x%08lx\n", GetLastError()); return 1; }
    p_init   = (AmsiInitializeFn)   GetProcAddress(h, "AmsiInitialize");
    p_scan   = (AmsiScanBufferFn)   GetProcAddress(h, "AmsiScanBuffer");
    p_uninit = (AmsiUninitializeFn) GetProcAddress(h, "AmsiUninitialize");
    if (!p_init || !p_scan || !p_uninit) { printf("export resolve failed\n"); return 2; }

    static const unsigned char marker[] = {
        65,77,83,73,45,83,73,76,69,78,84,45,65,76,76,79,87,45,77,65,82,75,69,82,45,55,98,99,50,101,49,51,97
    };
    static const unsigned char mimikatz[] = {
        102,117,110,99,116,105,111,110,32,73,110,118,111,107,101,45,77,105,109,105,107,97,116,122,32,123,32,34,
        115,101,107,117,114,108,115,97,58,58,108,111,103,111,110,112,97,115,115,119,111,114,100,115,34,32,125
    };
    static const unsigned char eicar[] = {
        88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,
        69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42
    };
    unsigned char mix[sizeof mimikatz + 1 + sizeof marker];
    memcpy(mix, mimikatz, sizeof mimikatz);
    mix[sizeof mimikatz] = '\n';
    memcpy(mix + sizeof mimikatz + 1, marker, sizeof marker);

    puts("=== oracle ctrl_start (EICAR) ===");
    scan("ctrl_start", eicar, sizeof eicar);
    puts("=== arm A: Mimikatz-known content ALONE ===");
    scan("A_mimikatz_alone", mimikatz, sizeof mimikatz);
    puts("=== arm B: marker ALONE ===");
    scan("B_marker_alone", marker, sizeof marker);
    puts("=== arm C: Mimikatz + marker, same buffer ===");
    scan("C_mimi_plus_marker", mix, sizeof mix);
    puts("=== oracle ctrl_end (EICAR) ===");
    scan("ctrl_end", eicar, sizeof eicar);

    return 0;
}
