#include <windows.h>
#include <tchar.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <string>

#pragma comment(lib, "wtsapi32")
#pragma comment(lib, "userenv")

#ifdef _TCHAR_DEFINED
#define _tstring wstring
#elif
#define _tstring string
#endif

using namespace std;

DWORD SvcWork()
{
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	_tstring curPath = _tstring(szPath);
	int dirPos = curPath.rfind(L"\\");
	int suffixPos = curPath.rfind(L".");
	_tstring iniPath = curPath.substr(0, dirPos) + curPath.substr(dirPos, suffixPos - dirPos) + L".ini";
	TCHAR command[512];
	GetPrivateProfileString(L"service", L"command", L"", command, 512, iniPath.c_str());

    DWORD dwSessionId = WTSGetActiveConsoleSessionId();
	DWORD dwCreationFlags = NULL;

    HANDLE hUserToken = NULL;
	HANDLE hUserTokenDup = NULL;
	HANDLE hPToken = NULL;

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = TEXT("winsta0\\default");

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	TOKEN_PRIVILEGES tp;
	LUID luid;

	DWORD dwRet = 0;
	do {
		WTSQueryUserToken(dwSessionId, &hUserToken);

		dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
		if (!::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
			| TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
			| TOKEN_READ | TOKEN_WRITE, &hPToken)) {
			dwRet = GetLastError();
			break;
		}
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			dwRet = GetLastError();
			break;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserTokenDup)) {
			dwRet = GetLastError();
			break;
		}
		if (!SetTokenInformation(hUserTokenDup, TokenSessionId, (void*)& dwSessionId, sizeof(DWORD))) {
			dwRet = GetLastError();
			break;
		}
		if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL)) {
			dwRet = GetLastError();
			break;
		}

		PVOID lpEnvironment = NULL;
		if (CreateEnvironmentBlock(&lpEnvironment, hUserToken, FALSE)) {
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else {
			lpEnvironment = NULL;
		}

		LPTSTR szCmdline = _tcsdup(command);

		CreateProcessAsUser(hUserTokenDup,
			NULL,
			szCmdline,
			NULL,
			NULL,
			FALSE,
			dwCreationFlags,
			lpEnvironment,
			NULL,
			&si,
			&pi);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	} while (0);

    CloseHandle(hUserToken);
	CloseHandle(hUserTokenDup);
	CloseHandle(hPToken);
	
	return dwRet;
}