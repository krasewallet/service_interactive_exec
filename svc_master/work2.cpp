#include <windows.h>
#include <tchar.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <string>

#pragma comment(lib, "wtsapi32")
#pragma comment(lib, "userenv")

#ifdef _TCHAR_DEFINED
#define _tstring wstring
#elif
#define _tstring string
#endif

using namespace std;

BOOL EnumProcess(PROCESSENTRY32 &pe32, HANDLE &hProcessSnap)
{
	pe32.dwSize = sizeof(pe32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	return Process32First(hProcessSnap, &pe32);
}

_tstring GetInstanceDictionary()
{
	TCHAR tszModule[MAX_PATH + 1] = { 0 };
	::GetModuleFileName(NULL, tszModule, MAX_PATH);
	_tstring sInstancePath = tszModule;
	_tstring sInstanceDirtory = sInstancePath.substr(0, sInstancePath.find_last_of(L"/\\") + 1); // path with last '\'
	return sInstanceDirtory;
}

DWORD SvcWork()
{
	_tstring curPath = GetInstanceDictionary();
	_tstring command = curPath + L"startup.exe";
	_tstring params = L"";

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
		// WTSQueryUserToken(dwSessionId, &hUserToken);
		// wait explorer.exe
		//_tstring logonExe = L"explorer.exe";
		//HANDLE hProcessLogon = NULL;
		//while (!hProcessLogon) {
		//	PROCESSENTRY32 pe32;
		//	HANDLE hProcessSnap;
		//	BOOL bResult = EnumProcess(pe32, hProcessSnap);
		//	while (bResult)
		//	{
		//		if (_tcscmp(logonExe.c_str(), pe32.szExeFile) == 0) {
		//			hProcessLogon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		//			break;
		//		}
		//		bResult = Process32Next(hProcessSnap, &pe32);
		//	}
		//	CloseHandle(hProcessSnap);
		//}
		////
		//dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
		//if (!::OpenProcessToken(hProcessLogon, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
		//	| TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
		//	| TOKEN_READ | TOKEN_WRITE, &hPToken)) {
		//	dwRet = GetLastError();
		//	break;
		//}
		//if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		//	dwRet = GetLastError();
		//	break;
		//}
		//tp.PrivilegeCount = 1;
		//tp.Privileges[0].Luid = luid;
		//tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		//if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserTokenDup)) {
		//	dwRet = GetLastError();
		//	break;
		//}
		//if (!SetTokenInformation(hUserTokenDup, TokenSessionId, (void*)& dwSessionId, sizeof(DWORD))) {
		//	dwRet = GetLastError();
		//	break;
		//}
		//if (!AdjustTokenPrivileges(hUserTokenDup, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL)) {
		//	dwRet = GetLastError();
		//	break;
		//}

		//PVOID lpEnvironment = NULL;
		//if (CreateEnvironmentBlock(&lpEnvironment, hUserToken, FALSE)) {
		//	dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		//}
		//else {
		//	lpEnvironment = NULL;
		//}
		//
		HKEY hKeyUAC = NULL;
		DWORD dwConsentPromptBehaviorAdmin = 0;
		DWORD dwSize = sizeof(DWORD);
		DWORD dwType = REG_DWORD;
		if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &hKeyUAC)) {	
			RegQueryValueEx(hKeyUAC, L"ConsentPromptBehaviorAdmin", 0, &dwType, (LPBYTE)(&dwConsentPromptBehaviorAdmin), &dwSize);
			DWORD dwValue = 0;
			::RegSetValueEx(hKeyUAC, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (LPBYTE)&dwValue, sizeof(DWORD));
		}
		BOOL bWaitLogon = TRUE;
		while (bWaitLogon) {
			WTS_SESSION_INFO *pSession = NULL;
			DWORD session_id = -1;
			DWORD session_count = 0;
			WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSession, &session_count);
			for (int i = 0; i < session_count; i++)
			{
				session_id = pSession[i].SessionId;

				WTS_CONNECTSTATE_CLASS wts_connect_state = WTSDisconnected;
				WTS_CONNECTSTATE_CLASS* ptr_wts_connect_state = NULL;

				DWORD bytes_returned = 0;
				if (::WTSQuerySessionInformation(
					WTS_CURRENT_SERVER_HANDLE,
					session_id,
					WTSConnectState,
					reinterpret_cast<LPTSTR*>(&ptr_wts_connect_state),
					&bytes_returned))
				{
					wts_connect_state = *ptr_wts_connect_state;
					::WTSFreeMemory(ptr_wts_connect_state);
					if (wts_connect_state != WTSActive) continue;
				}
				else
				{
					//log error
					continue;
				}
				HANDLE hImpersonationToken;

				if (!WTSQueryUserToken(session_id, &hImpersonationToken))
				{
					//log error
					continue;
				}
				DWORD nSize = 0;
				HANDLE *realToken = new HANDLE;
				if (GetTokenInformation(hImpersonationToken, (::TOKEN_INFORMATION_CLASS) TokenLinkedToken, realToken, sizeof(HANDLE), &nSize))
				{
					CloseHandle(hImpersonationToken);
					hImpersonationToken = *realToken;
				}
				else
				{
					//log error
					continue;
				}
				TCHAR* pUserName;
				DWORD user_name_len = 0;

				if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id, WTSUserName, &pUserName, &user_name_len))
				{
					_tstring strUserName = pUserName;
					if (strUserName != L"SYSTEM") {
						//log username contained in pUserName WCHAR string
						DuplicateTokenEx(hImpersonationToken,
							//0,
							//MAXIMUM_ALLOWED,
							TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS | MAXIMUM_ALLOWED,
							NULL,
							SecurityImpersonation,
							TokenPrimary,
							&hUserToken);
						bWaitLogon = FALSE;
						break;
					}
				}
				if (pUserName) WTSFreeMemory(pUserName);
			}
			WTSFreeMemory(pSession);
		}
		//
		PVOID lpEnvironment = NULL;
		if (CreateEnvironmentBlock(&lpEnvironment, hUserToken, FALSE)) {
			dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
		}
		else {
			lpEnvironment = NULL;
		}

		ImpersonateLoggedOnUser(hUserToken);
		//
		LPTSTR szCmdline = _tcsdup(command.c_str());
		LPTSTR szParams = _tcsdup(params.c_str());

		CreateProcessAsUser(hUserToken,
			szCmdline,
			szParams,
			NULL,
			NULL,
			FALSE,
			dwCreationFlags,
			lpEnvironment,
			NULL,
			&si,
			&pi);
		//
		WaitForSingleObject(pi.hProcess, INFINITE);
		//
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		if (hKeyUAC) {
			::RegSetValueEx(hKeyUAC, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (LPBYTE)&dwConsentPromptBehaviorAdmin, sizeof(DWORD));
			RegCloseKey(hKeyUAC);
		}
		
	} while (0);

    CloseHandle(hUserToken);
	CloseHandle(hUserTokenDup);
	CloseHandle(hPToken);
	
	return dwRet;
}