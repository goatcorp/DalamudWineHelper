#define WIN32_LEAN_AND_MEAN 1

#include <iostream>
#include <windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <iomanip>
#include <sstream>
#include <lmcons.h>
#include <vector>

using namespace std;

void append_quoted_argv(const std::wstring& arg, std::wstring& cmdline, bool force_escape = false);

bool disable_debug_privilege() {
	HANDLE hToken = NULL;
	LUID luid_debug{};
	PRIVILEGE_SET required_privileges{};
	TOKEN_PRIVILEGES token_privileges{};
	BOOL res = false;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid_debug)) {
		std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	required_privileges.PrivilegeCount = 1;
	required_privileges.Control = PRIVILEGE_SET_ALL_NECESSARY;

	required_privileges.Privilege[0].Luid = luid_debug;
	required_privileges.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!PrivilegeCheck(hToken, &required_privileges, &res)) {
		std::cerr << "PrivilegeCheck failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	if (!res) {
		// SeDebugPrivilege is disabled; for our purposes this counts as already done
		res = true;
		goto cleanup;
	}

	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = luid_debug;
	token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &token_privileges, 0, NULL, 0)) {
		std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
		res = false;
		goto cleanup;
	}

cleanup:
	if (hToken)
		CloseHandle(hToken);

	return res;
}

HWND find_game_main_window(DWORD game_pid) {
	HWND hwnd = nullptr;
	while ((hwnd = FindWindowExW(nullptr, hwnd, L"FFXIVGAME", nullptr))) {
		DWORD pid;
		GetWindowThreadProcessId(hwnd, &pid);

		if (pid == game_pid)
			break;
	}
	return hwnd;
}

int launch_game(const wchar_t* app, int argc, const wchar_t* const* argv) {
	std::vector<void*> local_free_targets;

	int res = -1;
	DWORD err = 0;
	EXPLICIT_ACCESS explicit_access{};
	PACL new_acl{}, my_acl{};
	SECURITY_DESCRIPTOR new_descriptor{};
	PSECURITY_DESCRIPTOR my_descriptor{};
	STARTUPINFO si{ sizeof si };
	PROCESS_INFORMATION pi{};
	SECURITY_ATTRIBUTES security_attributes{ sizeof security_attributes };
	security_attributes.lpSecurityDescriptor = &new_descriptor;

	std::wstring args;
	append_quoted_argv(app, args, true);
	for (int i = 0; i < argc; i++) {
		args.push_back(L' ');
		append_quoted_argv(argv[i], args);
	}

	std::wstring username;
	{
		DWORD size = UNLEN + 1;
		username.resize(size, L'\0');
		if (!GetUserName(&username[0], &size)) {
			std::cerr << "GetUserName failed: " << GetLastError() << std::endl;
			goto cleanup;
		}
		username.resize(size);
	}

	BuildExplicitAccessWithName(&explicit_access, &username[0], 0x001fffdf, GRANT_ACCESS, 0);

	if (ERROR_SUCCESS != (err = SetEntriesInAcl(1u, &explicit_access, nullptr, &new_acl))) {
		std::cerr << "SetEntriesInAcl failed: " << err << std::endl;
		goto cleanup;
	}
	local_free_targets.push_back(new_acl);

	if (!InitializeSecurityDescriptor(&new_descriptor, 1u)) {
		std::cerr << "InitializeSecurityDescriptor failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	if (!SetSecurityDescriptorDacl(&new_descriptor, true, new_acl, false)) {
		std::cerr << "SetSecurityDescriptorDacl failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	if (!CreateProcess(app, &args[0], &security_attributes, nullptr, false, 0x20, nullptr, nullptr, &si, &pi)) {
		std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
		goto cleanup;
	}

	while (!find_game_main_window(pi.dwProcessId))
		Sleep(10);

	if (ERROR_SUCCESS != (err = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &my_acl, nullptr, &my_descriptor))) {
		std::cerr << "GetSecurityInfo failed: " << err << std::endl;
		goto cleanup;
	}
	local_free_targets.push_back(my_descriptor);

	if (ERROR_SUCCESS != (SetSecurityInfo(pi.hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, my_acl, nullptr))) {
		std::cerr << "SetSecurityInfo failed: " << err << std::endl;
		goto cleanup;
	}

	res = static_cast<int>(pi.dwProcessId);

cleanup:
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	for (auto& local_free_target : local_free_targets)
		LocalFree(local_free_target);

	return res;
}

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) {
		std::wcerr << L"usage example: " << argv[0] << L" path/to/ffxiv_dx11.exe DEV.TestSID=0 ..." << std::endl;
		return -1;
	}

	if (!disable_debug_privilege())
		return -1;

	int pid = launch_game(argv[1], argc - 2, &argv[2]);
	if (pid == -1)
		return -1;

	std::cerr << "Game PID: " << pid << std::endl;
	return pid;
}

// https://docs.microsoft.com/en-us/archive/blogs/twistylittlepassagesallalike/everyone-quotes-command-line-arguments-the-wrong-way
void append_quoted_argv(const std::wstring& arg, std::wstring& cmdline, bool force_escape) {
	//
	// Unless we're told otherwise, don't quote unless we actually
	// need to do so --- hopefully avoid problems if programs won't
	// parse quotes properly
	//

	if (force_escape == false &&
		arg.empty() == false &&
		arg.find_first_of(L" \t\n\v\"") == arg.npos) {
		cmdline.append(arg);
	} else {
		cmdline.push_back(L'"');

		for (auto it = arg.begin(); ; ++it) {
			unsigned backslash_count = 0;

			while (it != arg.end() && *it == L'\\') {
				++it;
				++backslash_count;
			}

			if (it == arg.end()) {

				//
				// Escape all backslashes, but let the terminating
				// double quotation mark we add below be interpreted
				// as a metacharacter.
				//

				cmdline.append(backslash_count * 2, L'\\');
				break;
			} else if (*it == L'"') {

				//
				// Escape all backslashes and the following
				// double quotation mark.
				//

				cmdline.append(backslash_count * 2 + 1, L'\\');
				cmdline.push_back(*it);
			} else {

				//
				// Backslashes aren't special here.
				//

				cmdline.append(backslash_count, L'\\');
				cmdline.push_back(*it);
			}
		}

		cmdline.push_back(L'"');
	}
}
