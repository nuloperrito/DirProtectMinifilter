#include <Windows.h>
#include <fltUser.h>
#include <iostream>
#include <ShlObj.h>

#include "../DirProtectDrv/data.h"

#include "resource.h"

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "fltLib.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

// --- Global Variables ---
HANDLE g_hPort = INVALID_HANDLE_VALUE;
HWND   g_hMainDialog = NULL;
HANDLE g_hCommThread = NULL;
BOOL   g_bProtectionActive = FALSE;

// --- Forward Declarations ---
const WCHAR* ReasonToString(ASK_REASON reason);
HRESULT InitialCommunicationPort(void);
DWORD WINAPI CommunicationThreadProc(LPVOID lpParam);
INT_PTR CALLBACK AlertDlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK MainDlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
void LogMessage(const WCHAR* format, ...);
int BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData);


// --- Entry Point ---
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR pCmdLine, int nCmdShow)
{
	// Main application window
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, MainDlgProc);
	return 0;
}

// --- Logging Function ---
void LogMessage(const WCHAR* format, ...)
{
	if (!g_hMainDialog) return;

	WCHAR buffer[1024];
	va_list args;
	va_start(args, format);
	vswprintf_s(buffer, sizeof(buffer) / sizeof(WCHAR), format, args);
	va_end(args);

	// Append timestamp
	SYSTEMTIME st;
	GetLocalTime(&st);
	WCHAR finalMessage[1200];
	wsprintf(finalMessage, L"[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, buffer);

	HWND hLog = GetDlgItem(g_hMainDialog, IDC_EDIT_LOG);
	int len = GetWindowTextLength(hLog);
	SendMessage(hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
	SendMessage(hLog, EM_REPLACESEL, 0, (LPARAM)finalMessage);
}


// --- Main Dialog Procedure ---
INT_PTR CALLBACK MainDlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	g_hMainDialog = hwnd;

	switch (message)
	{
	case WM_INITDIALOG:
	{
		// Centralize the dialog in the screen view
		RECT rc;
		GetWindowRect(hwnd, &rc);

		int windowWidth = rc.right - rc.left;
		int windowHeight = rc.bottom - rc.top;

		int screenWidth = GetSystemMetrics(SM_CXSCREEN);
		int screenHeight = GetSystemMetrics(SM_CYSCREEN);

		int newX = (screenWidth - windowWidth) / 2;
		int newY = (screenHeight - windowHeight) / 2;

		SetWindowPos(hwnd, NULL, newX, newY, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
		LogMessage(L"Application started. Please add directories to protect.");
		return TRUE;
	}

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_BTN_ADD:
		{
			WCHAR szDir[MAX_PATH] = { 0 };
			BROWSEINFO bi = { 0 };
			bi.hwndOwner = hwnd;
			bi.lpszTitle = L"Select a folder to protect";
			bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
			bi.lpfn = BrowseCallbackProc;
			bi.lParam = (LPARAM)L"C:\\";

			LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
			if (pidl != NULL)
			{
				if (SHGetPathFromIDList(pidl, szDir))
				{
					SendDlgItemMessage(hwnd, IDC_LIST_DIRS, LB_ADDSTRING, 0, (LPARAM)szDir);
				}
				CoTaskMemFree(pidl);
			}
			return TRUE;
		}

		case IDC_BTN_REMOVE:
		{
			int sel = (int)SendDlgItemMessage(hwnd, IDC_LIST_DIRS, LB_GETCURSEL, 0, 0);
			if (sel != LB_ERR)
			{
				SendDlgItemMessage(hwnd, IDC_LIST_DIRS, LB_DELETESTRING, sel, 0);
			}
			return TRUE;
		}

		case IDC_BTN_START_STOP:
		{
			if (g_bProtectionActive)
			{
				// --- Stop Protection ---
				LogMessage(L"Stopping protection...");
				g_bProtectionActive = FALSE;
				if (g_hCommThread != NULL)
				{
					// Wait for the communication thread to finish
					WaitForSingleObject(g_hCommThread, INFINITE);
					CloseHandle(g_hCommThread);
					g_hCommThread = NULL;
				}
				if (g_hPort != INVALID_HANDLE_VALUE)
				{
					CloseHandle(g_hPort);
					g_hPort = INVALID_HANDLE_VALUE;
				}

				SetDlgItemText(hwnd, IDC_BTN_START_STOP, L"Start Protection");
				EnableWindow(GetDlgItem(hwnd, IDC_BTN_ADD), TRUE);
				EnableWindow(GetDlgItem(hwnd, IDC_BTN_REMOVE), TRUE);
				EnableWindow(GetDlgItem(hwnd, IDC_LIST_DIRS), TRUE);
				LogMessage(L"Protection stopped.");
			}
			else
			{
				// --- Start Protection ---
				int count = (int)SendDlgItemMessage(hwnd, IDC_LIST_DIRS, LB_GETCOUNT, 0, 0);
				if (count == 0)
				{
					MessageBox(hwnd, L"Please add at least one directory to protect.", L"Error", MB_ICONWARNING);
					return TRUE;
				}

				if (FAILED(InitialCommunicationPort()))
				{
					LogMessage(L"Error: Could not connect to the filter driver. Is it running?");
					MessageBox(hwnd, L"Failed to connect to the filter driver.\nPlease ensure the driver is loaded.", L"Connection Error", MB_ICONERROR);
					return TRUE;
				}
				LogMessage(L"Successfully connected to the filter driver.");

				bool allDirsSent = true;
				for (int i = 0; i < count; i++)
				{
					WCHAR dir_dos[MAX_PATH];
					SendDlgItemMessage(hwnd, IDC_LIST_DIRS, LB_GETTEXT, i, (LPARAM)dir_dos);

					COMMAND_MESSAGE_DIR sendMessage;
					memset(&sendMessage, 0, sizeof(COMMAND_MESSAGE_DIR));
					if (wcslen(dir_dos) > DIR_LENGTH - 1)
					{
						LogMessage(L"Error: Path is too long: %s", dir_dos);
						allDirsSent = false;
						break;
					}

					WCHAR driver[] = L"X:";
					driver[0] = dir_dos[0];
					DWORD retquery = QueryDosDeviceW(driver, sendMessage.protectdir_nt, DIR_LENGTH - 1);
					if (retquery > 0)
					{
						if (wcslen(dir_dos) > 2)
						{
							wcsncat_s(sendMessage.protectdir_nt, DIR_LENGTH - 1, dir_dos + 2, _TRUNCATE);
						}

						sendMessage.command_head.command_type = ENUM_DIRINFO;
						wcsncpy_s(sendMessage.protectdir_dos, DIR_LENGTH - 1, dir_dos, _TRUNCATE);
						
						ULONG send_ret = 0;
						DWORD returned = 0;
						if (S_OK != FilterSendMessage(g_hPort, &sendMessage, sizeof(COMMAND_MESSAGE_DIR), &send_ret, sizeof(send_ret), &returned))
						{
							LogMessage(L"Error sending path to driver: %s", dir_dos);
							allDirsSent = false;
							break;
						}
						LogMessage(L"Sent to protect: %s", dir_dos);
					}
					else
					{
						LogMessage(L"Error converting path: %s", dir_dos);
						allDirsSent = false;
						break;
					}
				}

				if (allDirsSent)
				{
					COMMAND_START_PROTECT startMessage;
					startMessage.command_head.command_type = ENUM_START_PROTECT;
					ULONG send_ret = 0;
					DWORD returned = 0;
					if (S_OK == FilterSendMessage(g_hPort, &startMessage, sizeof(COMMAND_START_PROTECT), &send_ret, sizeof(send_ret), &returned))
					{
						LogMessage(L"Protection started successfully!");
						g_bProtectionActive = TRUE;
						g_hCommThread = CreateThread(NULL, 0, CommunicationThreadProc, NULL, 0, NULL);
						
						SetDlgItemText(hwnd, IDC_BTN_START_STOP, L"Stop Protection");
						EnableWindow(GetDlgItem(hwnd, IDC_BTN_ADD), FALSE);
						EnableWindow(GetDlgItem(hwnd, IDC_BTN_REMOVE), FALSE);
						EnableWindow(GetDlgItem(hwnd, IDC_LIST_DIRS), FALSE);
					}
					else
					{
						LogMessage(L"Error: Failed to send start protection command.");
						CloseHandle(g_hPort);
						g_hPort = INVALID_HANDLE_VALUE;
					}
				}
				else
				{
					LogMessage(L"Failed to start protection due to errors.");
					CloseHandle(g_hPort);
					g_hPort = INVALID_HANDLE_VALUE;
				}
			}
			return TRUE;
		}
		}
		break;
	}

	case WM_CLOSE:
	{
		if (g_bProtectionActive)
		{
			// Perform cleanup as if "Stop" was clicked
			SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(IDC_BTN_START_STOP, BN_CLICKED), 0);
		}
		EndDialog(hwnd, 0);
		return TRUE;
	}
	}
	return FALSE;
}

// Helper for SHBrowseForFolder to set initial directory
int CALLBACK BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
{
	if (uMsg == BFFM_INITIALIZED)
	{
		// Set the initial folder.
		SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
	}
	return 0;
}

// --- Alert Dialog Procedure (Popup) ---
INT_PTR CALLBACK AlertDlgProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static ULONG max_wait_second = 60;
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SYS_2_USER* sys_2_user = (SYS_2_USER*)lParam;
		SetDlgItemInt(hwnd, IDC_EDIT_PID, sys_2_user->pid, FALSE);
		SetDlgItemTextW(hwnd, IDC_EDIT_PROCESSNAME, sys_2_user->processname);
		SetDlgItemTextW(hwnd, IDC_EDIT_OPERATION, ReasonToString(sys_2_user->ask_reason));
		SetDlgItemTextW(hwnd, IDC_EDIT_FILENAME, sys_2_user->filename);
		
		max_wait_second = 60;
		WCHAR info[100] = { 0 };
		wsprintf(info, L"Will reject by default if %d seconds countdown exceeds.", max_wait_second);
		SetDlgItemTextW(hwnd, IDC_EDIT_SHOW_SECOND, info);

		SetTimer(hwnd, 1, 1000, NULL);
		return TRUE;
	}
	case WM_TIMER:
	{
		--max_wait_second;
		if (0 == max_wait_second)
		{
			EndDialog(hwnd, 0); // Deny by default
		}
		else
		{
			WCHAR info[100] = { 0 };
			wsprintf(info, L"Will reject by default if %d seconds countdown exceeds.", max_wait_second);
			SetDlgItemTextW(hwnd, IDC_EDIT_SHOW_SECOND, info);
		}
		return TRUE;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDOK:
			EndDialog(hwnd, 1); // Allow
			break;
		case IDCANCEL:
			EndDialog(hwnd, 0); // Deny
			break;
		}
		return TRUE;
	}
	}
	return FALSE;
}

// --- Driver Communication ---
HRESULT InitialCommunicationPort(void)
{
	return FilterConnectCommunicationPort(NPMINI_PORT_NAME, 0, NULL, 0, NULL, &g_hPort);
}

const WCHAR* ReasonToString(ASK_REASON reason)
{
	switch (reason)
	{
	case REASON_DELETE_FILE: return L"Delete File";
	case REASON_DELETE_DIR:  return L"Delete Directory";
	case REASON_SET_DELETE_FLAG: return L"Delete File (Set Flag)";
	case REASON_CREATE_FILE: return L"Create File";
	case REASON_CREATE_DIR:  return L"Create Directory"; 
	case REASON_RENAME_OR_MOVE_FILE: return L"Rename/Move File";
	case REASON_RENAME_OR_MOVE_DIR: return L"Rename/Move Directory";
	case REASON_WRITE_FILE:  return L"Write/Modify File";
	default:                 return L"Unknown Action";
	}
}

DWORD WINAPI CommunicationThreadProc(LPVOID lpParam)
{
	size_t len = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SYS_2_USER);
	FILTER_MESSAGE_HEADER* header = (FILTER_MESSAGE_HEADER*)malloc(len);
	if (!header) return 1;

	USER_REPLY* reply = (USER_REPLY*)malloc(sizeof(FILTER_REPLY_HEADER) + sizeof(REPLY_DATA));
	if (!reply)
	{
		free(header);
		return 1;
	}

	OVERLAPPED over = { 0 };
	over.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!over.hEvent)
	{
		free(header);
		free(reply);
		return 1;
	}

	SYS_2_USER* sys_2_user = (SYS_2_USER*)((PCHAR)header + sizeof(FILTER_MESSAGE_HEADER));

	while (g_bProtectionActive)
	{
		memset(header, 0, len);
		HRESULT result = FilterGetMessage(g_hPort, header, (DWORD)len, &over);

		if (result != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			if (result == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
			{
				LogMessage(L"Communication port closed. Thread exiting.");
			}
			else
			{
				LogMessage(L"FilterGetMessage failed with error 0x%X. Thread exiting.", result);
			}
			break;
		}

		// Wait for the message or timeout to check the g_bProtectionActive flag
		DWORD waitResult = WaitForSingleObject(over.hEvent, 500); 

		if (waitResult == WAIT_TIMEOUT)
		{
			continue; // Check g_bProtectionActive and loop again
		}
		if (waitResult != WAIT_OBJECT_0)
		{
			LogMessage(L"WaitForSingleObject failed. Thread exiting.");
			break;
		}

		LogMessage(L"Request received: PID=%d, Process=%s, Action=%s, File=%s",
			sys_2_user->pid,
			sys_2_user->processname,
			ReasonToString(sys_2_user->ask_reason),
			sys_2_user->filename);
		
		// Show the popup dialog
		INT_PTR dlg_ret = DialogBoxParamW(NULL, MAKEINTRESOURCE(IDD_DIALOG1), g_hMainDialog, AlertDlgProc, (LPARAM)sys_2_user);

		reply->reply_data = (1 == dlg_ret) ? REPLY_ALLOW : REPLY_DENY;
		reply->reply_header.Status = 0;
		reply->reply_header.MessageId = header->MessageId;

		if (S_OK != FilterReplyMessage(g_hPort, (PFILTER_REPLY_HEADER)reply, sizeof(FILTER_REPLY_HEADER) + sizeof(REPLY_DATA)))
		{
			LogMessage(L"FilterReplyMessage failed. Thread exiting.");
			break;
		}
		LogMessage(L"Replied with: %s", (reply->reply_data == REPLY_ALLOW) ? L"Allow" : L"Deny");
	}

	free(header);
	free(reply);
	CloseHandle(over.hEvent);
	return 0;
}
