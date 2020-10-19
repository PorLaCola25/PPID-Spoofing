# PPID-Spoofing

POC of PPID spoofing using NtCreateUserProcess with syscalls to create a suspended process and performing process injection by overwritting ntdll:LdrInitializeThunk with shellcode.
