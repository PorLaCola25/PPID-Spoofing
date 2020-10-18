.code

NtCreateUserProcess10 proc
		mov r10, rcx
		mov eax, 0C8h
		syscall
		ret
NtCreateUserProcess10 endp

ZwOpenProcess10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
ZwOpenProcess10 endp

NtAllocateVirtualMemory10 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory10 endp

ZwWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
ZwWriteVirtualMemory10 endp

ZwProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
ZwProtectVirtualMemory10 endp

ZwClose10 proc
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
ZwClose10 endp

end
