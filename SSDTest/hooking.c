////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n 
//
//  Copyright 2016 Adrien Chevalier, Nicolas Correia, Cyril Moreau
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		hooking.c
//	Abstract :	Hooking function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "hooking.h"
#include "main.h"
#include "hook_reg.h"
#include "hook_process.h"
#include "hook_file.h"
#include "hook_misc.h"
#include "struct.h"

PVOID MapNtdllIntoMemory()
{
	NTSTATUS status;
	HANDLE hSection;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING pathFile;
	USHORT NumberOfSections;
	SECTION_IMAGE_INFORMATION sii = {0};
	PVOID pSection = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader64 = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	DWORD dwExportRVA, dwExportSize;

	RtlInitUnicodeString(&pathFile, L"\\KnownDlls\\ntdll.dll");
	InitializeObjectAttributes(&objAttr, &pathFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	if(NT_SUCCESS(status = ZwOpenSection(&hSection, SECTION_MAP_READ, &objAttr)))
	{
		ZwQuerySection(hSection, 1, &sii, sizeof(sii), 0);
		Dbg("ntdll entry point : %llx\n", sii.EntryPoint);
		Ntdll_ImageBase = sii.EntryPoint;
		pDosHeader = (PIMAGE_DOS_HEADER)Ntdll_ImageBase;
		
		#ifdef _M_X64
		pNtHeader64 = (PIMAGE_NT_HEADERS64)((unsigned char*)Ntdll_ImageBase+pDosHeader->e_lfanew); 
		pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader64+sizeof(IMAGE_NT_HEADERS64)); 
		dwExportRVA  = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		dwExportSize = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		#endif
		
		pNtHeader = (PIMAGE_NT_HEADERS)((unsigned char*)Ntdll_ImageBase+pDosHeader->e_lfanew); 
		pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS)); 
		dwExportRVA  = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		dwExportSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					
		Dbg("Export table address : 0x%08x\n", dwExportRVA);
		Dbg("Export table size : 0x%08x\n", dwExportSize);
		Dbg("EAT : 0x%08X\n", (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)Ntdll_ImageBase+dwExportRVA));
		pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)Ntdll_ImageBase+dwExportRVA);
		Dbg("number of exported functions : 0x%08x\n", pImageExportDirectory->NumberOfFunctions);
	}
	ZwClose(hSection);
	return pImageExportDirectory;
}

ULONG GetSyscallNumber(__in PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, 
					   __in PUCHAR funcName, 
					   __in ULONG offsetSyscall)
{
	PULONG addrName = NULL, addrFunc = NULL;
	PWORD addrOrdinal = NULL;
	ULONG i = 0;
	PCHAR name = NULL;
	SIZE_T n;
	
	if(pImageExportDirectory && funcName)
	{
		addrName = (PULONG)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfNames);
		addrFunc = (PULONG)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfFunctions);
		addrOrdinal = (PWORD)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfNameOrdinals);
		
		for(i=0; i < pImageExportDirectory->NumberOfNames; ++i)
		{
			name = ((unsigned char*)Ntdll_ImageBase + addrName[i]);
			__try
			{
				ProbeForRead(name, 0, 1);
				RtlStringCchLengthA(funcName, NTSTRSAFE_MAX_CCH, &n);
				if(RtlEqualMemory(funcName, name, n))
				{
					Dbg("[+] FOUND : %s\n", name);
					Dbg("addr : 0x%08x\n", ((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]));
					Dbg("syscall : %x\n", *(PULONG)((PUCHAR)((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]+offsetSyscall)));
					return *(PULONG)((PUCHAR)((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]+offsetSyscall));
					
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				Dbg("Exception : %x\n", GetExceptionCode());
			}
		}
	}
	return 0;
}

ULONG GetSSDTEntry(__in PULONG KiServiceTable, 
				   __in PVOID FuncAddress)
{
	return ((ULONG)((ULONGLONG)FuncAddress-(ULONGLONG)KiServiceTable)) << 4;
}

PVOID SearchCodeCave(__in PUCHAR pStartSearchAddress)
{	
	while(pStartSearchAddress++)
	{		
		if(MmIsAddressValid(pStartSearchAddress))
		{
			if(*(PULONG)pStartSearchAddress == 0x00000000 && *(PULONG)(pStartSearchAddress+4) == 0x00000000 && *(PULONG)(pStartSearchAddress+8) == 0x00000000)
				return pStartSearchAddress;	
		}
	}
	return 0;
}
 
ULONGLONG GetNTAddressFromSSDT(__in PULONG KiServiceTable, 
							   __in ULONG ServiceId )
{
	return (LONGLONG)( KiServiceTable[ServiceId] >> 4 ) 
		+ (ULONGLONG)KiServiceTable;
}

PVOID GetEndOfTextSection(__in PVOID moduleBase)
{
	USHORT NumberOfSections;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ULONG i;
	PVOID begin_text, end_text;
	end_text = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	pNtHeader = (PIMAGE_NT_HEADERS64)((unsigned char*)moduleBase+pDosHeader->e_lfanew);

	NumberOfSections = pNtHeader->FileHeader.NumberOfSections;
	Dbg("Number of Sections: %d\n", NumberOfSections);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS64));
	Dbg("section header : %llx \n", pSectionHeader);

	// parse each section in order to get to the executable section 
	for(i=0; i<NumberOfSections; i++)
	{
		// this is the .text section
		//modified by simpower91 由于SSDT加密后偏移地址不能为负数，因此searchAddr必须要在SSDT之后
		//然而SSDT却在.rdata区段，SSDT所指向的入口有的在PAGE区段，理论上放在.rdata之后的可X区段都可以，PAGE属于可交换分页，位于PAGELK之后。
		//if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)&&(strcmp(pSectionHeader->Name,"PAGELK")==0))
		{
			begin_text = (PVOID)(pSectionHeader->VirtualAddress + (ULONG_PTR)moduleBase);
			end_text = (PVOID)((ULONG_PTR)begin_text + pSectionHeader->Misc.VirtualSize);
			Dbg("%s section is located at : %llx \n", pSectionHeader->Name, begin_text);
			Dbg("end of %s section at : %llx \n", pSectionHeader->Name, end_text);
			break;
		}
		pSectionHeader++;
	}
	return end_text;
}
 
PVOID GetKernelBase()
{
	UNICODE_STRING funcAddr;
	ULONG ulNeededSize = 0, ModuleCount;
	PVOID pBuffer;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	PSYSTEM_MODULE pSystemModule = NULL;
	PVOID imgBaseAddr;

	ZwQuerySystemInformation(SystemModuleInformation, &ulNeededSize, 0, &ulNeededSize);
	if(ulNeededSize)
	{
		pBuffer = PoolAlloc(ulNeededSize);
		if(NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeededSize, &ulNeededSize)))
		{
			pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
			pSystemModule = &pSystemModuleInformation->Modules[0]; //ntoskrnl.exe模块
			imgBaseAddr = pSystemModule->Base; //内核基址
			return imgBaseAddr;
		}
	}
	return 0;
}

ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR      pStartSearchAddress   = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR      pEndSearchAddress     = (PUCHAR)( ((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF) );
	PULONG      pFindCodeAddress      = NULL;
	ULONG_PTR   pKeServiceDescriptorTable;

	while ( ++pStartSearchAddress < pEndSearchAddress )
	{
		//if ((*(PULONG)pStartSearchAddress & 0xFFFFFF00) == 0x83f70000)
		if ((*(PULONG)pStartSearchAddress & 0x00FFFFFF) == 0x158d4c)
		{
			//pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
			pFindCodeAddress = (PULONG)(pStartSearchAddress + 3);
			//return (ULONG_PTR)pFindCodeAddress + (((*(PULONG)pFindCodeAddress) >> 24) + 7) + (ULONG_PTR)(((*(PULONG)(pFindCodeAddress + 1)) & 0x0FFFF) << 8);
			return ((ULONG_PTR)pFindCodeAddress-3 + 7) + ((LONG)(*(PULONG)pFindCodeAddress));
		}
	}
	return 0;
}

VOID HookSSDT()
{
	PDWORD func = NULL;
	PULONG KiServiceTable = NULL;
	PVOID kernelBase = NULL;
	PVOID pStartSearchAddress = NULL;
	DWORD offsetSyscall = 1;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

#ifdef _M_X64
	KeServiceDescriptorTable = (pServiceDescriptorTableEntry)GetKeServiceDescriptorTable64();
	Dbg("KeServiceDescriptorTable : %llx\n", KeServiceDescriptorTable);
	KiServiceTable = KeServiceDescriptorTable->ServiceTableBase;
	Dbg("KiServiceTable : %llx\n", KiServiceTable);
	kernelBase = GetKernelBase();
	Dbg("Kernel base addr : %llx\n", kernelBase);
	pStartSearchAddress = GetEndOfTextSection(kernelBase);
	Dbg("pStartSearchAddress : %llx\n", pStartSearchAddress);
	offsetSyscall = 4;
#endif

	pImageExportDirectory = MapNtdllIntoMemory();
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwWriteFile", offsetSyscall), (PVOID)Hooked_NtWriteFile, (PVOID*)&Orig_NtWriteFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateFile", offsetSyscall), (PVOID)Hooked_NtCreateFile, (PVOID*)&Orig_NtCreateFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwReadFile", offsetSyscall), (PVOID)Hooked_NtReadFile, (PVOID*)&Orig_NtReadFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeleteFile", offsetSyscall), (PVOID)Hooked_NtDeleteFile, (PVOID*)&Orig_NtDeleteFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwOpenFile", offsetSyscall), (PVOID)Hooked_NtOpenFile, (PVOID*)&Orig_NtOpenFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwClose", offsetSyscall), (PVOID)Hooked_NtClose, (PVOID*)&Orig_NtClose, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeviceIoControlFile", offsetSyscall), (PVOID)Hooked_NtDeviceIoControlFile, (PVOID*)&Orig_NtDeviceIoControlFile, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQueryAttributesFile", offsetSyscall), (PVOID)Hooked_NtQueryAttributesFile, (PVOID*)&Orig_NtQueryAttributesFile, pStartSearchAddress, KiServiceTable);
	//the up is ok
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQueryValueKey", offsetSyscall), (PVOID)Hooked_NtQueryValueKey, (PVOID*)&Orig_NtQueryValueKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwOpenKey", offsetSyscall), (PVOID)Hooked_NtOpenKey, (PVOID*)&Orig_NtOpenKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwOpenKeyEx", offsetSyscall), (PVOID)Hooked_NtOpenKeyEx, (PVOID*)&Orig_NtOpenKeyEx, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateKey", offsetSyscall), (PVOID)Hooked_NtCreateKey, (PVOID*)&Orig_NtCreateKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeleteKey", offsetSyscall), (PVOID)Hooked_NtDeleteKey, (PVOID*)&Orig_NtDeleteKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeleteValueKey", offsetSyscall), (PVOID)Hooked_NtDeleteValueKey, (PVOID*)&Orig_NtDeleteValueKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSetValueKey", offsetSyscall), (PVOID)Hooked_NtSetValueKey, (PVOID*)&Orig_NtSetValueKey, pStartSearchAddress, KiServiceTable);
	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwTerminateProcess", offsetSyscall), (PVOID)Hooked_NtTerminateProcess, (PVOID*)&Orig_NtTerminateProcess, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateProcess", offsetSyscall), (PVOID)Hooked_NtCreateProcess, (PVOID*)&Orig_NtCreateProcess, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateProcessEx", offsetSyscall), (PVOID)Hooked_NtCreateProcessEx, (PVOID*)&Orig_NtCreateProcessEx, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateUserProcess", offsetSyscall), (PVOID)Hooked_NtCreateUserProcess, (PVOID*)&Orig_NtCreateUserProcess, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwWriteVirtualMemory", offsetSyscall), (PVOID)Hooked_NtWriteVirtualMemory, (PVOID*)&Orig_NtWriteVirtualMemory, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwReadVirtualMemory", offsetSyscall), (PVOID)Hooked_NtReadVirtualMemory, (PVOID*)&Orig_NtReadVirtualMemory, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwMapViewOfSection", offsetSyscall), (PVOID)Hooked_NtMapViewOfSection, (PVOID*)&Orig_NtMapViewOfSection, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwOpenProcess", offsetSyscall), (PVOID)Hooked_NtOpenProcess, (PVOID*)&Orig_NtOpenProcess, pStartSearchAddress, KiServiceTable);
	return;
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwResumeThread", offsetSyscall), (PVOID)Hooked_NtResumeThread, (PVOID*)&Orig_NtResumeThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSetContextThread", offsetSyscall), (PVOID)Hooked_NtSetContextThread, (PVOID*)&Orig_NtSetContextThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateThread", offsetSyscall), (PVOID)Hooked_NtCreateThread, (PVOID*)&Orig_NtCreateThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateThreadEx", offsetSyscall), (PVOID)Hooked_NtCreateThreadEx, (PVOID*)&Orig_NtCreateThreadEx, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateSection", offsetSyscall), (PVOID)Hooked_NtCreateSection, (PVOID*)&Orig_NtCreateSection, pStartSearchAddress, KiServiceTable);//
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSystemDebugControl", offsetSyscall), (PVOID)Hooked_NtSystemDebugControl, (PVOID*)&Orig_NtSystemDebugControl, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQueueApcThread", offsetSyscall), (PVOID)Hooked_NtQueueApcThread, (PVOID*)&Orig_NtQueueApcThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwOpenThread", offsetSyscall), (PVOID)Hooked_NtOpenThread, (PVOID*)&Orig_NtOpenThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQuerySystemInformation", offsetSyscall), (PVOID)Hooked_NtQuerySystemInformation, (PVOID*)&Orig_NtQuerySystemInformation, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDebugActiveProcess", offsetSyscall), (PVOID)Hooked_NtDebugActiveProcess, (PVOID*)&Orig_NtDebugActiveProcess, pStartSearchAddress, KiServiceTable);

	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateMutant", offsetSyscall), (PVOID)Hooked_NtCreateMutant, (PVOID*)&Orig_NtCreateMutant, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDelayExecution", offsetSyscall), (PVOID)Hooked_NtDelayExecution, (PVOID*)&Orig_NtDelayExecution, pStartSearchAddress, KiServiceTable);
	return; //问题函数
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSetInformationFile", offsetSyscall), (PVOID)Hooked_NtSetInformationFile, (PVOID*)&Orig_NtSetInformationFile, pStartSearchAddress, KiServiceTable);

}

VOID Install_Hook(__in ULONG syscall, 
				  __in PVOID hookedFunc, 
				  __inout PVOID *origFunc, 
				  __in PVOID searchAddr, 
				  __in PULONG KiServiceTable)
{	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UCHAR jmp_to_newFunction[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xE0"; //mov rax, xxx ; jmp rax
	KIRQL Irql;
	ULONG SsdtEntry;
	PVOID trampoline = NULL;
	PMDL mdl = NULL;
	PVOID memAddr = NULL;
	KIRQL irql;

	if(syscall > 0)
	{
		irql = UnsetWP();

		#ifdef _M_IX86
		*origFunc = (PVOID)SYSTEMSERVICE(syscall);
		(PVOID)SYSTEMSERVICE(syscall) = hookedFunc;
		
		#elif defined _M_X64
		Dbg("OS : 64 bits !\n");
		*origFunc = (PVOID)GetNTAddressFromSSDT(KiServiceTable, syscall); 
		Dbg("Orig_Func : %llx\n", *origFunc);
		Dbg("Hooked_Func : %llx\n", hookedFunc);
		// mov rax, @NewFunc; jmp rax
		*(PULONGLONG)(jmp_to_newFunction+2) = (ULONGLONG)hookedFunc;

		trampoline = SearchCodeCave(searchAddr);
		Dbg("trampoline : %llx\n", trampoline);

		mdl = IoAllocateMdl(trampoline, 12, FALSE, FALSE, NULL);
		MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess); 
		memAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

		RtlMoveMemory(memAddr, jmp_to_newFunction, 12); 

		SsdtEntry = GetSSDTEntry(KiServiceTable, trampoline);
		SsdtEntry &= 0xFFFFFFF0;
		SsdtEntry += KiServiceTable[syscall] & 0x0F;		
		KiServiceTable[syscall] = SsdtEntry;   
		#endif
		
		SetWP(irql);

	}
}

KIRQL UnsetWP( )
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();

	cr0 &= ~0x10000;
	__writecr0( cr0 );
	_disable();

	return Irql;
}

VOID SetWP(KIRQL Irql)
{
	UINT_PTR cr0 = __readcr0();

	cr0 |= 0x10000;
	_enable();  
	__writecr0( cr0 );

	KeLowerIrql( Irql );
}
