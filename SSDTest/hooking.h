////////////////////////////////////////////////////////////////////////////
//
//  zer0m0n 
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
//  File :      hooking.h
//  Abstract :  Hooking header for zer0m0n
//  Revision :  v1.1
//  Author :    Adrien Chevalier, Nicolas Correia, Cyril Moreau
//  Email :     contact.zer0m0n@gmail.com
//  Date :      2016-07-05      
//
/////////////////////////////////////////////////////////////////////////////


#ifndef __HOOKING_H
#define __HOOKING_H

#include <fltkernel.h>
#include <ntimage.h>
#include "hook-info.h"

#pragma intrinsic(__readcr0)
#pragma intrinsic(__writecr0)
#pragma intrinsic(_disable)
#pragma intrinsic(_enable)

#ifdef _M_IX86
	#define SYSTEMSERVICE(_syscall) KeServiceDescriptorTable.ServiceTableBase[_syscall]
#endif

#define ObjectNameInformation	1
#define MAX_SIZE 1024

// from ReactOS code : https://reactos.googlecode.com/svn/trunk/reactos/include/reactos/probe.h
static const LARGE_INTEGER __emptyLargeInteger =  {{0, 0}};

#define ProbeForReadGenericType(Ptr, Type, Default) \
    (((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) || \
      (ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) ? \
        ExRaiseAccessViolation(), Default : \
            *(const volatile Type *)(Ptr))

#define ProbeForReadLargeInteger(Ptr) ProbeForReadGenericType((const LARGE_INTEGER *)(Ptr), LARGE_INTEGER, __emptyLargeInteger)

// log mode
#define LOG_ERROR 0
#define LOG_SUCCESS 1
#define LOG_PARAM 2

#define SEC_IMAGE 0x1000000

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    unsigned long *ServiceTableBase;
    unsigned long *ServiceCounterTableBase;
    unsigned long NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


// SSDT imports
#ifdef _M_IX86
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable; 
#elif defined _M_X64
pServiceDescriptorTableEntry KeServiceDescriptorTable;
#endif

PVOID Ntdll_ImageBase;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      looks for ntdll file and maps in into memory
//  Parameters :
//      None
//  Return value :
//      PVOID : address of the ntdll export directory
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID MapNtdllIntoMemory();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      retrieves syscall number of the function specified in argument by parsing ntdll export directory
//  Parameters :
//      PIMAGE_EXPORT_DIRECTORY pImageExportDirectory : ntdll export directory
//      PUCHAR funcName : function name to look for
//      ULONG offsetSyscall : offset from the function address start to get the corresponding syscall
//  Return value :
//      ULONG : function syscall number
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONG GetSyscallNumber(__in PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
                       __in PUCHAR funcName, 
                       __in ULONG offsetSyscall);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve 12 bytes of free space in order to use that space as trampoline 
//  Parameters :
//      PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//  Return value :
//      PVOID : address of the code cave found
//  Process :
//      Search for 12 successive bytes at 0x00 from the address given in argument and returns the address found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID SearchCodeCave(__in PVOID pStartSearchAddress);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve the Nt* address function given its syscall number in the SSDT
//  Parameters :
//      PULONG KiServiceTable : the SSDT base address
//      ULONG  ServiceId      : a syscall number
//  Return value :
//      ULONGLONG : the address of the function which has the syscall number given in argument
//  Process :
//      Because the addresses contained in the SSDT have the last four bits reserved to store the number of arguments,
//      in order to retrieve only the address, we shift four bits to the right
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
ULONGLONG GetNTAddressFromSSDT(__in PULONG KiServiceTable, 
                               __in ULONG ServiceId);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve index of the Nt* function (given in parameter) in the SSDT
//  Parameters :
//      PULONG KiServiceTable : the SSDT address
//      PVOID FuncAddress     : a Nt* function address
//  Return value :
//      ULONG : the address which stores the Nt* function address (FuncAddress) in the SSDT
//  Process :
//      same as GetNtAddressFromSSDT() but in revert order
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONG GetSSDTEntry(__in PULONG KiServiceTable, 
                   __in PVOID FuncAddress);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Retrieve end address of the .text section of the module given in argument
//  Parameters :
//      PVOID moduleBase : base address of a module
//  Return value :
//      Returns end address of .text section of moduleBase
//  Process :
//      Parse module base PE header to get the number of sections and to retrieve section header address,
//      then parse each section and when we get to the .text section, returns address of the end of the section
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID GetEndOfTextSection(__in PVOID moduleBase);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Retrieve KeServiceDescriptorTable address
//  Parameters :
//      None
//  Return value :
//      ULONGLONG : The service descriptor table address 
//  Process :
//      Since KeServiceDescriptorTable isn't an exported symbol anymore, we have to retrieve it. 
//      When looking at the disassembly version of nt!KiSystemServiceRepeat, we can see interesting instructions :
//          4c8d15c7202300  lea r10, [nt!KeServiceDescriptorTable (addr)]    => it's the address we are looking for (:
//          4c8d1d00212300  lea r11, [nt!KeServiceDescriptorTableShadow (addr)]
//          f7830001000080  test dword ptr[rbx+100h], 80h
//
//      Furthermore, the LSTAR MSR value (at 0xC0000082) is initialized with nt!KiSystemCall64, which is a function 
//      close to nt!KiSystemServiceRepeat. We will begin to search from this address, the opcodes 0x83f7, the ones 
//      after the two lea instructions, once we get here, we can finally retrieve the KeServiceDescriptorTable address 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetKeServiceDescriptorTable64();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description : 
//      Retrieve kernel base address
//  Parameters :
//      None
//  Return value :
//      PVOID : the kernel base address
//  Process :
//      Retrieve the ntoskrnl module and returns its base address
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID GetKernelBase();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      install SSDT hooks
//  Parameters :
//      None
//  Return value :
//      None
//  Process :
//      retrieves SSDT address and hooks SSDT table
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID HookSSDT();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Modify an entry of the SSDT by an adresse of the corresponding hooked function.
//	Parameters :
//		__in ULONG syscall     : syscall number of the function we want to hook
//		__in PVOID hookedFunc  : address of the hooked function
//		__inout PVOID origFunc : address of the function to hook
//      __in PVOID searchAddr  : address of the end of the .text section (only used in x64) 
//      __in PULONG KiServiceTable : SSDT address
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Install_Hook(__in ULONG syscall, 
				  __in PVOID hookedFunc, 
				  __inout PVOID *origFunc,
				  __in PVOID searchAddr,
				  __in PULONG KiServiceTable);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Unsets WP bit of CR0 register (allows writing into SSDT).
//      See http://en.wikipedia.org/wiki/Control_register#CR0
//  Parameters :
//      None
//  Return value :
//      KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL UnsetWP( );

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID SetWP(KIRQL Irql);


#endif
