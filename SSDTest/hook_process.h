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
//	File :		hook_process.h
//	Abstract :	Hook process header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __HOOK_PROCESS_H
#define __HOOK_PROCESS_H

#define INVALID_HANDLE_VALUE -1

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(*NTTERMINATEPROCESS)(HANDLE, NTSTATUS);
typedef NTSTATUS(*NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*NTCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS(*NTCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
typedef NTSTATUS(*NTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(*NTOPENPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*NTRESUMETHREAD)(HANDLE, PULONG);
typedef NTSTATUS(*NTSETCONTEXTHREAD)(HANDLE, PCONTEXT);
typedef NTSTATUS(*NTCREATETHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
typedef NTSTATUS(*NTCREATETHREADEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, BOOLEAN, ULONG, ULONG, ULONG, PVOID);
typedef NTSTATUS(*NTCREATESECTION)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(*NTSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTQUEUEAPCTHREAD)(HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG);
typedef NTSTATUS(*NTOPENTHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTDEBUGACTIVEPROCESS)(HANDLE, HANDLE);

NTTERMINATEPROCESS Orig_NtTerminateProcess;
NTCREATEPROCESS Orig_NtCreateProcess;
NTCREATEPROCESSEX Orig_NtCreateProcessEx;
NTCREATEUSERPROCESS Orig_NtCreateUserProcess;
NTWRITEVIRTUALMEMORY Orig_NtWriteVirtualMemory;
NTREADVIRTUALMEMORY Orig_NtReadVirtualMemory;
NTMAPVIEWOFSECTION Orig_NtMapViewOfSection;
NTOPENPROCESS Orig_NtOpenProcess;
NTRESUMETHREAD Orig_NtResumeThread;
NTSETCONTEXTHREAD Orig_NtSetContextThread;
NTCREATETHREAD Orig_NtCreateThread;
NTCREATETHREADEX Orig_NtCreateThreadEx;
NTSYSTEMDEBUGCONTROL Orig_NtSystemDebugControl;
NTQUEUEAPCTHREAD Orig_NtQueueApcThread;
NTCREATESECTION Orig_NtCreateSection;
NTOPENTHREAD Orig_NtOpenThread;
NTQUERYSYSTEMINFORMATION Orig_NtQuerySystemInformation;
NTDEBUGACTIVEPROCESS Orig_NtDebugActiveProcess;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging operations (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Process :
//		Pass the call and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtSystemDebugControl(__in SYSDBG_COMMAND Command,
									 __in_opt PVOID InputBuffer,
									 __in ULONG InputBufferLength,
									 __out_opt PVOID OutputBuffer,
									 __in ULONG OutputBufferLength,
									 __out_opt PULONG ReturnLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs section object creation.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//	Process :
//		logs SectionHandle, DesiredAccess, SectionPageProtection, FileHandle, ObjectHandle and SectionName
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateSection(__out PHANDLE SectionHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in_opt PLARGE_INTEGER MaximumSize,
								__in ULONG SectionPageProtection,
								__in ULONG AllocationAttributes,
								__in_opt HANDLE FileHandle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging (may be used for code injection).
//	Parameters :
//		See http://www.openrce.org/articles/full_view/26
//	Return value :
//		See http://www.openrce.org/articles/full_view/26
//	Process :
//		Adds the process to the monitored processes list and logs the ProcessHandle and DebugHandle parameters
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDebugActiveProcess(__in HANDLE ProcessHandle,
									 __in HANDLE DebugHandle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Hides specific processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//	Process :
//		Checks the information type. If SystemProcessInformation (enumerate running processes), the
//		hidden targetProcessIds are unlinked from the result (SYSTEM_PROCESS_INFORMATION linked list).
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQuerySystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
										 __inout PVOID SystemInformation,
										 __in ULONG SystemInformationLength,
										 __out_opt PULONG ReturnLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread opening and hides threads which belong to the processes to hide
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Process :
//		logs thread handle, desired access and the process id which the thread belongs
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtOpenThread(__out PHANDLE ThreadHandle,
							 __in ACCESS_MASK DesiredAccess,
							 __in POBJECT_ATTRIBUTES ObjectAttributes,
							 __in PCLIENT_ID ClientId);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread-based Asynchronous Procedure Call creation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Process :
//		Proceed the call then gets the thread owner and adds it to the monitored processes list, then
//		log.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueueApcThread(__in HANDLE ThreadHandle,
								 __in PIO_APC_ROUTINE Apcroutine,
								 __in_opt PVOID ApcRoutineContext,
								 __in_opt PIO_STATUS_BLOCK ApcStatusBlock,
								 __in_opt ULONG ApcReserved);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Process :
//		Gets the thread's owner, proceeds the call then adds immediately the targetProcessId to the monitored
//		processes list if it succeeded. Then logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateThread(__out PHANDLE ThreadHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in POBJECT_ATTRIBUTES ObjectAttributes,
							   __in HANDLE ProcessHandle,
							   __out PCLIENT_ID ClientId,
							   __in PCONTEXT ThreadContext,
							   __in PINITIAL_TEB InitialTeb,
							   __in BOOLEAN CreateSuspended);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread creation.
//	Parameters :
//		See http://securityxploded.com/ntcreatethreadex.php (lulz)
//	Return value :
//		See http://securityxploded.com/ntcreatethreadex.php (lulz)
//	Process :
//		Gets the thread's owner, proceeds the call then adds immediately the targetProcessId to the monitored
//		processes list if it succeeded. Then logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateThreadEx(__out PHANDLE ThreadHandle,
								 __in ACCESS_MASK DesiredAccess,
								 __in POBJECT_ATTRIBUTES ObjectAttributes,
								 __in HANDLE ProcessHandle,
								 __in PVOID lpStartAddress,
								 __in PVOID lpParameter,
								 __in BOOLEAN CreateSuspended,
								 __in ULONG StackZeroBits,
								 __in ULONG SizeOfStackCommit,
								 __in ULONG SizeOfStackReserve,
								 __out PVOID lpBytesBuffer);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread context manipulation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Process :
//		Pass the call, adds the process (thread owner) to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtSetContextThread(__in HANDLE ThreadHandle,
								   __in PCONTEXT Context);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs resume thread
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//	Process :
//		logs thread handle and SuspendCount
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtResumeThread(__in HANDLE ThreadHandle,
							   __out_opt PULONG SuspendCount);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process opening (mandatory for most of code injection techniques), and hides specific processes
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//	Process :
//		Calls the original function and if it succeeds, gets the targetProcessId by handle. If the targetProcessId is hidden
//		closes the handle and returns STATUS_INVALID_PARAMETER.
////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtOpenProcess(__out PHANDLE ProcessHandle,
							  __in ACCESS_MASK DesiredAccess,
							  __in POBJECT_ATTRIBUTES ObjectAttributes,
							  __in_opt PCLIENT_ID ClientId);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs section mapping (may be used for code injection).
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Process :
//		Pass the call, adds the targeted process to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtMapViewOfSection(__in HANDLE SectionHandle,
								   __in HANDLE ProcessHandle,
								   __inout PVOID *BaseAddress,
								   __in ULONG_PTR ZeroBits,
								   __in SIZE_T CommitSize,
								   __inout_opt PLARGE_INTEGER SectionOffset,
								   __inout PSIZE_T ViewSize,
								   __in SECTION_INHERIT InheritDisposition,
								   __in ULONG AllocationType,
								   __in ULONG Win32Protect);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory modification.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Process :
//		Adds the process to the monitored processes list and logs the ProcessHandle, BaseAddress and Buffer parameters.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtWriteVirtualMemory(__in HANDLE ProcessHandle,
									 __in PVOID BaseAddress,
									 __in PVOID Buffer,
									 __in ULONG NumberOfBytesToWrite,
									 __out_opt PULONG NumberOfBytesWritten);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory read.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//	Process :
//		logs the ProcessHandle, BaseAddress and Buffer parameters.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtReadVirtualMemory(__in HANDLE ProcessHandle,
									__in PVOID BaseAddress,
									__out PVOID Buffer,
									__in ULONG NumberOfBytesToRead,
									__out_opt PULONG NumberOfBytesReaded);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs process termination.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//	Process :
//		logs process handle and exit status	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtTerminateProcess( __in_opt HANDLE ProcessHandle, 
									__in NTSTATUS ExitStatus);
									
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Process :
//		Starts the process, gets its targetProcessId and adds it to the monitored processes list, logs
//		the new process handle, desired access, inherit object table and its filepath
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateProcess(__out PHANDLE ProcessHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in HANDLE ParentProcess,
								__in BOOLEAN InheritObjectTable,
								__in_opt HANDLE SectionHandle,
								__in_opt HANDLE DebugPort,
								__in_opt HANDLE ExceptionPort);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See https://doxygen.reactos.org/d2/d9f/ntoskrnl_2ps_2process_8c_source.html
//	Return value :
//		See https://doxygen.reactos.org/d2/d9f/ntoskrnl_2ps_2process_8c_source.html
//	Process :
//		Starts the process, gets its targetProcessId and adds it to the monitored processes list, logs
//		the new process handle, desired access, the flags and the process filepath
////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateProcessEx(__out PHANDLE ProcessHandle,
								  __in ACCESS_MASK DesiredAccess,
								  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								  __in HANDLE ParentProcess,
								  __in ULONG Flags,
								  __in_opt HANDLE SectionHandle,
								  __in_opt HANDLE DebugPort,
								  __in_opt HANDLE ExceptionPort,
								  __in BOOLEAN InJob);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//	Return value :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateUserProcess(__out PHANDLE ProcessHandle,
									__out PHANDLE ThreadHandle,
									__in ACCESS_MASK ProcessDesiredAccess,
									__in ACCESS_MASK ThreadDesiredAccess,
									__in_opt POBJECT_ATTRIBUTES ProcessObjectAttributes,
									__in_opt POBJECT_ATTRIBUTES ThreadObjectAttributes,
									__in ULONG ProcessFlags,
									__in ULONG ThreadFlags,
									__in_opt PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
									__inout PVOID CreateInfo,
									__in_opt PVOID AttributeList);


#endif