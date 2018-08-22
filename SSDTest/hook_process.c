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
//	File :		hook_process.c
//	Abstract :	Hook process function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "hooking.h"
#include "hook_process.h"
#include "monitor.h"
#include "utils.h"
#include "main.h"
#include "comm.h"

NTSTATUS Hooked_NtDebugActiveProcess(__in HANDLE ProcessHandle,
									 __in HANDLE DebugHandle)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtDebugActiveProcess(ProcessHandle, DebugHandle);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtDebugActiveProcess\n");

		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		targetProcessId = getPIDByHandle(ProcessHandle);
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,ProcessHandle->0x%08x,DebugHandle->0x%08x", ProcessHandle, DebugHandle)))
				log_lvl = LOG_PARAM;
			
			if(targetProcessId)
				StartMonitoringProcess(targetProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,ProcessHandle->0x%08x,DebugHandle->0x%08x", statusCall, ProcessHandle, DebugHandle)))
				log_lvl = LOG_PARAM;
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtDebugActiveProcess, parameter);
			break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtDebugActiveProcess, L"0,-1,ss,ProcessHandle->0,DebugHandle->0");
			break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtDebugActiveProcess, L"1,0,ss,ProcessHandle->0,DebugHandle->0");
			break;
		}

		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}									 
									
NTSTATUS Hooked_NtQuerySystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
										 __inout PVOID SystemInformation,
										 __in ULONG SystemInformationLength,
										 __out_opt PULONG ReturnLength)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL, pPrev = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtQuerySystemInformation\n");
	
		if(NT_SUCCESS(statusCall))
		{
			if(SystemInformationClass == SystemProcessInformation)
			{
				pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
				pPrev = pSystemProcessInformation;
				
				while(pSystemProcessInformation->NextEntryOffset)
				{
					if(IsProcessInList((ULONG)pSystemProcessInformation->ProcessId, pHiddenProcessListHead))
						pPrev->NextEntryOffset += pSystemProcessInformation->NextEntryOffset;
					
					pPrev = pSystemProcessInformation;
					pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
				}
			}
		}
	}
	return statusCall;	
}

NTSTATUS Hooked_NtOpenThread(__out PHANDLE ThreadHandle,
							 __in ACCESS_MASK DesiredAccess,
							 __in POBJECT_ATTRIBUTES ObjectAttributes,
							 __in PCLIENT_ID ClientId)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId;
	ULONG kClientId = 0;
	HANDLE kThreadHandle = (HANDLE)INVALID_HANDLE_VALUE;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtOpenThread\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ThreadHandle)
			{
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
				kThreadHandle = *ThreadHandle;
			}
			if(ClientId)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), 1);
				kClientId = (ULONG)ClientId->UniqueProcess;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ThreadHandle->0,DesiredAccess->0,ProcessIdentifier->0", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, L"0,-1,sss,ThreadHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
				
		if(NT_SUCCESS(statusCall))
		{
			targetProcessId = getPIDByThreadHandle(kThreadHandle);
			
			if(IsProcessInList(targetProcessId, pHiddenProcessListHead))
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,3221225485,sss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", kThreadHandle, DesiredAccess, kClientId))) 
					SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, parameter);
				else
					SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, L"0,3221225485,sss,ThreadHandle->0,DesiredAccess->0,ProcessIdentifier->0");	
				if(parameter)
					PoolFree(parameter);
				*ThreadHandle = (HANDLE)INVALID_HANDLE_VALUE;
				return STATUS_INVALID_PARAMETER;
			}
			
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", kThreadHandle, DesiredAccess, kClientId)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", statusCall, kThreadHandle, DesiredAccess, kClientId)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, L"0,-1,sss,ThreadHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenThread, L"1,0,sss,ThreadHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtQueueApcThread(__in HANDLE ThreadHandle, 
								 __in PIO_APC_ROUTINE ApcRoutine, 
								 __in PVOID ApcRoutineContext, 
								 __in PIO_STATUS_BLOCK ApcStatusBlock, 
								 __in ULONG ApcReserved)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();

	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtQueueApcThread\n");

		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
				
		targetProcessId = getPIDByThreadHandle(ThreadHandle);
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,ThreadHandle->0x%08x,FunctionAddress->0x%08x,Parameter->0x%08x,PID->%d", ThreadHandle, ApcRoutineContext, ApcStatusBlock, targetProcessId)))
				log_lvl = LOG_PARAM;
			
			if(targetProcessId)
				StartMonitoringProcess(targetProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,ThreadHandle->0x%08x,FunctionAddress->0x%08x,Parameter->0x%08x,PID->%d", statusCall, ThreadHandle, ApcRoutineContext, ApcStatusBlock, targetProcessId)))
				log_lvl = LOG_PARAM;
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtQueueApcThread, parameter);
			break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtQueueApcThread, L"0,-1,ssss,ThreadHandle->0,FunctionAddress->0,Parameter->0,PID->0");
			break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtQueueApcThread, L"1,0,ssss,ThreadHandle->0,FunctionAddress->0,Parameter->0,PID->0");
			break;
		}

		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;
}

NTSTATUS Hooked_NtCreateSection(__out PHANDLE SectionHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in_opt PLARGE_INTEGER MaximumSize,
								__in ULONG SectionPageProtection,
								__in ULONG AllocationAttributes,
								__in_opt HANDLE FileHandle)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	UNICODE_STRING kObjectName;
	USHORT log_lvl = LOG_ERROR;
	HANDLE kSectionHandle = (HANDLE)INVALID_HANDLE_VALUE;
	HANDLE kRootDirectory = (HANDLE)INVALID_HANDLE_VALUE;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateSection\n");
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(SectionHandle)
			{			
				ProbeForRead(SectionHandle, sizeof(HANDLE), 1);
				kSectionHandle = *SectionHandle;
			}
			if(ObjectAttributes != NULL)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				kRootDirectory = ObjectAttributes->RootDirectory;
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			else
				RtlInitUnicodeString(&kObjectName, L"");
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssssss,SectionHandle->0,DesiredAccess->0,SectionPageProtection->0,FileHandle->0,ObjectHandle->0,SectionName->NULL", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateSection, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateSection, L"0,-1,ssssss,SectionHandle->0,DesiredAccess->0,SectionPageProtection->0,FileHandle->0,ObjectHandle->0,SectionName->NULL");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}

		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssssss,SectionHandle->0x%08x,DesiredAccess->0x%08x,SectionPageProtection->%d,FileHandle->0x%08x,ObjectHandle->0x%08x,SectionName->%wZ", kSectionHandle, DesiredAccess, SectionPageProtection, FileHandle, kRootDirectory, &kObjectName)))
				log_lvl = LOG_PARAM;	
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssssss,SectionHandle->0x%08x,DesiredAccess->0x%08x,SectionPageProtection->%d,FileHandle->0x%08x,ObjectHandle->0x%08x,SectionName->%wZ", statusCall, kSectionHandle, DesiredAccess, SectionPageProtection, FileHandle, kRootDirectory, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateSection, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateSection, L"0,-1,ssssss,SectionHandle->0,DesiredAccess->0,SectionPageProtection->0,FileHandle->0,ObjectHandle->0,SectionName->NULL");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateSection, L"1,0,ssssss,SectionHandle->0,DesiredAccess->0,SectionPageProtection->0,FileHandle->0,ObjectHandle->0,SectionName->NULL");
			break;
		}
	
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtSystemDebugControl(__in SYSDBG_COMMAND Command,
									 __in_opt PVOID InputBuffer,
									 __in ULONG InputBufferLength,
									 __out_opt PVOID OutputBuffer,
									 __in ULONG OutputBufferLength,
									 __out_opt PULONG ReturnLength)
{
	NTSTATUS statusCall;
	USHORT log_lvl = LOG_ERROR;
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtSystemDebugControl\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
					
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,s,Command->%d", Command)))
				log_lvl = LOG_PARAM;	
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,s,Command->%d", statusCall, Command)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtSystemDebugControl, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtSystemDebugControl, L"0,-1,s,Command->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtSystemDebugControl, L"1,0,s,Command->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtCreateThread(__out PHANDLE ThreadHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in POBJECT_ATTRIBUTES ObjectAttributes,
							   __in HANDLE ProcessHandle,
							   __out PCLIENT_ID ClientId,
							   __in PCONTEXT ThreadContext,
							   __in PINITIAL_TEB InitialTeb,
							   __in BOOLEAN CreateSuspended)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	HANDLE kThreadHandle = (HANDLE)INVALID_HANDLE_VALUE;
	UNICODE_STRING kObjectName;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;

	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateThread\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ThreadHandle)
			{
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
				kThreadHandle = *ThreadHandle;
			}
			
			if(ObjectAttributes != NULL)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			else
				RtlInitUnicodeString(&kObjectName, L"");
			newProcessId = getPIDByHandle(ProcessHandle);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssss,ThreadHandle->0,DesiredAccess->0,ProcessHandle->0,CreateSuspended->0,ThreadName->NULL", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThread, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThread, L"0,-1,sssss,ThreadHandle->0,DesiredAccess->0,ProcessHandle->0,CreateSuspended->0,ThreadName->NULL");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sssss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ProcessHandle->0x%08x,CreateSuspended->%d,ThreadName->%wZ", kThreadHandle, DesiredAccess, ProcessHandle, CreateSuspended, &kObjectName)))
				log_lvl = LOG_PARAM;	
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ProcessHandle->0x%08x,CreateSuspended->%d,ThreadName->%wZ", statusCall, kThreadHandle, DesiredAccess, ProcessHandle, CreateSuspended, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThread, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThread, L"0,-1,sssss,ThreadHandle->0,DesiredAccess->0,ProcessHandle->0,CreateSuspended->0,ThreadName->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThread, L"1,0,sssss,ThreadHandle->0,DesiredAccess->0,ProcessHandle->0,CreateSuspended->0,ThreadName->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

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
								 __out PVOID lpBytesBuffer)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	HANDLE kThreadHandle = (HANDLE)INVALID_HANDLE_VALUE;
	UNICODE_STRING kObjectName;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	kObjectName.Buffer = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateThreadEx\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ThreadHandle)
			{
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
				kThreadHandle = *ThreadHandle;
			}
			if(ObjectAttributes != NULL)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			else
				RtlInitUnicodeString(&kObjectName, L"");
			newProcessId = getPIDByHandle(ProcessHandle);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssssssss,ThreadHandle->0,DesiredAccess->0,ThreadName->NULL,ProcessHandle->0,FunctionAddress->0,Parameter->0,CreateSuspended->0,StackZeroBits->0", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThreadEx, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThreadEx, L"0,-1,ssssssss,ThreadHandle->0,DesiredAccess->0,ThreadName->NULL,ProcessHandle->0,FunctionAddress->0,Parameter->0,CreateSuspended->0,StackZeroBits->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssssssss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ThreadName->%wZ,ProcessHandle->0x%08x,FunctionAddress->0x%08x,Parameter->0x%08x,CreateSuspended->%d,StackZeroBits->%d", kThreadHandle, DesiredAccess, &kObjectName, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits)))
				log_lvl = LOG_PARAM;	
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssssssss,ThreadHandle->0x%08x,DesiredAccess->0x%08x,ThreadName->%wZ,ProcessHandle->0x%08x,FunctionAddress->0x%08x,Parameter->0x%08x,CreateSuspended->%d,StackZeroBits->%d", statusCall, kThreadHandle, DesiredAccess, &kObjectName, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThreadEx, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThreadEx, L"0,-1,ssssssss,ThreadHandle->0,DesiredAccess->0,ThreadName->NULL,ProcessHandle->0,FunctionAddress->0,Parameter->0,CreateSuspended->0,StackZeroBits->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateThreadEx, L"1,0,ssssssss,ThreadHandle->0,DesiredAccess->0,ThreadName->NULL,ProcessHandle->0,FunctionAddress->0,Parameter->0,CreateSuspended->0,StackZeroBits->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}


NTSTATUS Hooked_NtSetContextThread(__in HANDLE ThreadHandle,
								   __in PCONTEXT Context)								   
{
	NTSTATUS statusCall, exceptionCode;
	USHORT log_lvl = LOG_ERROR;
	ULONG currentProcessId, newProcessId;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtSetContextThread(ThreadHandle, Context);
	newProcessId = getPIDByThreadHandle(ThreadHandle);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtSetContextThread\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
					
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,s,ThreadHandle->0x%08x", ThreadHandle)))
				log_lvl = LOG_PARAM;	
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,s,ThreadHandle->0x%08x", statusCall, ThreadHandle)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtSetContextThread, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtSetContextThread, L"0,-1,s,ThreadHandle->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtSetContextThread, L"1,0,s,ThreadHandle->0");
			break;
		}
		if(parameter != NULL) 
			PoolFree(parameter);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtResumeThread(__in HANDLE ThreadHandle,
							   __out_opt PULONG SuspendCount)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId;
	ULONG kSuspendCount = 0;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtResumeThread(ThreadHandle, SuspendCount);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtResumeThread\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			ProbeForRead(SuspendCount, sizeof(ULONG), 1);
			kSuspendCount = *SuspendCount;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,ThreadHandle->0,SuspendCount->0", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtResumeThread, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtResumeThread, L"0,-1,ss,ThreadHandle->0,SuspendCount->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
				
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,ThreadHandle->0x%08x,SuspendCount->%d", ThreadHandle, kSuspendCount)))
				log_lvl = LOG_PARAM;
			
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,ThreadHandle->0x%08x,SuspendCount->%d", statusCall, ThreadHandle, kSuspendCount)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtResumeThread, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtResumeThread, L"0,-1,ss,ThreadHandle->0,SuspendCount->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtResumeThread, L"1,0,ss,ThreadHandle->0,SuspendCount->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}							   

NTSTATUS Hooked_NtOpenProcess(__out PHANDLE ProcessHandle,
							  __in ACCESS_MASK DesiredAccess,
							  __in POBJECT_ATTRIBUTES ObjectAttributes,
							  __in_opt PCLIENT_ID ClientId)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId = 0;
	HANDLE kProcessHandle = (HANDLE)INVALID_HANDLE_VALUE;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtOpenProcess\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ProcessHandle)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				kProcessHandle = *ProcessHandle;
			}
			if(ClientId)
			{
				ProbeForRead(ClientId, sizeof(CLIENT_ID), 1);
				targetProcessId = (ULONG)ClientId->UniqueProcess;
			}
			else
				targetProcessId = getPIDByHandle(kProcessHandle);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ProcessHandle->0,DesiredAccess->0,ProcessIdentifier->0", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, L"0,-1,sss,ProcessHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
				
		if(NT_SUCCESS(statusCall))
		{
			if(IsProcessInList(targetProcessId, pHiddenProcessListHead))
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,-1,sss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", kProcessHandle, DesiredAccess, targetProcessId)))
					SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, parameter);
				else
					SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, L"0,-1,sss,ProcessHandle->0,DesiredAccess->0,ProcessIdentifier->0");	
				NtClose(*ProcessHandle);
				return STATUS_INVALID_PARAMETER;
			}
			
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", kProcessHandle, DesiredAccess, targetProcessId)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,ProcessIdentifier->%d", statusCall, kProcessHandle, DesiredAccess, targetProcessId)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, L"0,-1,sss,ProcessHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtOpenProcess, L"1,0,sss,ProcessHandle->0,DesiredAccess->0,ProcessIdentifier->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtMapViewOfSection(__in HANDLE SectionHandle,
								   __in HANDLE ProcessHandle,
								   __inout PVOID *BaseAddress,
								   __in ULONG_PTR ZeroBits,
								   __in SIZE_T CommitSize,
								   __inout_opt PLARGE_INTEGER SectionOffset,
								   __inout PSIZE_T ViewSize,
								   __in SECTION_INHERIT InheritDisposition,
								   __in ULONG AllocationType,
								   __in ULONG Win32Protect)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	USHORT log_lvl = LOG_ERROR;
	LARGE_INTEGER kSectionOffset = {0};
	ULONG kViewSize = 0;
	ULONG ulBytesRead = 0;
	PWCHAR buff = NULL;
	PUCHAR buff2 = NULL;
	PWCHAR parameter = NULL;
	PVOID kBaseAddress = NULL;
	
	PAGED_CODE();
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		newProcessId = getPIDByHandle(ProcessHandle);
		
		if(currentProcessId != newProcessId)
		{
			Dbg("Call NtMapViewOfSection\n");

			parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
			
			__try
			{
				if(SectionOffset)
				{
					ProbeForReadLargeInteger(SectionOffset);
					kSectionOffset = *SectionOffset;
				}
				if(BaseAddress)
					kBaseAddress = *BaseAddress;
				if(ViewSize)
				{					
					ProbeForRead(ViewSize, sizeof(SIZE_T), 1);
					kViewSize = (ULONG)*ViewSize;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssssssss,SectionHandle->0,ProcessHandle->0,BaseAddress->0,CommitSize->0,SectionOffset->0,ViewSize->0,AllocationType->0,Win32Protect->0,Buffer->ERROR", exceptionCode)))
					SendLogs(currentProcessId, SIG_ntdll_NtMapViewOfSection, parameter);
				else
					SendLogs(currentProcessId, SIG_ntdll_NtMapViewOfSection, L"0,-1,sssssssss,SectionHandle->0,ProcessHandle->0,BaseAddress->0,CommitSize->0,SectionOffset->0,ViewSize->0,AllocationType->0,Win32Protect->0,Buffer->ERROR");
				if(parameter != NULL)
					PoolFree(parameter);
				return statusCall;
			}
			
			
			// log buffer
			buff = PoolAlloc(BUFFER_LOG_MAX);
			buff2 = PoolAlloc(BUFFER_LOG_MAX);
			RtlZeroMemory(buff2, BUFFER_LOG_MAX);
					
			if(NT_SUCCESS(statusCall))
			{
				if(kBaseAddress)
				{
					Orig_NtReadVirtualMemory(ProcessHandle, kBaseAddress, buff2, kViewSize, &ulBytesRead);
					CopyBuffer(buff, buff2, ulBytesRead);
				}
				log_lvl = LOG_SUCCESS;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sssssssss,SectionHandle->0x%08x,ProcessHandle->0x%08x,BaseAddress->0x%08x,CommitSize->%d,SectionOffset->%d,ViewSize->%d,AllocationType->%d,Win32Protect->%d,Buffer->%ws", SectionHandle, ProcessHandle, kBaseAddress, CommitSize, 0/*kSectionOffset.QuadPart*/, kViewSize, AllocationType, Win32Protect, buff)))
					log_lvl = LOG_PARAM;
				if(newProcessId)
					StartMonitoringProcess(newProcessId);
			}
			else
			
			{
				log_lvl = LOG_ERROR;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sssssssss,SectionHandle->0x%08x,ProcessHandle->0x%08x,BaseAddress->0x%08x,CommitSize->%d,SectionOffset->%d,ViewSize->%d,AllocationType->%d,Win32Protect->%d,Buffer->%ws", statusCall, SectionHandle, ProcessHandle, kBaseAddress, CommitSize, 0/*kSectionOffset.QuadPart*/, kViewSize, AllocationType, Win32Protect, buff)))
					log_lvl = LOG_PARAM;
			}
				
			switch(log_lvl)
			{
				case LOG_PARAM:
					SendLogs(currentProcessId, SIG_ntdll_NtMapViewOfSection, parameter);
					break;
				case LOG_SUCCESS:
					SendLogs(currentProcessId, SIG_ntdll_NtMapViewOfSection, L"1,0,sssssssss,SectionHandle->0,ProcessHandle->0,BaseAddress->0,CommitSize->0,SectionOffset->0,ViewSize->0,AllocationType->0,Win32Protect->0,Buffer->ERROR");
					break;
				default:
					SendLogs(currentProcessId, SIG_ntdll_NtMapViewOfSection, L"0,-1,sssssssss,SectionHandle->0,ProcessHandle->0,BaseAddress->0,CommitSize->0,SectionOffset->0,ViewSize->0,AllocationType->0,Win32Protect->0,Buffer->ERROR");
			}
			if(buff != NULL)
				PoolFree(buff);
			if(buff2 != NULL)
				PoolFree(buff2);
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}


NTSTATUS Hooked_NtReadVirtualMemory(__in HANDLE ProcessHandle,
									__in PVOID BaseAddress,
									__out PVOID Buffer,
									__in ULONG NumberOfBytesToRead,
									__out_opt PULONG NumberOfBytesReaded)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	ULONG kBufferSize = 0;
	PUCHAR kBuffer = NULL;
	PWCHAR buff = NULL;
	PWCHAR parameter = NULL;

	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("Call NtReadVirtualMemory()\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(NumberOfBytesReaded)
			{
				ProbeForRead(NumberOfBytesReaded, sizeof(ULONG), 1);	
				kBufferSize = *NumberOfBytesReaded;
			}
			ProbeForRead(Buffer, kBufferSize, 1);
			kBuffer = Buffer;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtReadVirtualMemory, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtReadVirtualMemory, L"0,-1,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		// log buffer
		buff = PoolAlloc(BUFFER_LOG_MAX);
		CopyBuffer(buff, kBuffer, kBufferSize);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sss,ProcessHandle->0x%08x,BaseAddress->0x%08x,Buffer->%ws", ProcessHandle, BaseAddress, buff)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sss,ProcessHandle->0x%08x,BaseAddress->0x%08x,Buffer->%ws", statusCall, ProcessHandle, BaseAddress, buff)))
				log_lvl = LOG_PARAM;
		}
			
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtReadVirtualMemory, parameter);
				break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtReadVirtualMemory, L"1,0,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
				break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtReadVirtualMemory, L"0,-1,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
		}

		if(parameter != NULL)
			PoolFree(parameter);
		if(buff != NULL)
			PoolFree(buff);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtWriteVirtualMemory(__in HANDLE ProcessHandle,
									 __in PVOID BaseAddress,
									 __in PVOID Buffer,
									 __in ULONG NumberOfBytesToWrite,
									 __out_opt PULONG NumberOfBytesWritten)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId;
	USHORT log_lvl = LOG_ERROR;
	ULONG kBufferSize = 0;
	PUCHAR kBuffer = NULL;
	PWCHAR buff = NULL;
	PWCHAR parameter = NULL;

	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("Call NtWriteVirtualMemory()\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		newProcessId = getPIDByHandle(ProcessHandle);
		
		__try
		{
			if(NumberOfBytesWritten)
			{
				ProbeForRead(NumberOfBytesWritten, sizeof(ULONG), 1);	
				kBufferSize = *NumberOfBytesWritten;
			}
			ProbeForRead(Buffer, kBufferSize, 1);
			kBuffer = Buffer;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtWriteVirtualMemory, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtWriteVirtualMemory, L"0,-1,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		// log buffer
		buff = PoolAlloc(BUFFER_LOG_MAX);
		CopyBuffer(buff, kBuffer, kBufferSize);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sss,ProcessHandle->0x%08x,BaseAddress->0x%08x,Buffer->%ws", ProcessHandle, BaseAddress, buff)))
				log_lvl = LOG_PARAM;
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sss,ProcessHandle->0x%08x,BaseAddress->0x%08x,Buffer->%ws", statusCall, ProcessHandle, BaseAddress, buff)))
				log_lvl = LOG_PARAM;
		}
			
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtWriteVirtualMemory, parameter);
				break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtWriteVirtualMemory, L"1,0,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
				break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtWriteVirtualMemory, L"0,-1,sss,ProcessHandle->0,BaseAddress->0,Buffer->ERROR");
		}

		if(parameter != NULL)
			PoolFree(parameter);
		if(buff != NULL)
			PoolFree(buff);
	}
	return statusCall;		
}

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
									__in_opt PVOID AttributeList)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	UNICODE_STRING process_name, thread_name;
	HANDLE kProcessHandle = (HANDLE)INVALID_HANDLE_VALUE, kThreadHandle = (HANDLE)INVALID_HANDLE_VALUE;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateUserProcess\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ProcessHandle)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				kProcessHandle = *ProcessHandle;
			}
			if(ThreadHandle)
			{
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
				kThreadHandle = *ThreadHandle;
			}
			if(ProcessParameters)
				ProbeForRead(ProcessParameters, sizeof(RTL_USER_PROCESS_PARAMETERS), 1);
			newProcessId = getPIDByHandle(kProcessHandle);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,0x%08x,ssssssss,ProcessHandle->0,ThreadHandle->0,DesiredAccessProcess->0,DesiredAccessThread->0,FlagsProcess->0,FlagsThread->0,FilePath->ERROR,CommandLine->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateUserProcess, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateUserProcess, L"0,-1,ssssssss,ProcessHandle->0,ThreadHandle->0,DesiredAccessProcess->0,DesiredAccessThread->0,FlagsProcess->0,FlagsThread->0,FilePath->ERROR,CommandLine->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssssssss,ProcessHandle->0x%08x,ThreadHandle->0x%08x,DesiredAccessProcess->0x%08x,DesiredAccessThread->0x%08x,FlagsProcess->%d,FlagsThread->%d,FilePath->%wZ,CommandLine->%wZ", kProcessHandle, kThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessFlags, ThreadFlags, &ProcessParameters->ImagePathName, &ProcessParameters->CommandLine)))
					log_lvl = LOG_PARAM;
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssssssss,ProcessHandle->0x%08x,ThreadHandle->0x%08x,DesiredAccessProcess->0x%08x,DesiredAccessThread->0x%08x,FlagsProcess->%d,FlagsThread->%d,FilePath->%wZ,CommandLine->%wZ", statusCall, kProcessHandle, kThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessFlags, ThreadFlags, &ProcessParameters->ImagePathName, &ProcessParameters->CommandLine)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateUserProcess, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateUserProcess, L"0,-1,ssssssss,ProcessHandle->0,ThreadHandle->0,DesiredAccessProcess->0,DesiredAccessThread->0,FlagsProcess->0,FlagsThread->0,FilePath->ERROR,CommandLine->ERROR");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateUserProcess, L"1,0,ssssssss,ProcessHandle->0,ThreadHandle->0,DesiredAccessProcess->0,DesiredAccessThread->0,FlagsProcess->0,FlagsThread->0,FilePath->ERROR,CommandLine->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtCreateProcessEx(__out PHANDLE ProcessHandle,
								  __in ACCESS_MASK DesiredAccess,
								  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								  __in HANDLE ParentProcess,
								  __in ULONG Flags,
								  __in_opt HANDLE SectionHandle,
								  __in_opt HANDLE DebugPort,
								  __in_opt HANDLE ExceptionPort,
								  __in BOOLEAN InJob)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	HANDLE kProcessHandle = (HANDLE)INVALID_HANDLE_VALUE;
	UNICODE_STRING kObjectName;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	kObjectName.Buffer = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateProcessEx\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ProcessHandle)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				kProcessHandle = *ProcessHandle;
				newProcessId = getPIDByHandle(kProcessHandle);
			}

			if(ObjectAttributes != NULL)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			else
				RtlInitUnicodeString(&kObjectName, L"");
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,ProcessHandle->0,DesiredAccess->0,Flags->0,FilePath->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcessEx, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcessEx, L"0,-1,ssss,ProcessHandle->0,DesiredAccess->0,Flags->0,FilePath->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
				
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,Flags->%d,FilePath->%wZ", kProcessHandle, DesiredAccess, Flags, &kObjectName)))
					log_lvl = LOG_PARAM;
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,Flags->%d,FilePath->%wZ", statusCall, kProcessHandle, DesiredAccess, Flags, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcessEx, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcessEx, L"0,-1,ssss,ProcessHandle->0,DesiredAccess->0,Flags->0,FilePath->ERROR");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcessEx, L"1,0,ssss,ProcessHandle->0,DesiredAccess->0,Flags->0,FilePath->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtCreateProcess(__out PHANDLE ProcessHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in HANDLE ParentProcess,
								__in BOOLEAN InheritObjectTable,
								__in_opt HANDLE SectionHandle,
								__in_opt HANDLE DebugPort,
								__in_opt HANDLE ExceptionPort)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, newProcessId = 0;
	HANDLE kProcessHandle = (HANDLE)INVALID_HANDLE_VALUE;
	UNICODE_STRING kObjectName;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	kObjectName.Buffer = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateProcess\n");
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(ProcessHandle)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				kProcessHandle = *ProcessHandle;
				newProcessId = getPIDByHandle(kProcessHandle);
			}
			if(ObjectAttributes != NULL)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			else
				RtlInitUnicodeString(&kObjectName, L"");
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,ProcessHandle->0,DesiredAccess->0,InheritObjectTable->0,FilePath->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcess, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcess, L"0,-1,ssss,ProcessHandle->0,DesiredAccess->0,InheritObjectTable->0,FilePath->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,InheritObjectTable->%d,FilePath->%wZ", kProcessHandle, DesiredAccess, InheritObjectTable, &kObjectName)))
					log_lvl = LOG_PARAM;
			if(newProcessId)
				StartMonitoringProcess(newProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssss,ProcessHandle->0x%08x,DesiredAccess->0x%08x,InheritObjectTable->%d,FilePath->%wZ", statusCall, kProcessHandle, DesiredAccess, InheritObjectTable, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcess, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcess, L"0,-1,ssss,ProcessHandle->0,DesiredAccess->0,InheritObjectTable->0,FilePath->ERROR");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateProcess, L"1,0,ssss,ProcessHandle->0,DesiredAccess->0,InheritObjectTable->0,FilePath->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}

NTSTATUS Hooked_NtTerminateProcess(__in_opt HANDLE ProcessHandle,
								   __in NTSTATUS ExitStatus)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = Orig_NtTerminateProcess(ProcessHandle, ExitStatus);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtTerminateProcess\n");
	
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(ProcessHandle)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,ProcessHandle->0x%08x,ExitStatus->0x%08x", ProcessHandle, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,ProcessHandle->0xffffffff,ExitStatus->0x%08x", ExitStatus)))
					log_lvl = LOG_PARAM;
			}
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(ProcessHandle)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,ProcessHandle->0x%08x,ExitStatus->0x%08x", statusCall, ProcessHandle, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,ProcessHandle->0xffffffff,ExitStatus->0x%08x", statusCall, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
		}
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtTerminateProcess, parameter);
			break;
				
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtTerminateProcess, L"0,-1,ss,ProcessHandle->0,ExitStatus->0");
			break;
				
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtTerminateProcess, L"1,0,ss,ProcessHandle->0,ExitStatus->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;
}