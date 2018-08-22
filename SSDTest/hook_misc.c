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
//	File :		hook_misc.c
//	Abstract :	Hook misc function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "hooking.h"
#include "hook_misc.h"
#include "monitor.h"
#include "utils.h"
#include "main.h"
#include "comm.h"

VOID imageCallback(__in PUNICODE_STRING FullImageName,
				   __in HANDLE ProcessId,
				   __in PIMAGE_INFO ImageInfo)
{
	NTSTATUS exceptionCode;
	ULONG currentProcessId;
	UNICODE_STRING kImageName;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();

	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(ImageInfo && IsProcessInList(currentProcessId, pMonitoredProcessListHead))
	{
		if(ImageInfo->SystemModeImage)
		{
			parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
			kImageName.Buffer = NULL;

			__try
			{
				if(FullImageName)
				{
					ProbeForRead(FullImageName, sizeof(UNICODE_STRING), 1);
					kImageName.Length = FullImageName->Length;
					kImageName.MaximumLength = FullImageName->MaximumLength;
					kImageName.Buffer = PoolAlloc(FullImageName->MaximumLength);
					RtlCopyUnicodeString(&kImageName, FullImageName);
				}
	
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,s,DriverName->ERROR", exceptionCode)))
					SendLogs(currentProcessId, SIG_ntdll_NtLoadDriver, parameter);
				else 
					SendLogs(currentProcessId, SIG_ntdll_NtLoadDriver, L"0,-1,s,DriverName->ERROR");
				if(parameter != NULL)
					PoolFree(parameter);
				return;
			}
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"1,0,s,DriverName->%wZ", &kImageName)))
				SendLogs(currentProcessId, SIG_ntdll_NtLoadDriver, parameter);
			else
				SendLogs(currentProcessId, SIG_ntdll_NtLoadDriver, L"0,-1,s,DriverName->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
		}
	}
}

NTSTATUS Hooked_NtDelayExecution(__in BOOLEAN Alertable,
								 __in PLARGE_INTEGER DelayInterval)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	LARGE_INTEGER kDelayInterval = {0};
	ULONGLONG ms = 0;

	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtDelayExecution(Alertable, DelayInterval);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("Call NtDelayExecution\n");
			
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{
			if(DelayInterval)
			{
				ProbeForRead(DelayInterval, sizeof(LARGE_INTEGER), 1);
				kDelayInterval = *DelayInterval;
				ms = -kDelayInterval.QuadPart/10000;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,s,DelayInterval->0", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtDelayExecution, parameter);
			else 
				SendLogs(currentProcessId, SIG_ntdll_NtDelayExecution, L"0,-1,s,DelayInterval->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,s,DelayInterval->%d", ms)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,s,DelayInterval->%d", statusCall, ms)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtDelayExecution, parameter);
			break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtDelayExecution, L"1,0,s,DelayInterval->0");
			break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtDelayExecution, L"0,-1,s,DelayInterval->0");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;
}

NTSTATUS Hooked_NtCreateMutant(__out PHANDLE MutantHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							   __in BOOLEAN InitialOwner)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kMutantHandle;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("Call NtCreateMutant\n");
			
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{

			ProbeForRead(MutantHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		
			kMutantHandle = *MutantHandle;
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
			kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);	
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR", exceptionCode)))
				SendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, parameter);
			else 
				SendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"0,-1,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,InitialOwner->%d,MutantName->%wZ", kMutantHandle, DesiredAccess, InitialOwner, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,InitialOwner->%d,MutantName->%wZ", statusCall, kMutantHandle, DesiredAccess, InitialOwner, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, parameter);
			break;
			case LOG_SUCCESS:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"1,0,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			break;
			default:
				SendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"0,-1,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;
}
