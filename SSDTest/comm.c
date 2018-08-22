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
//	File :		comm.c
//	Abstract :	Comm function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include <fltKernel.h>
#include "main.h"
#include "struct.h"
#include "utils.h"
#include "monitor.h"
#include "hooking.h"
#include "comm.h"


// filter callbacks struct
static const FLT_REGISTRATION fltRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	NULL,//FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, 
	NULL,
	NULL,
	FltUnregister,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

NTSTATUS InitMinifilter(__in PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	PSECURITY_DESCRIPTOR pSecurityDesc = NULL;
	UNICODE_STRING fltPortName;

	status = FltRegisterFilter(pDriverObject, &fltRegistration, &fltFilter); // win10 return STATUS_OBJECT_NAME_NOT_FOUND(0xC0000034L | 0n-1073741772)
	if(!NT_SUCCESS(status))
		return status;

	RtlInitUnicodeString(&fltPortName, FILTER_PORT_NAME);
	status = FltBuildDefaultSecurityDescriptor(&pSecurityDesc, FLT_PORT_ALL_ACCESS); 
	if(!NT_SUCCESS(status))
		return status;

	InitializeObjectAttributes(&objAttr, &fltPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, pSecurityDesc);

	status = FltCreateCommunicationPort(fltFilter, &fltServerPort, &objAttr, NULL, FltConnectCallback, 
			FltDisconnectCallback, NULL, FLT_MAX_CONNECTIONS);
	FltFreeSecurityDescriptor(pSecurityDesc);    
	if(!NT_SUCCESS(status))
		return status;

	return STATUS_SUCCESS;
}


NTSTATUS FltConnectCallback(__in PFLT_PORT ClientPort, 
							__in PVOID ServerPortCookie, 	
							__in PVOID ConnectionContext, 
							__in ULONG SizeOfContext, 
							__out PVOID *ConnectionPortCookie)
{
	if(ClientPort == NULL)
		return STATUS_INVALID_PARAMETER;

	fltClientPort = ClientPort;
	return STATUS_SUCCESS;
}

VOID FltDisconnectCallback(__in PVOID ConnectionCookie)
{
}

NTSTATUS Ioctl_DeviceControl(__in PDEVICE_OBJECT pDeviceObject,
   							 __in PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	PCHAR buffer;
	ULONG ioControlCode;
	ULONG inputLength;
	ULONG malware_pid = 0;

	if(pIrp == NULL || pDeviceObject == NULL)
		return STATUS_INVALID_PARAMETER;

	pIoStackIrp = IoGetCurrentIrpStackLocation(pIrp);

	ioControlCode = pIoStackIrp->Parameters.DeviceIoControl.IoControlCode;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	buffer = pIrp->AssociatedIrp.SystemBuffer;

	switch(ioControlCode)
	{
		case IOCTL_PROC_MALWARE:
			Dbg("IOCTL_PROC_MALWARE received\n");
			status = RtlCharToInteger(buffer, 10, &malware_pid);
			Dbg("malware_pid : %d\n", malware_pid);
			if(NT_SUCCESS(status) && malware_pid > 0)
				StartMonitoringProcess(malware_pid);				
			break;	

		case IOCTL_PROC_TO_HIDE:
			Dbg("pids to hide : %s\n", buffer);
			status = ParsePids(buffer);
			RtlZeroMemory(buffer, inputLength);
			break;


		case IOCTL_CUCKOO_PATH:
			cuckooPath = PoolAlloc(MAX_SIZE);
			if(inputLength && inputLength < MAX_SIZE)
				RtlStringCchPrintfW(cuckooPath, MAX_SIZE, L"\\??\\%ws", buffer);
			else
			{
				Dbg("IOCTL_CUCKOO_PATH : Buffer too large\n");
				return STATUS_BUFFER_TOO_SMALL;
			}
			Dbg("cuckoo path : %ws\n", cuckooPath);
			break;

		default:
			break;
	}

	pIrp->IoStatus.Status = status;	
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS Ioctl_NotSupported(__in PDEVICE_OBJECT pDeviceObject,
							__in PIRP pIrp)
{
	return STATUS_NOT_SUPPORTED;
}


NTSTATUS FltUnregister(__in FLT_FILTER_UNLOAD_FLAGS flags)
{
	FltCloseCommunicationPort(fltServerPort);

	if(fltFilter != NULL)
		FltUnregisterFilter(fltFilter);

	return STATUS_FLT_DO_NOT_DETACH;
}

NTSTATUS SendLogs(__in ULONG pid, 
				  __in ULONG sig_func, 
				  __in PWCHAR parameter)
{
	NTSTATUS status = STATUS_SUCCESS;
	CHAR buf[MAX_SIZE];
	UNICODE_STRING processName;
	size_t sizeBuf;

	LARGE_INTEGER timeout;
	timeout.QuadPart = -((LONGLONG)0.5*10*1000*1000);

	if(sig_func <= 0)
		return STATUS_INVALID_PARAMETER;

	Dbg("SendLogs\n");
	Dbg("parameter : %ws\n", parameter);
		
	processName.Length = 0;
	processName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	processName.Buffer = PoolAlloc(processName.MaximumLength);
	if(!processName.Buffer)
	{
		Dbg("Error 1\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		return STATUS_NO_MEMORY;
	}

	status = getProcNameByPID(pid, &processName);
	if(!NT_SUCCESS(status))
	{
		Dbg("Error 2\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}

	status = RtlStringCbPrintfA(buf, MAX_SIZE, "%d,%wZ,%d,%ws\n", pid, &processName, sig_func, parameter);
	if(!NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
	{
		Dbg("Error 3 : %x\n", status);
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}

	status = RtlStringCbLengthA(buf, MAX_SIZE, &sizeBuf);
	if(!NT_SUCCESS(status))
	{
		Dbg("Error 4\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}


	KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
	Dbg("\tmsg : %s\n", buf);

	status = FltSendMessage(fltFilter, &fltClientPort, buf, sizeBuf, NULL, 0, NULL);
	if(status == STATUS_TIMEOUT)
		Dbg("STATUS_TIMEOUT !!\n");
	KeReleaseMutex(&mutex, FALSE);
	PoolFree(processName.Buffer);

	if(!NT_SUCCESS(status))
		Dbg("return : 0x%08x\n", status);

	return status;
}
