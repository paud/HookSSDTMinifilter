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
//	File :		main.h
//	Abstract :	Main header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __MAIN_H
#define __MAIN_H

#include <fltkernel.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <windef.h>

#define DEBUG
#ifdef DEBUG
	#define Dbg(fmt, ...) \
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__);
#else
	#define Dbg(fmt, ...)
#endif

#define TAG_NAME 		'zm0n'
#define PoolAlloc(x)	ExAllocatePoolWithTag(NonPagedPool, x, TAG_NAME)
#define PoolFree(x)		ExFreePoolWithTag(x, TAG_NAME)

// userland communication mutex
KMUTEX mutex;

#define FLT_MAX_CONNECTIONS 	1
#define DRIVER_NAME 			L"zer0m0n"
#define FILTER_PORT_NAME 		L"\\FilterPort"

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


// some functions needed to import
//typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS);// a, int b, ULONG c, PULONG d);
typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationCLass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
ZWQUERYSYSTEMINFORMATION 	ZwQuerySystemInformation;

typedef NTSTATUS (*ZWQUERYINFORMATIONPROCESS)(HANDLE,ULONG,PVOID,ULONG,PULONG);
ZWQUERYINFORMATIONPROCESS 	ZwQueryInformationProcess;

typedef NTSTATUS (*ZWQUERYINFORMATIONTHREAD)(HANDLE,ULONG,PVOID,ULONG,PULONG);
ZWQUERYINFORMATIONTHREAD 	ZwQueryInformationThread;

typedef NTSTATUS (*ZWQUERYATTRIBUTESFILE)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
ZWQUERYATTRIBUTESFILE 		ZwQueryAttributesFile;

typedef NTSTATUS (*ZWCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
ZWCREATEPROCESS 			ZwCreateProcess;

typedef NTSTATUS (*ZWCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
ZWCREATEPROCESSEX			ZwCreateProcessEx;

typedef NTSTATUS (*ZWCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID);
ZWCREATEPROCESSEX			ZwCreateUserProcess;

typedef NTSTATUS (*ZWRESUMETHREAD)(HANDLE, PULONG);
ZWRESUMETHREAD				ZwResumeThread;

typedef NTSTATUS (*ZWQUERYSECTION)(HANDLE, ULONG, PVOID, ULONG, PULONG);
ZWQUERYSECTION				ZwQuerySection;

// Dos device driver name
UNICODE_STRING 	usDosDeviceName;

// cuckoo path (where the files about to be delete will be moved)
PWCHAR cuckooPath;

// filter stuff
PFLT_FILTER 	fltFilter;
PFLT_PORT 		fltServerPort;
PFLT_PORT 		fltClientPort;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the driver, communication and hooks.
//
//	Parameters : 
//		__in PDRIVER_OBJECT pDriverObject :	    Data structure used to represent the driver.
//		__in PUNICODE_STRING pRegistryPath :	Registry location where the information for the driver
//												was stored.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the driver initialization has been well completed
//	Process :
//		Import needed functions
//		Creates the device driver and its symbolic link.
//		Sets IRP callbacks.
//		Creates filter communication port to send logs from the driver to the userland process.
//		Creates logs mutex.
//		Hooks SSDT.
//		Register image load callback.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
					 __in PUNICODE_STRING pRegistryPath);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Driver unload callback. Removes hooks, callbacks, and communication stuff.
//
//	Parameters :
//		__in PDRIVER_OBJECT pDriverObject :	Data structure used to represent the driver.
//	Process :
//		Removes hooks, callbacks, device driver symbolic link / device. 
//		Cleans the monitored processes linked list.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Unload(__in PDRIVER_OBJECT pDriverObject);

#endif __MAIN_H