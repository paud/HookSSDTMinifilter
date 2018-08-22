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
//	File :		hook_file.h
//	Abstract :	Hook file header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __HOOK_FILE_H
#define __HOOK_FILE_H

#define FILE_SHARE_READ 			0x00000001
#define INVALID_FILE_ATTRIBUTES 	-1

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

typedef NTSTATUS(*NTWRITEFILE)(HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
typedef NTSTATUS(*NTCREATEFILE)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS(*NTREADFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(*NTDELETEFILE)(POBJECT_ATTRIBUTES);
typedef NTSTATUS(*NTOPENFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(*NTSETINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(*NTCLOSE)(HANDLE);
typedef NTSTATUS(*NTDEVICEIOCONTROLFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(*NTQUERYATTRIBUTESFILE)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);

NTWRITEFILE Orig_NtWriteFile;
NTCREATEFILE Orig_NtCreateFile;
NTREADFILE Orig_NtReadFile;
NTDELETEFILE Orig_NtDeleteFile;
NTOPENFILE Orig_NtOpenFile;
NTSETINFORMATIONFILE Orig_NtSetInformationFile;
NTCLOSE Orig_NtClose;
NTDEVICEIOCONTROLFILE Orig_NtDeviceIoControlFile;
NTQUERYATTRIBUTESFILE Orig_NtQueryAttributesFile;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX files
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//	Process :
//		if a malware tries to identify VirtualBox by trying to get attributes of vbox files, we return
//		INVALID_FILE_ATTRIBUTES.
//		we only log when there is an attempt to detect VirtualBox
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueryAttributesFile(__in POBJECT_ATTRIBUTES ObjectAttributes,
									  __out PFILE_BASIC_INFORMATION FileInformation);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs IOCTLs
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//	Process :
//		logs file handle, IoControlCode and both input and output buffer
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDeviceIoControlFile(__in HANDLE FileHandle,
									  __in_opt HANDLE Event,
									  __in_opt PIO_APC_ROUTINE ApcRoutine,
									  __in_opt PVOID ApcContext,
									  __out PIO_STATUS_BLOCK IoStatusBlock,
									  __in ULONG IoControlCode,
									  __in_opt PVOID InputBuffer,
									  __in ULONG InputBufferLength,
									  __out_opt PVOID OutputBuffer,
									  __in ULONG OutputBufferLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion / rename.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Process :
//		Copy the FileHandle parameter, then checks the FileInformationClass argument.
//		If FileDispositionInformation, the file may be deleted, the FileInformation->DeleteFile
//		parameter is copied and tested.
//		If FileRenameInformationrmation, the FileInformation->FileName parameter is copied along with the
//		FileInformation->RootDirectory parameter, then the call is logged.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtSetInformationFile(__in HANDLE FileHandle,
									  __out PIO_STATUS_BLOCK IoStatusBlock,
									  __in PVOID FileInformation,
									  __in ULONG Length,
									  __in FILE_INFORMATION_CLASS FileInformationClass);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file modification.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Process :
//		logs FileHandle, ByteOffset and Buffer	   
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtWriteFile( __in HANDLE FileHandle, 
							 __in_opt HANDLE Event, 
							 __in_opt PVOID ApcRoutine, 
							 __in_opt PVOID ApcContext, 
							 __out PIO_STATUS_BLOCK IoStatusBlock, 
							 __in PVOID Buffer, 
							 __in ULONG Length, 
							 __in_opt PLARGE_INTEGER ByteOffset, 
							 __in_opt PULONG Key);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file creation and/or file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Process :
//		Copies arguments, handles the non-NULL ObjectAttributes->RootDirectory parameter case (concat
//		of RootDirectory and ObjectName) then logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateFile(__out PHANDLE FileHandle, 
							 __in ACCESS_MASK DesiredAccess, 
							 __in POBJECT_ATTRIBUTES ObjectAttributes, 
							 __out PIO_STATUS_BLOCK IoStatusBlock, 
							 __in_opt PLARGE_INTEGER AllocationSize, 
							 __in ULONG FileAttributes, 
							 __in ULONG ShareAccess, 
							 __in ULONG CreateDisposition, 
							 __in ULONG CreateOptions,
							 __in PVOID EaBuffer,
							 __in ULONG EaLength);		

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file reading.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Process :
//		logs FileHandle, Length, ByteOffset and Buffer
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtReadFile(__in HANDLE FileHandle,
						   __in_opt HANDLE Event,
						   __in_opt PIO_APC_ROUTINE ApcRoutine,
						   __in_opt PVOID ApcContext,
						   __out PIO_STATUS_BLOCK IoStatusBlock,
						   __out PVOID Buffer,
						   __in ULONG Length,
						   __in_opt PLARGE_INTEGER ByteOffset,
						   __in_opt PULONG Key);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432381(v=vs.85).aspx
//  Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432381(v=vs.85).aspx
//	Process :
//		Copies arguments, handles the non-NULL ObjectAttributes->RootDirectory parameter case (concat
//		of RootDirectory and ObjectName) then logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////						   
NTSTATUS Hooked_NtOpenFile(__out PHANDLE FileHandle,
						   __in ACCESS_MASK DesiredAccess,
						   __in POBJECT_ATTRIBUTES ObjectAttributes,
						   __out PIO_STATUS_BLOCK IoStatusBlock,
						   __in ULONG ShareAccess,
						   __in ULONG OpenOptions);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Process :
//		Copies the ObjectAttributes->ObjectName parameter, copies the file about to be deleted in another
//		directory in order to dump it later and then logs the file deletion.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDeleteFile(__in POBJECT_ATTRIBUTES ObjectAttributes);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Dumps files which are about to be deleted (FILE_DELETE_ON_CLOSE)
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566417%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566417%28v=vs.85%29.aspx
// 	Process :
//		if Handle is on the handle monitored list, retrieve filename from handle and move the file 
// 		to cuckoo directory in order to dump it
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtClose(__in HANDLE Handle);
						   
#endif