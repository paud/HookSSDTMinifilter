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
//  File :      utils.h
//  Abstract :  Utils header for zer0m0n
//  Revision :  v1.1
//  Author :    Adrien Chevalier, Nicolas Correia, Cyril Moreau
//  Email :     contact.zer0m0n@gmail.com
//  Date :      2016-07-05      
//
/////////////////////////////////////////////////////////////////////////////
#ifndef __UTILS_H
#define __UTILS_H

#include <fltkernel.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define BUFFER_LOG_MAX 	256
#define OBJECT_NAME_INFORMATION_REQUIRED_SIZE \
	sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR) + MAX_PATH
	

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves functions addresses
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Resolve_FunctionsAddr();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Parses received PIDs and adds them in the hidden list.
//	Parameters :
//		list of pids to hide.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS on success.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ParsePids(__in PCHAR pids);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve the registry key name from the key handle
//	Parameters :
//		
//	Return value :
//		NTSTATUS : STATUS_SUCCESS on success.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS reg_get_key(__in HANDLE KeyHandle, 
					 __out PWCHAR regkey);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		wcsstr case-insensitive version (scans "haystack" for "needle").
//	Parameters :
//		_in_ PWCHAR *haystack :	PWCHAR string to be scanned.
//		_in_ PWCHAR *needle :	PWCHAR string to find.
//	Return value :
//		PWCHAR : NULL if not found, otherwise "needle" first occurence pointer in "haystack".
//	Notes : http://www.codeproject.com/Articles/383185/SSE-accelerated-case-insensitive-substring-search
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PWCHAR wcsistr(__in PWCHAR wcs1, 
			   __in PWCHAR wcs2);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getTIDByHandle(__in HANDLE hThread);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByThreadHandle(__in HANDLE hThread);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process identifier from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc :	Process handle. If NULL, retrieves current process identifier.
//	Return value :
//		ULONG : -1 if an error was encountered, otherwise, process identifier.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByHandle(__in HANDLE hProc);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Copy the content of src buffer to dst buffer
//	Parameters :
//		_out_ PWCHAR dst : the buffer of destination
//		_in_  PUCHAR src : the buffer to be copied
//		_in_  ULONG size : the size of the src buffer  	
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID CopyBuffer(__out PWCHAR dst, 
				__in PUCHAR src, 
				__in ULONG_PTR size);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process name from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc : Process ID
//		_out_ PUNICODE_STRING : Caller allocated UNICODE_STRING, process name.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS getProcNameByPID(__in ULONG pid, 
						  __out PUNICODE_STRING procName);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Move the file given as parameter to the cuckoo directory
//	Parameters :
//		_in_  UNICODE_STRING filepath : the file to be moved
//		_out_ PUNICODE_STRING filepath_to_dump : the new pathfile (after the file has been moved)  	
//	Return value :
//		STATUS_SUCCESS if the file has correctly been moved, otherwise return error message
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS dump_file(__in UNICODE_STRING filepath, 
				   __out PUNICODE_STRING filepath_to_dump);

#endif