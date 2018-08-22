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
//	File :		utils.c
//	Abstract :	Utils function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "utils.h"
#include "monitor.h"
#include "hook_reg.h"
#include "query_information.h"
#include "main.h"


NTSTATUS reg_get_key(__in HANDLE KeyHandle, 
					 __out PWCHAR regkey)
{
	ULONG buffer_length, length;
	KEY_NAME_INFORMATION *key_name_information;
	
	buffer_length = sizeof(KEY_NAME_INFORMATION) + MAX_SIZE * sizeof(wchar_t);	
	key_name_information = PoolAlloc(buffer_length);
	if(key_name_information == NULL)
		return STATUS_NO_MEMORY;
	
	if(!NT_SUCCESS(ZwQueryKey(KeyHandle, KeyNameInformation, key_name_information, buffer_length, &length)))
	{
		PoolFree(key_name_information);
		return STATUS_INVALID_PARAMETER;
	}
	
	length = key_name_information->NameLength / sizeof(wchar_t);
	RtlCopyMemory(&regkey[0], key_name_information->Name, length * sizeof(wchar_t));
	regkey[length] = 0;
	
	if(key_name_information != NULL)
		PoolFree(key_name_information);
	return STATUS_SUCCESS;
}

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2)
{
    const wchar_t *s1, *s2;
    const wchar_t l = towlower(*wcs2);
    const wchar_t u = towupper(*wcs2);
    
    if (!*wcs2)
        return wcs1;
    
    for (; *wcs1; ++wcs1)
    {
        if (*wcs1 == l || *wcs1 == u)
        {
            s1 = wcs1 + 1;
            s2 = wcs2 + 1;
            
            while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
                ++s1, ++s2;
            
            if (!*s2)
                return wcs1;
        }
    }
 
    return NULL;
} 

NTSTATUS ParsePids(__in PCHAR pids)
{
	PCHAR start = NULL, current = NULL, data = NULL;
	size_t len;
	ULONG pid;
	NTSTATUS status;
	
	if(pids == NULL)
		return STATUS_INVALID_PARAMETER;
	
	status = RtlStringCbLengthA(pids, MAX_SIZE, &len);
	if(!NT_SUCCESS(status))
		return status;
	
	data = PoolAlloc(len+1);
	if(data == NULL)
		return STATUS_NO_MEMORY;
	
	status = RtlStringCbPrintfA(data, len+1, "%s", pids);
	if(!NT_SUCCESS(status))
	{
		PoolFree(data);
		return status;
	}
	
	start = data;
	current = data;
	
	while(*current != 0x00)
	{
		if(*current == ',' && current!=start)
		{
			*current = 0x00;
			status = RtlCharToInteger(start, 10, &pid);
			if(NT_SUCCESS(status) && pid!=0)
			{
				Dbg("pid to hide : %d\n", pid);
				AddProcessToHideToList(pid);
			}
			start = current+1;
		}
		current++;
	}
	
	if(start != current)
	{
		status = RtlCharToInteger(start, 10, &pid);
		if(NT_SUCCESS(status) && pid!=0)
		{
			Dbg("pid to hide : %d\n", pid);
			AddProcessToHideToList(pid);
		}
	}	
	PoolFree(data);
	
	return STATUS_SUCCESS;
}

VOID Resolve_FunctionsAddr()
{
	UNICODE_STRING usFuncName;
	
	RtlInitUnicodeString(&usFuncName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = MmGetSystemRoutineAddress(&usFuncName);

	RtlInitUnicodeString(&usFuncName, L"ZwQueryInformationProcess");
	ZwQueryInformationProcess = MmGetSystemRoutineAddress(&usFuncName);
	
	RtlInitUnicodeString(&usFuncName, L"ZwQueryInformationThread");
	ZwQueryInformationThread = MmGetSystemRoutineAddress(&usFuncName);
		
	RtlInitUnicodeString(&usFuncName, L"ZwQuerySection");
	ZwQuerySection = MmGetSystemRoutineAddress(&usFuncName);
}	

ULONG getPIDByThreadHandle(__in HANDLE hThread)
{
	THREAD_BASIC_INFORMATION teb;
	
	if(hThread)
		if(NT_SUCCESS(ZwQueryInformationThread(hThread, 0, &teb, sizeof(teb), NULL)))
			return (ULONG)teb.ClientId.UniqueProcess;
	
	return 0;
}

ULONG getTIDByHandle(__in HANDLE hThread)
{
	THREAD_BASIC_INFORMATION teb;
	
	if(hThread)
		if(NT_SUCCESS(ZwQueryInformationThread(hThread, 0, &teb, sizeof(teb), NULL)))
			return (ULONG)teb.ClientId.UniqueThread;
	
	return 0;
}
	
ULONG getPIDByHandle(__in HANDLE hProc)
{
	PROCESS_BASIC_INFORMATION peb;
	
	if(hProc)
		if(NT_SUCCESS(ZwQueryInformationProcess(hProc, 0, &peb, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
			return (ULONG)peb.UniqueProcessId;
	
	return 0;
}

VOID CopyBuffer(__out PWCHAR dst, 
				__in PUCHAR src, 
				__in ULONG_PTR size)
{
	ULONG i, n = 0;
	if(dst && src && size)
	{
		RtlZeroMemory(dst, BUFFER_LOG_MAX);
		for(i=0; i<size; i++)
		{
			if(i >= (BUFFER_LOG_MAX/2))
				break;
			
			if(src[i] != 0x00)
			{
				if((src[i] >= 0x20) && (src[i] <= 0x7E) && (src[i] != 0x2C))
				{
					RtlStringCchPrintfW(&dst[n], (BUFFER_LOG_MAX/2)-n-1, L"%c", src[i]);
					n++;
				}
				else
				{
					RtlStringCchPrintfW(&dst[n], (BUFFER_LOG_MAX/2)-n-1, L"\\x%02x", src[i]);
					n+=4;
				}
			}
		}
	}
}

NTSTATUS dump_file(__in UNICODE_STRING filepath, 
				   __out PUNICODE_STRING filepath_to_dump)
{
	NTSTATUS status;
	PWCHAR ptr_filename = NULL;
	PWCHAR filename = NULL;
	PWCHAR newpath = NULL;
	HANDLE hFile = NULL;
	PFILE_RENAME_INFORMATION pRenameInformation = NULL;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fullpath;
	IO_STATUS_BLOCK iosb;
	DWORD i;
	
	filename = PoolAlloc(MAX_SIZE);
	if(!filename)
		return STATUS_NO_MEMORY;
		
	if(!NT_SUCCESS(RtlStringCchPrintfW(filename, MAX_SIZE, L"%wZ", &filepath)))
		return STATUS_INVALID_PARAMETER;
		
	i = wcslen(filename);
	while(filename[i] != 0x5C)
		i--;	
	i++;	
	ptr_filename = filename+i;
	
	if(!ptr_filename)
		return STATUS_INVALID_PARAMETER;
		
	newpath = PoolAlloc(MAX_SIZE);
	if(!newpath)
		return STATUS_NO_MEMORY;
		
	RtlStringCchPrintfW(newpath, MAX_SIZE, L"%ws\\%ws", cuckooPath, ptr_filename);
	RtlInitUnicodeString(&fullpath, newpath);
	
	if(filepath_to_dump == NULL)
		return STATUS_INVALID_PARAMETER;
	
	RtlCopyUnicodeString(filepath_to_dump, &fullpath); 
	InitializeObjectAttributes(&objAttr, &filepath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&hFile, (SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &objAttr, &iosb, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);	
	if(!NT_SUCCESS(status))
		return STATUS_INVALID_PARAMETER;
	
	pRenameInformation = PoolAlloc(sizeof(FILE_RENAME_INFORMATION) + 2048);
	
	pRenameInformation->ReplaceIfExists = TRUE;
	pRenameInformation->RootDirectory = NULL;
	RtlCopyMemory(pRenameInformation->FileName, fullpath.Buffer, 2048);
	pRenameInformation->FileNameLength = wcslen(pRenameInformation->FileName)*sizeof(WCHAR);
	
	status = ZwSetInformationFile(hFile, &iosb, pRenameInformation, sizeof(FILE_RENAME_INFORMATION)+pRenameInformation->FileNameLength, FileRenameInformation);
	
	if(!NT_SUCCESS(status))
		return STATUS_INVALID_PARAMETER;
	ZwClose(hFile);
	
	PoolFree(filename);
	PoolFree(newpath);
	PoolFree(pRenameInformation);
	
	return status;
}

NTSTATUS getProcNameByPID(__in ULONG pid, 
						  __out PUNICODE_STRING procName)
{
	NTSTATUS status;
	HANDLE hProcess;
	PEPROCESS eProcess = NULL;
	ULONG returnedLength;
	UNICODE_STRING func;
	PVOID buffer = NULL;
	PUNICODE_STRING imageName = NULL;

	if(pid == 0 || procName == NULL)
		return STATUS_INVALID_PARAMETER;

	if(pid == 4)
	{
		RtlInitUnicodeString(&func, L"System");
		RtlCopyUnicodeString(procName, &func);
		return STATUS_SUCCESS;
	}

	status = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if(!NT_SUCCESS(status))
		return status;

	status = ObOpenObjectByPointer(eProcess,0, NULL, 0,0,KernelMode,&hProcess);
	if(!NT_SUCCESS(status))
		return status;

	ObDereferenceObject(eProcess);
	ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);

	buffer = PoolAlloc(returnedLength);
	if(!buffer)
		return STATUS_NO_MEMORY;

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, returnedLength, &returnedLength);
	if(NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		if(procName->MaximumLength > imageName->Length)
			RtlCopyUnicodeString(procName, imageName);
		else
			status = STATUS_BUFFER_TOO_SMALL;
	}
	PoolFree(buffer);
	return status;
}