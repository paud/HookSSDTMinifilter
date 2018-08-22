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
//	File :		monitor.c
//	Abstract :	Monitor function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "monitor.h"
#include "main.h"

NTSTATUS Init_LinkedLists()
{
	PPROCESS_ENTRY pInitHideEntry = NULL;
	PPROCESS_ENTRY pInitProcEntry = NULL;	
	pMonitoredProcessListHead = NULL;
	pHiddenProcessListHead = NULL;
	pHandleListHead = NULL;

	pInitHideEntry = AllocateProcessEntry(0);
	if(pInitHideEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}
	pInitProcEntry = AllocateProcessEntry(0);
	if(pInitProcEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}

	InitializeListHead(&pInitProcEntry->entry);            
	pMonitoredProcessListHead = &pInitProcEntry->entry;
	InitializeListHead(&pInitHideEntry->entry);            
	pHiddenProcessListHead = &pInitHideEntry->entry;

	return STATUS_SUCCESS;
}

PPROCESS_ENTRY AllocateProcessEntry(__in ULONG new_pid)
{
	PPROCESS_ENTRY pProcessEntry = NULL;

	pProcessEntry = PoolAlloc(sizeof(PROCESS_ENTRY));
	if(pProcessEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n");
		return NULL;
	}

	pProcessEntry->pid = new_pid;

	return pProcessEntry;
}

PHANDLE_ENTRY AllocateHandleEntry(__in HANDLE new_handle)
{
	PHANDLE_ENTRY pHandleEntry = NULL;

	pHandleEntry = PoolAlloc(sizeof(HANDLE_ENTRY));
	if(pHandleEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n"); 
		return NULL;
	}
	pHandleEntry->handle = new_handle;

	return pHandleEntry;
}

NTSTATUS StartMonitoringProcess(__in ULONG new_pid)
{
	PPROCESS_ENTRY pNewEntry = NULL;

	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;

	if(IsProcessInList(new_pid, pMonitoredProcessListHead))
	{
		Dbg(__FUNCTION__ ":\t%d deja dans la liste : %d\n", new_pid);
		return STATUS_SUCCESS;
	}

	pNewEntry = AllocateProcessEntry(new_pid);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ ":\tAllocation failed !\n");
		return STATUS_NO_MEMORY;
	}	
	InsertHeadList(pMonitoredProcessListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

NTSTATUS AddProcessToHideToList(__in ULONG new_pid)
{
	PPROCESS_ENTRY pNewEntry = NULL;

	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;
	if(IsProcessInList(new_pid, pHiddenProcessListHead))
	{
		Dbg(__FUNCTION__ "\t: process to hide %d deja dans la liste : %d\n", new_pid);
		return STATUS_SUCCESS;
	}
	pNewEntry = AllocateProcessEntry(new_pid);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ "pNewEntry allocation failed !\n");
		return STATUS_NO_MEMORY;
	}

	InsertHeadList(pHiddenProcessListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

NTSTATUS AddHandleToList(__in HANDLE new_handle)
{    
	PHANDLE_ENTRY pNewEntry = NULL;

	if(new_handle == 0)
		return STATUS_INVALID_PARAMETER;
	if(IsHandleInList(new_handle))
	{
		Dbg(__FUNCTION__ "\t: handle %d deja dans la liste : %d\n", new_handle);
		return STATUS_SUCCESS;
	}	

	if(pHandleListHead == NULL)
	{
		pNewEntry = AllocateHandleEntry(0);
		if(pNewEntry == NULL)
		{
			Dbg(__FUNCTION__ ": failed !\n");
			return STATUS_NO_MEMORY;
		}
		InitializeListHead(&pNewEntry->entry);            
		pHandleListHead = &pNewEntry->entry;
	}

	pNewEntry = AllocateHandleEntry(new_handle);
	if(pNewEntry == NULL)
	{
		Dbg(__FUNCTION__ ": failed !\n");
		return STATUS_NO_MEMORY;
	}    
	InsertHeadList(pHandleListHead, &pNewEntry->entry);        
	return STATUS_SUCCESS;
}

NTSTATUS RemoveHandleFromList(__in HANDLE handle)
{
	PLIST_ENTRY pListEntry = NULL;
	PHANDLE_ENTRY pCurEntry = NULL;

	if(handle == 0)
		return STATUS_INVALID_PARAMETER;

	if(!IsHandleInList(handle))
		return STATUS_SUCCESS;

	pListEntry = pHandleListHead->Flink;
	do
	{
		pCurEntry = (PHANDLE_ENTRY) CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
		if(pCurEntry->handle == handle)
		{
			RemoveEntryList(&pCurEntry->entry);
			return STATUS_SUCCESS; 
		}

		pListEntry = pListEntry->Flink;
	}
	while(pListEntry != pHandleListHead);

	return STATUS_SUCCESS;

}

BOOLEAN IsProcessInList(__in ULONG pid, 
		__in PLIST_ENTRY pListHead)
{

	PLIST_ENTRY pListEntry = NULL;
	PPROCESS_ENTRY pCurEntry = NULL;

	if(pListHead == NULL)
		return FALSE;

	if(IsListEmpty(pListHead))
		return FALSE;

	pListEntry = pListHead->Flink;
	do
	{
		pCurEntry = CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
		if(pCurEntry->pid == pid)
			return TRUE;

		pListEntry = pListEntry->Flink;   
	} 
	while(pListEntry != pListHead);

	return FALSE;
}

BOOLEAN IsHandleInList(__in HANDLE handle)
{
	PLIST_ENTRY pListEntry = NULL;
	PHANDLE_ENTRY pCurEntry = NULL;

	if(pHandleListHead == NULL)
		return FALSE;

	if(IsListEmpty(pHandleListHead))
		return FALSE;

	pListEntry = pHandleListHead->Flink;

	do
	{
		pCurEntry = (PHANDLE_ENTRY)CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
		if(pCurEntry->handle == handle)
			return TRUE;

		pListEntry = pListEntry->Flink;   
	}
	while(pListEntry != pHandleListHead);

	return FALSE;
}


VOID FreeList()
{
	PLIST_ENTRY pListEntry = NULL; 
	PLIST_ENTRY pNextEntry = NULL;
	PPROCESS_ENTRY pCurProcEntry = NULL;
	PHANDLE_ENTRY pCurHandleEntry = NULL;

	if(pMonitoredProcessListHead != NULL)
	{
		if(!IsListEmpty(pMonitoredProcessListHead))
		{
			pListEntry = pMonitoredProcessListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pMonitoredProcessListHead);
			pMonitoredProcessListHead = NULL;
		}
	}

	if(pHiddenProcessListHead != NULL)
	{
		if(!IsListEmpty(pHiddenProcessListHead))
		{
			pListEntry = pHiddenProcessListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pHiddenProcessListHead);
			pHiddenProcessListHead = NULL;
		}
	}

	if(pHandleListHead != NULL)
	{
		if(!IsListEmpty(pHandleListHead))
		{
			pListEntry = pHandleListHead->Flink;
			do
			{
				pCurProcEntry = (PPROCESS_ENTRY)CONTAINING_RECORD(pListEntry, HANDLE_ENTRY, entry);
				pNextEntry = pListEntry->Flink;
				ExFreePool(pCurProcEntry);
				pListEntry = pNextEntry;
			}
			while(pListEntry != pHandleListHead);
			pHandleListHead = NULL;
		}

	}
}