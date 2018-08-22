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
//  File :      monitor.h
//  Abstract :  Monitor header for zer0m0n
//  Revision :  v1.1
//  Author :    Adrien Chevalier, Nicolas Correia, Cyril Moreau
//  Email :     contact.zer0m0n@gmail.com
//  Date :      2016-07-05      
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __MONITOR_H
#define __MONITOR_H

#include <fltkernel.h>

/////////////////////////////////////////////////////////////////////////////
// STRUCTS
/////////////////////////////////////////////////////////////////////////////


// processes linked list
typedef struct _PROCESS_ENTRY
{
    LIST_ENTRY entry;
    ULONG pid;
} PROCESS_ENTRY, *PPROCESS_ENTRY;

// file handle linked list
typedef struct _HANDLE_ENTRY
{
    LIST_ENTRY entry;
    HANDLE handle;
} HANDLE_ENTRY, *PHANDLE_ENTRY;


/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


// monitored processes list
PLIST_ENTRY pMonitoredProcessListHead;

// processes list to be hidden
PLIST_ENTRY pHiddenProcessListHead;

// file handle list
PLIST_ENTRY pHandleListHead;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Initialize the linked lists
//  Parameters :
//      None
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Init_LinkedLists();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Allocate a new node for a process linked list
//  Parameters :
//      __in ULONG new_pid : PID to add to the list
//  Return value :
//      PPROCESS_ENTRY : an allocated PROCESS_ENTRY or NULL if an error occured      
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PPROCESS_ENTRY AllocateProcessEntry(__in ULONG new_pid);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Allocate a new node for a process linked list
//  Parameters :
//      __in HANDLE new_handle : handle to add to the list
//  Return value :
//      PHANDLE_ENTRY : an allocated HANLE_ENTRY or NULL if an error occured
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PHANDLE_ENTRY AllocateHandleEntry(__in HANDLE new_handle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new process to monitor in the list 
//  Parameters :
//      __in ULONG new_pid : pid to add to the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the pid in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS StartMonitoringProcess(__in ULONG new_pid);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new process to hide in the list 
//  Parameters :
//      __in ULONG new_pid : pid to add to the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the pid in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS AddProcessToHideToList(__in ULONG new_pid);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Add a new handle to monitor in the list 
//  Parameters :
//      __in ULONG new_handle : new_handle to add in the list
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise returns the relevant NTSTATUS code
//  Process :
//      Add the handle in the list if he's not already inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS AddHandleToList(__in HANDLE new_handle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Removes handle from the list (stop monitoring this handle) 
//  Parameters :
//      __in ULONG handle : handle to remove from the monitored handle list 
//  Return value :
//      NTSTATUS : STATUS_SUCCESS if no error occured, otherwise, relevant NTSTATUS code
//  Process :
//      Remove handle from the list if he's inside.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS RemoveHandleFromList(__in HANDLE handle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Checks if a process is in a linked list 
//  Parameters :
//      __in ULONG pid : process identifier to check for
//      __in PLIST_ENTRY pListHead : linked list to check in
//  Return value :
//      BOOLEAN : TRUE if found, FALSE if not 
//  Process :
//      Walks through the linked list, returns TRUE if the process is found 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsProcessInList(__in ULONG pid, 
                        __in PLIST_ENTRY pListHead);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Checks if a handle is in a linked list 
//  Parameters :
//      __in HANDLE handle : handle to check for
//      __in PLIST_ENTRY pListHead : linked list to check in
//  Return value :
//      BOOLEAN : TRUE if found, FALSE if not 
//  Process :
//      Walks through the linked list, returns TRUE if the handle is found 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN IsHandleInList(__in HANDLE handle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//      Remove the entries from every linked list 
//  Parameters :
//      None
//  Return value :
//      None
//  Process :
//      Walks through the linked lists and removes each entries.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID FreeList();

#endif
