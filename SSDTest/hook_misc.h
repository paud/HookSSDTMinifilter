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
//	File :		hook_misc.h
//	Abstract :	Hook misc header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __HOOK_MISC_H
#define __HOOK_MISC_H

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(*NTCREATEMUTANT)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,BOOLEAN);
typedef NTSTATUS(*NTDELAYEXECUTION)(BOOLEAN, PLARGE_INTEGER);

NTCREATEMUTANT Orig_NtCreateMutant;
NTDELAYEXECUTION Orig_NtDelayExecution;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs mutex creation
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Process :
//		logs mutex handle, desired access, mutex name and initial owner
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateMutant(__out PHANDLE MutantHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							   __in BOOLEAN InitialOwner);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs delay execution.
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//	Process :
//		logs delay execution (in ms)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDelayExecution(__in BOOLEAN Alertable,
								 __in PLARGE_INTEGER DelayInterval);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Image load callback. Allows being notified when a PE image is loaded into kernel space.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff559957(v=vs.85).aspx
//	Return value :
//		None
//	Process :
//		The function tests if the image is mapped into kernel memory (ImageInfo->SystemModeImage is set),
//		only if the analysis has started (if monitored_process_list is not NULL). If so, the image load
//		is logged, along with its filename (DriverName->name).
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID imageCallback(__in PUNICODE_STRING FullImageName,
				   __in HANDLE ProcessId,
				   __in PIMAGE_INFO ImageInfo);
#endif