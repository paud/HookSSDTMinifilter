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
//	File :		hook_reg.h
//	Abstract :	Hook reg header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __HOOK_REG_H
#define __HOOK_REG_H

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(*NTQUERYVALUEKEY)(HANDLE,PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTOPENKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(*NTOPENKEYEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(*NTCREATEKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(*NTDELETEKEY)(HANDLE);
typedef NTSTATUS(*NTDELETEVALUEKEY)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS(*NTSETVALUEKEY)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

NTCREATEKEY Orig_NtCreateKey;
NTQUERYVALUEKEY Orig_NtQueryValueKey;
NTOPENKEY Orig_NtOpenKey;
NTOPENKEYEX Orig_NtOpenKeyEx;
NTDELETEKEY Orig_NtDeleteKey;
NTDELETEVALUEKEY Orig_NtDeleteValueKey;
NTSETVALUEKEY Orig_NtSetValueKey;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs value key set
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567109(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567109(v=vs.85).aspx
//	Process :
//		logs KeyHandle, ValueName, TitleIndex, Type and Data
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtSetValueKey(__in HANDLE KeyHandle,
							  __in PUNICODE_STRING ValueName,
							  __in_opt ULONG TitleIndex,
							  __in ULONG Type,
							  __in_opt PVOID Data,
							  __in ULONG DataSize);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs deleted value key
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566439(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566439(v=vs.85).aspx
//	Process :
//		logs KeyHandle, ValueName
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDeleteValueKey(__in HANDLE KeyHandle,
								 __in PUNICODE_STRING ValueName);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs deleted key
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566437(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566437(v=vs.85).aspx
//	Process :
//		logs KeyHandle, key name
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtDeleteKey(__in HANDLE KeyHandle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs value key queries
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069(v=vs.85).aspx
//	Process :
//		logs KeyHandle, value name, KeyValueInformationClass, reg key name and reg type
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueryValueKey( __in HANDLE KeyHandle, 
								 __in PUNICODE_STRING ValueName,
								 __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
								 __out_opt PVOID KeyValueInformation,
								 __in ULONG Length,
								 __out PULONG ResultLength);
						
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs key opening
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567014(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567014(v=vs.85).aspx
//	Process :
//		logs KeyHandle, desired access and key name
//////////////////////////////////////////////////////////////////////////////////////////////////////////////			
NTSTATUS Hooked_NtOpenKey(__out PHANDLE KeyHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//  	Logs key opening
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567015(v=vs.85).aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567015(v=vs.85).aspx
//	Process :
//		logs KeyHandle, desired access, key name and OpenOptions
//////////////////////////////////////////////////////////////////////////////////////////////////////////////							  
NTSTATUS Hooked_NtOpenKeyEx(__out PHANDLE KeyHandle,
						    __in ACCESS_MASK DesiredAccess,
						    __in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG OpenOptions);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs key creation and/or key opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566425(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566425(v=vs.85).aspx
//	Process :
//		Copies KeyHandle, desired access, TitleIndex, Class, CreateOptions, Disposition and reg key name
//////////////////////////////////////////////////////////////////////////////////////////////////////////////							
NTSTATUS Hooked_NtCreateKey(__out PHANDLE KeyHandle,
							__in ACCESS_MASK DesiredAccess,
							__in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG TitleIndex,
							__in_opt PUNICODE_STRING Class,
							__in ULONG CreateOptions,
							__out_opt PULONG Disposition);
						  
#endif