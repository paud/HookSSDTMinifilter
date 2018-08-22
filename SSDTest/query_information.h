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
//  File :      query_information.h
//  Abstract :  Query information header for zer0m0n
//  Revision :  v1.1
//  Author :    Adrien Chevalier, Nicolas Correia, Cyril Moreau
//  Email :     contact.zer0m0n@gmail.com
//  Date :      2016-07-05      
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __QUERY_INFORMATION_H
#define __QUERY_INFORMATION_H

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

#include "hooking.h"

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QuerySystemInformation is a wrapper around ZwQuerySystemInformation.
// 		Return a pointer to a structure information of the current process, depending of the SystemInformationClass requested
//
//	Parameters :
//		IN SYSTEM_INFORMATION_CLASS SystemInformationClass		The information class requested
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQuerySystemInformation depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQuerySystemInformation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID QuerySystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QueryProcessInformation is a wrapper around ZwQueryInformationProcess.
// 		Return a pointer to a structure information of the current process, depending of the ProcessInformationClass requested
//
//	Parameters :
//		IN HANDLE Process								The process targeted
//		IN PROCESSINFOCLASS ProcessInformationClass		The information class requested
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQueryInformationProcess depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQueryInformationProcess
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID QueryProcessInformation(__in HANDLE Process, 
							  __in PROCESSINFOCLASS ProcessInformationClass, 
							  __in DWORD ProcessInformationLength);

#endif