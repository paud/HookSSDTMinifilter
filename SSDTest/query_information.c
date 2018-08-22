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
//	File :		query_information.c
//	Abstract :	Query information function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	  
//
/////////////////////////////////////////////////////////////////////////////

#include "struct.h"
#include "query_information.h"
#include "main.h"

PVOID QuerySystemInformation (__in SYSTEM_INFORMATION_CLASS SystemInformationClass) 
{
	NTSTATUS Status;
	PVOID pSystemInformation = NULL;
	ULONG SystemInformationLength = 0;
	ULONG ReturnLength = 0;

	// Retrieve the requested structure size
	if (ZwQuerySystemInformation (SystemInformationClass, &SystemInformationLength, 0, &SystemInformationLength) != STATUS_INFO_LENGTH_MISMATCH) {
		Dbg ("ZwQuerySystemInformation should return STATUS_INFO_LENGTH_MISMATCH");
		return NULL;
	}

	// Allocate the memory for the requested structure
	if ((pSystemInformation = ExAllocatePoolWithTag (NonPagedPool, SystemInformationLength, 'QSI')) == NULL) {
		Dbg ("ExAllocatePoolWithTag failed");
		return NULL;
	}

	// Fill the requested structure
	if (!NT_SUCCESS (ZwQuerySystemInformation (SystemInformationClass, pSystemInformation, SystemInformationLength, &ReturnLength))) {
		Dbg ("ZwQuerySystemInformation should return NT_SUCCESS");
		ExFreePool (pSystemInformation);   
		return NULL;
	}

	// Check the structure size requested with the one returned by ZwQuerySystemInformation
	if (ReturnLength != SystemInformationLength) {
		Dbg ("Warning : ZwQuerySystemInformation ReturnLength is different than SystemInformationLength");
	}

	return pSystemInformation;
}

PVOID QueryProcessInformation(__in HANDLE Process, 
							  __in PROCESSINFOCLASS ProcessInformationClass, 
							  __in DWORD ProcessInformationLength) 
{
	NTSTATUS Status;
	PVOID pProcessInformation = NULL;
	ULONG ReturnLength = 0;

	// Allocate the memory for the requested structure
	if ((pProcessInformation = ExAllocatePoolWithTag (NonPagedPool, ProcessInformationLength, 'QPI')) == NULL) {
		Dbg ("ExAllocatePoolWithTag failed");
		return NULL;
	}

	// Fill the requested structure
	if (!NT_SUCCESS (ZwQueryInformationProcess (Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
		Dbg ("ZwQueryInformationProcess should return NT_SUCCESS");
		ExFreePool (pProcessInformation);   
		return NULL;
	}

	// Check the requested structure size with the one returned by ZwQueryInformationProcess
	if (ReturnLength != ProcessInformationLength) {
		Dbg ("Warning : ZwQueryInformationProcess ReturnLength is different than ProcessInformationLength");
	}

	return pProcessInformation;
}