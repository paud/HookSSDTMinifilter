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
//	File :		comm.h
//	Abstract :	Comm header for zer0m0n
//	Revision : 	v1.1
//	Author :	Adrien Chevalier, Nicolas Correia, Cyril Moreau
//	Email :		contact.zer0m0n@gmail.com
//	Date :		2016-07-05	 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __COMM_H
#define __COMM_H

#include <fltkernel.h>

#define IOCTL_PROC_MALWARE \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
		
#define IOCTL_PROC_TO_HIDE \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CUCKOO_PATH \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the filter port
//
//	Parameters : 
//		__in PDRIVER_OBJECT pDriverObject :	    Data structure used to represent the driver.
//
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the minifilter initialization has been well completed
//	Process :
//		Register filter / Creates communication port
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS InitMinifilter(__in PDRIVER_OBJECT);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication connection callback.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Process :
//		Sets the global variable "clientPort" with the supplied client port communication.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltConnectCallback(__in PFLT_PORT ClientPort, 
						 __in PVOID ServerPortCookie, 
					     __in PVOID ConnectionContext, 
						 __in ULONG SizeOfContext, 
						 __out PVOID* ConnectionPortCookie);
		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication disconnection callback.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Process :
//		We don't use it but this callback has to be declared anyway.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID FltDisconnectCallback(__in PVOID ConnectionCookie);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//		Unregisters the minifilter.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//	Process :
//		Closes filter communication port and unregisters the filter.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltUnregister(__in FLT_FILTER_UNLOAD_FLAGS flags);
		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		DEVICE_IO_CONTROL IRP handler. Used for getting informations from Cuckoo.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Process :
//		Handles IRP_MJ_CONTROL IOCTLs.
//		Retrieves PIDs to monitor / hide.  
// 		Retrieve the cuckoo path.
//		Destroys the driver symbolic name for security (we don't want someone to interact with the driver).
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_DeviceControl(__in PDEVICE_OBJECT pDeviceObject,
							 __in PIRP pIrp);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		NTSTATUS : STATUS_NOT_SUPPORTED
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_NotSupported(__in PDEVICE_OBJECT pDeviceObject,
                            __in PIRP pIrp);
							
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Generates a message using "pid", "sig_func" and "parameter" and sends it back to userland through
//		a filter communication port.
//	Parameters :
//		_in_opt_ ULONG pid :		Process ID from which the logs are produced.
//		_in_ ULONG sig_func :	    Function signature 
//		_in_opt_ PWCHAR parameter :	Function args.
//	Return value :
//		NTSTATUS : FltSendMessage return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS SendLogs(__in ULONG pid, 
				  __in ULONG sig_func, 
				  __in PWCHAR parameter);

#endif
