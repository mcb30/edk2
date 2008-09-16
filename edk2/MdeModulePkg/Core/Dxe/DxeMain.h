/** @file
  The internal header file includes the common header files, defines
  internal structure and functions used by DxeCore module.

Copyright (c) 2006 - 2008, Intel Corporation. <BR>
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _DXE_MAIN_H_
#define _DXE_MAIN_H_



#include <PiDxe.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/GuidedSectionExtraction.h>
#include <Protocol/DevicePath.h>
#include <Protocol/Runtime.h>
#include <Protocol/LoadFile.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Protocol/Variable.h>
#include <Protocol/Timer.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Bds.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/WatchdogTimer.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/StatusCode.h>
#include <Protocol/Decompress.h>
#include <Protocol/LoadPe32Image.h>
#include <Protocol/FirmwareVolumeDispatch.h>
#include <Protocol/Security.h>
#include <Protocol/Ebc.h>
#include <Protocol/Reset.h>
#include <Protocol/Cpu.h>
#include <Protocol/Metronome.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Protocol/Capsule.h>
#include <Protocol/BusSpecificDriverOverride.h>
#include <Protocol/Performance.h>
#include <Protocol/TcgService.h>
#include <Protocol/TcgPlatform.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Guid/HobList.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/FileInfo.h>
#include <Guid/Apriori.h>
#include <Guid/DxeServices.h>
#include <Guid/MemoryAllocationHob.h>
#include <Guid/EventLegacyBios.h>
#include <Guid/EventGroup.h>


#include <Library/DxeCoreEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/PerformanceLib.h>
#include <Library/UefiDecompressLib.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/ReportStatusCodeLib.h>

#include "DebugImageInfo.h"
#include "Library.h"
#include "FwVolBlock.h"
#include "FwVolDriver.h"
#include "Gcd.h"
#include "Imem.h"
#include "Image.h"
#include "Event.h"
#include "Handle.h"

//
// attributes for reserved memory before it is promoted to system memory
//
#define EFI_MEMORY_PRESENT      0x0100000000000000ULL
#define EFI_MEMORY_INITIALIZED  0x0200000000000000ULL
#define EFI_MEMORY_TESTED       0x0400000000000000ULL

//
// range for memory mapped port I/O on IPF
//
#define EFI_MEMORY_PORT_IO  0x4000000000000000ULL


///
/// EFI_DEP_REPLACE_TRUE - Used to dynamically patch the dependecy expression
///                        to save time.  A EFI_DEP_PUSH is evauated one an
///                        replaced with EFI_DEP_REPLACE_TRUE. If PI spec's Vol 2
///                        Driver Execution Environment Core Interface use 0xff
///                        as new DEPEX opcode. EFI_DEP_REPLACE_TRUE should be
///                        defined to a new value that is not conflicting with PI spec.
///
#define EFI_DEP_REPLACE_TRUE  0xff

///
/// Define the initial size of the dependency expression evaluation stack
///
#define DEPEX_STACK_SIZE_INCREMENT  0x1000

typedef struct {
  EFI_GUID                    *ProtocolGuid;
  VOID                        **Protocol;
  EFI_EVENT                   Event;
  VOID                        *Registration;
  BOOLEAN                     Present;
} ARCHITECTURAL_PROTOCOL_ENTRY;

//
// DXE Dispatcher Data structures
//

#define KNOWN_HANDLE_SIGNATURE  EFI_SIGNATURE_32('k','n','o','w')
typedef struct {
  UINTN           Signature;
  LIST_ENTRY      Link;         // mFvHandleList
  EFI_HANDLE      Handle;
} KNOWN_HANDLE;


#define EFI_CORE_DRIVER_ENTRY_SIGNATURE EFI_SIGNATURE_32('d','r','v','r')
typedef struct {
  UINTN                           Signature;
  LIST_ENTRY                      Link;             // mDriverList

  LIST_ENTRY                      ScheduledLink;    // mScheduledQueue

  EFI_HANDLE                      FvHandle;
  EFI_GUID                        FileName;
  EFI_DEVICE_PATH_PROTOCOL        *FvFileDevicePath;
  EFI_FIRMWARE_VOLUME2_PROTOCOL   *Fv;

  VOID                            *Depex;
  UINTN                           DepexSize;

  BOOLEAN                         Before;
  BOOLEAN                         After;
  EFI_GUID                        BeforeAfterGuid;

  BOOLEAN                         Dependent;
  BOOLEAN                         Unrequested;
  BOOLEAN                         Scheduled;
  BOOLEAN                         Untrusted;
  BOOLEAN                         Initialized;
  BOOLEAN                         DepexProtocolError;

  EFI_HANDLE                      ImageHandle;

} EFI_CORE_DRIVER_ENTRY;

//
//The data structure of GCD memory map entry
//
#define EFI_GCD_MAP_SIGNATURE  EFI_SIGNATURE_32('g','c','d','m')
typedef struct {
  UINTN                 Signature;
  LIST_ENTRY            Link;
  EFI_PHYSICAL_ADDRESS  BaseAddress;
  UINT64                EndAddress;
  UINT64                Capabilities;
  UINT64                Attributes;
  EFI_GCD_MEMORY_TYPE   GcdMemoryType;
  EFI_GCD_IO_TYPE       GcdIoType;
  EFI_HANDLE            ImageHandle;
  EFI_HANDLE            DeviceHandle;
} EFI_GCD_MAP_ENTRY;

//
// DXE Core Global Variables
//
extern EFI_SYSTEM_TABLE                         *gDxeCoreST;
extern EFI_RUNTIME_SERVICES                     *gDxeCoreRT;
extern EFI_DXE_SERVICES                         *gDxeCoreDS;
extern EFI_HANDLE                               gDxeCoreImageHandle;

extern EFI_DECOMPRESS_PROTOCOL                  gEfiDecompress;

extern EFI_RUNTIME_ARCH_PROTOCOL                *gRuntime;
extern EFI_CPU_ARCH_PROTOCOL                    *gCpu;
extern EFI_WATCHDOG_TIMER_ARCH_PROTOCOL         *gWatchdogTimer;
extern EFI_METRONOME_ARCH_PROTOCOL              *gMetronome;
extern EFI_TIMER_ARCH_PROTOCOL                  *gTimer;
extern EFI_SECURITY_ARCH_PROTOCOL               *gSecurity;
extern EFI_BDS_ARCH_PROTOCOL                    *gBds;

extern EFI_TPL                                  gEfiCurrentTpl;

extern EFI_GUID                                 *gDxeCoreFileName;
extern EFI_LOADED_IMAGE_PROTOCOL                *gDxeCoreLoadedImage;

extern EFI_MEMORY_TYPE_INFORMATION              gMemoryTypeInformation[EfiMaxMemoryType + 1];

extern BOOLEAN                                  gDispatcherRunning;
extern EFI_RUNTIME_ARCH_PROTOCOL                gRuntimeTemplate;

//
// Service Initialization Functions
//



/**
  Called to initialize the pool.

**/
VOID
CoreInitializePool (
  VOID
  );


/**
  Called to initialize the memory map and add descriptors to
  the current descriptor list.
  The first descriptor that is added must be general usable
  memory as the addition allocates heap.

  @param  Type                   The type of memory to add
  @param  Start                  The starting address in the memory range Must be
                                 page aligned
  @param  NumberOfPages          The number of pages in the range
  @param  Attribute              Attributes of the memory to add

  @return None.  The range is added to the memory map

**/
VOID
CoreAddMemoryDescriptor (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                NumberOfPages,
  IN UINT64                Attribute
  );


/**
  Release memory lock on mGcdMemorySpaceLock.

**/
VOID
CoreReleaseGcdMemoryLock (
  VOID
  );


/**
  Acquire memory lock on mGcdMemorySpaceLock.

**/
VOID
CoreAcquireGcdMemoryLock (
  VOID
  );


/**
  External function. Initializes the GCD and memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the GCD map and the
  memory map, so memory allocations and resource allocations can be made.  The first
  part of this function can not depend on any memory services until at least one
  memory descriptor is provided to the memory services.  Then the memory services
  can be used to intialize the GCD map.

  @param  HobStart               The start address of the HOB.
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            Memory services successfully initialized.

**/
EFI_STATUS
CoreInitializeMemoryServices (
  IN  VOID                  **HobStart,
  OUT EFI_PHYSICAL_ADDRESS  *MemoryBaseAddress,
  OUT UINT64                *MemoryLength
  );



/**
  External function. Initializes the GCD and memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the GCD map and the
  memory map, so memory allocations and resource allocations can be made.  The first
  part of this function can not depend on any memory services until at least one
  memory descriptor is provided to the memory services.  Then the memory services
  can be used to intialize the GCD map. The HobStart will be relocated to a pool
  buffer.

  @param  HobStart               The start address of the HOB
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            GCD services successfully initialized.

**/
EFI_STATUS
CoreInitializeGcdServices (
  IN OUT VOID              **HobStart,
  IN EFI_PHYSICAL_ADDRESS  MemoryBaseAddress,
  IN UINT64                MemoryLength
  );


/**
  Initializes "event" support and populates parts of the System and Runtime Table.

  @retval EFI_SUCCESS            Always return success

**/
EFI_STATUS
CoreInitializeEventServices (
  VOID
  );


/**
  Add the Image Services to EFI Boot Services Table and install the protocol
  interfaces for this image.

  @param  HobStart                The HOB to initialize

  @return Status code.

**/
EFI_STATUS
CoreInitializeImageServices (
  IN  VOID *HobStart
  );


/**
  Creates an event that is fired everytime a Protocol of a specific type is installed.

**/
VOID
CoreNotifyOnArchProtocolInstallation (
  VOID
  );


/**
  Return TRUE if all AP services are availible.

  @retval EFI_SUCCESS    All AP services are available
  @retval EFI_NOT_FOUND  At least one AP service is not available

**/
EFI_STATUS
CoreAllEfiServicesAvailable (
  VOID
  );


/**
  Calcualte the 32-bit CRC in a EFI table using the service provided by the
  gRuntime service.

  @param  Hdr                    Pointer to an EFI standard header

**/
VOID
CalculateEfiHdrCrc (
  IN  OUT EFI_TABLE_HEADER    *Hdr
  );


/**
  Called by the platform code to process a tick.

  @param  Duration               The number of 100ns elasped since the last call
                                 to TimerTick

**/
VOID
EFIAPI
CoreTimerTick (
  IN UINT64   Duration
  );


/**
  Initialize the dispatcher. Initialize the notification function that runs when
  an FV2 protocol is added to the system.

**/
VOID
CoreInitializeDispatcher (
  VOID
  );


/**
  This is the POSTFIX version of the dependency evaluator.  This code does
  not need to handle Before or After, as it is not valid to call this
  routine in this case. The SOR is just ignored and is a nop in the grammer.
  POSTFIX means all the math is done on top of the stack.

  @param  DriverEntry           DriverEntry element to update.

  @retval TRUE                  If driver is ready to run.
  @retval FALSE                 If driver is not ready to run or some fatal error
                                was found.

**/
BOOLEAN
CoreIsSchedulable (
  IN  EFI_CORE_DRIVER_ENTRY   *DriverEntry
  );


/**
  Preprocess dependency expression and update DriverEntry to reflect the
  state of  Before, After, and SOR dependencies. If DriverEntry->Before
  or DriverEntry->After is set it will never be cleared. If SOR is set
  it will be cleared by CoreSchedule(), and then the driver can be
  dispatched.

  @param  DriverEntry           DriverEntry element to update .

  @retval EFI_SUCCESS           It always works.

**/
EFI_STATUS
CorePreProcessDepex (
  IN  EFI_CORE_DRIVER_ENTRY   *DriverEntry
  );



/**
  Terminates all boot services.

  @param  ImageHandle            Handle that identifies the exiting image.
  @param  MapKey                 Key to the latest memory map.

  @retval EFI_SUCCESS            Boot Services terminated
  @retval EFI_INVALID_PARAMETER  MapKey is incorrect.

**/
EFI_STATUS
EFIAPI
CoreExitBootServices (
  IN EFI_HANDLE   ImageHandle,
  IN UINTN        MapKey
  );


/**
  Make sure the memory map is following all the construction rules,
  it is the last time to check memory map error before exit boot services.

  @param  MapKey                 Memory map key

  @retval EFI_INVALID_PARAMETER  Memory map not consistent with construction
                                 rules.
  @retval EFI_SUCCESS            Valid memory map.

**/
EFI_STATUS
CoreTerminateMemoryMap (
  IN UINTN          MapKey
  );


/**
  Signals all events in the EventGroup.

  @param  EventGroup             The list to signal

**/
VOID
CoreNotifySignalList (
  IN EFI_GUID     *EventGroup
  );



/**
  Boot Service called to add, modify, or remove a system configuration table from
  the EFI System Table.

  @param  Guid           Pointer to the GUID for the entry to add, update, or
                         remove
  @param  Table          Pointer to the configuration table for the entry to add,
                         update, or remove, may be NULL.

  @return EFI_SUCCESS               Guid, Table pair added, updated, or removed.
  @return EFI_INVALID_PARAMETER     Input GUID not valid.
  @return EFI_NOT_FOUND             Attempted to delete non-existant entry
  @return EFI_OUT_OF_RESOURCES      Not enough memory available

**/
EFI_STATUS
EFIAPI
CoreInstallConfigurationTable (
  IN EFI_GUID *Guid,
  IN VOID     *Table
  );



/**
  Raise the task priority level to the new level.
  High level is implemented by disabling processor interrupts.

  @param  NewTpl  New task priority level

  @return The previous task priority level

**/
EFI_TPL
EFIAPI
CoreRaiseTpl (
  IN EFI_TPL      NewTpl
  );



/**
  Lowers the task priority to the previous value.   If the new
  priority unmasks events at a higher priority, they are dispatched.

  @param  NewTpl  New, lower, task priority

**/
VOID
EFIAPI
CoreRestoreTpl (
  IN EFI_TPL NewTpl
  );



/**
  Introduces a fine-grained stall.

  @param  Microseconds           The number of microseconds to stall execution.

  @retval EFI_SUCCESS            Execution was stalled for at least the requested
                                 amount of microseconds.
  @retval EFI_NOT_AVAILABLE_YET  gMetronome is not available yet

**/
EFI_STATUS
EFIAPI
CoreStall (
  IN UINTN            Microseconds
  );



/**
  Sets the system's watchdog timer.

  @param  Timeout         The number of seconds to set the watchdog timer to.
                          A value of zero disables the timer.
  @param  WatchdogCode    The numeric code to log on a watchdog timer timeout
                          event. The firmware reserves codes 0x0000 to 0xFFFF.
                          Loaders and operating systems may use other timeout
                          codes.
  @param  DataSize        The size, in bytes, of WatchdogData.
  @param  WatchdogData    A data buffer that includes a Null-terminated Unicode
                          string, optionally followed by additional binary data.
                          The string is a description that the call may use to
                          further indicate the reason to be logged with a
                          watchdog event.

  @return EFI_SUCCESS               Timeout has been set
  @return EFI_NOT_AVAILABLE_YET     WatchdogTimer is not available yet
  @return EFI_UNSUPPORTED           System does not have a timer (currently not used)
  @return EFI_DEVICE_ERROR          Could not complete due to hardware error

**/
EFI_STATUS
EFIAPI
CoreSetWatchdogTimer (
  IN UINTN    Timeout,
  IN UINT64   WatchdogCode,
  IN UINTN    DataSize,
  IN CHAR16   *WatchdogData OPTIONAL
  );



/**
  Wrapper function to CoreInstallProtocolInterfaceNotify.  This is the public API which
  Calls the private one which contains a BOOLEAN parameter for notifications

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added

  @return Status code

**/
EFI_STATUS
EFIAPI
CoreInstallProtocolInterface (
  IN OUT EFI_HANDLE     *UserHandle,
  IN EFI_GUID           *Protocol,
  IN EFI_INTERFACE_TYPE InterfaceType,
  IN VOID               *Interface
  );


/**
  Installs a protocol interface into the boot services environment.

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added
  @param  Notify                 indicates whether notify the notification list
                                 for this protocol

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Protocol interface successfully installed

**/
EFI_STATUS
CoreInstallProtocolInterfaceNotify (
  IN OUT EFI_HANDLE     *UserHandle,
  IN EFI_GUID           *Protocol,
  IN EFI_INTERFACE_TYPE InterfaceType,
  IN VOID               *Interface,
  IN BOOLEAN            Notify
  );



/**
  Installs a list of protocol interface into the boot services environment.
  This function calls InstallProtocolInterface() in a loop. If any error
  occures all the protocols added by this function are removed. This is
  basically a lib function to save space.

  @param  Handle                 The handle to install the protocol handlers on,
                                 or NULL if a new handle is to be allocated
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to InstallProtocolInterface(). All the
                                 protocols are added to Handle.

  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_SUCCESS            Protocol interfaces successfully installed.

**/
EFI_STATUS
EFIAPI
CoreInstallMultipleProtocolInterfaces (
  IN OUT EFI_HANDLE           *Handle,
  ...
  );



/**
  Uninstalls a list of protocol interface in the boot services environment.
  This function calls UnisatllProtocolInterface() in a loop. This is
  basically a lib function to save space.

  @param  Handle                 The handle to uninstall the protocol
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to UninstallProtocolInterface(). All
                                 the protocols are added to Handle.

  @return Status code

**/
EFI_STATUS
EFIAPI
CoreUninstallMultipleProtocolInterfaces (
  IN EFI_HANDLE           Handle,
  ...
  );



/**
  Reinstall a protocol interface on a device handle.  The OldInterface for Protocol is replaced by the NewInterface.

  @param  UserHandle             Handle on which the interface is to be
                                 reinstalled
  @param  Protocol               The numeric ID of the interface
  @param  OldInterface           A pointer to the old interface
  @param  NewInterface           A pointer to the new interface

  @retval EFI_SUCCESS            The protocol interface was installed
  @retval EFI_NOT_FOUND          The OldInterface on the handle was not found
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value

**/
EFI_STATUS
EFIAPI
CoreReinstallProtocolInterface (
  IN EFI_HANDLE     UserHandle,
  IN EFI_GUID       *Protocol,
  IN VOID           *OldInterface,
  IN VOID           *NewInterface
  );



/**
  Uninstalls all instances of a protocol:interfacer from a handle.
  If the last protocol interface is remove from the handle, the
  handle is freed.

  @param  UserHandle             The handle to remove the protocol handler from
  @param  Protocol               The protocol, of protocol:interface, to remove
  @param  Interface              The interface, of protocol:interface, to remove

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Protocol interface successfully uninstalled.

**/
EFI_STATUS
EFIAPI
CoreUninstallProtocolInterface (
  IN EFI_HANDLE       UserHandle,
  IN EFI_GUID         *Protocol,
  IN VOID             *Interface
  );



/**
  Queries a handle to determine if it supports a specified protocol.

  @param  UserHandle             The handle being queried.
  @param  Protocol               The published unique identifier of the protocol.
  @param  Interface              Supplies the address where a pointer to the
                                 corresponding Protocol Interface is returned.

  @return The requested protocol interface for the handle

**/
EFI_STATUS
EFIAPI
CoreHandleProtocol (
  IN EFI_HANDLE       UserHandle,
  IN EFI_GUID         *Protocol,
  OUT VOID            **Interface
  );



/**
  Locates the installed protocol handler for the handle, and
  invokes it to obtain the protocol interface. Usage information
  is registered in the protocol data base.

  @param  UserHandle             The handle to obtain the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  Interface              The location to return the protocol interface
  @param  ImageHandle            The handle of the Image that is opening the
                                 protocol interface specified by Protocol and
                                 Interface.
  @param  ControllerHandle       The controller handle that is requiring this
                                 interface.
  @param  Attributes             The open mode of the protocol interface
                                 specified by Handle and Protocol.

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Get the protocol interface.

**/
EFI_STATUS
EFIAPI
CoreOpenProtocol (
  IN  EFI_HANDLE                UserHandle,
  IN  EFI_GUID                  *Protocol,
  OUT VOID                      **Interface OPTIONAL,
  IN  EFI_HANDLE                ImageHandle,
  IN  EFI_HANDLE                ControllerHandle,
  IN  UINT32                    Attributes
  );



/**
  Return information about Opened protocols in the system

  @param  UserHandle             The handle to close the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  EntryBuffer            A pointer to a buffer of open protocol
                                 information in the form of
                                 EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.
  @param  EntryCount             Number of EntryBuffer entries

**/
EFI_STATUS
EFIAPI
CoreOpenProtocolInformation (
  IN  EFI_HANDLE                          UserHandle,
  IN  EFI_GUID                            *Protocol,
  OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer,
  OUT UINTN                               *EntryCount
  );



/**
  Closes a protocol on a handle that was opened using OpenProtocol().

  @param  UserHandle             The handle for the protocol interface that was
                                 previously opened with OpenProtocol(), and is
                                 now being closed.
  @param  Protocol               The published unique identifier of the protocol.
                                 It is the caller's responsibility to pass in a
                                 valid GUID.
  @param  AgentHandle            The handle of the agent that is closing the
                                 protocol interface.
  @param  ControllerHandle       If the agent that opened a protocol is a driver
                                 that follows the EFI Driver Model, then this
                                 parameter is the controller handle that required
                                 the protocol interface. If the agent does not
                                 follow the EFI Driver Model, then this parameter
                                 is optional and may be NULL.

  @retval EFI_SUCCESS            The protocol instance was closed.
  @retval EFI_INVALID_PARAMETER  Handle, AgentHandle or ControllerHandle is not a
                                 valid EFI_HANDLE.
  @retval EFI_NOT_FOUND          Can not find the specified protocol or
                                 AgentHandle.

**/
EFI_STATUS
EFIAPI
CoreCloseProtocol (
  IN  EFI_HANDLE                UserHandle,
  IN  EFI_GUID                  *Protocol,
  IN  EFI_HANDLE                AgentHandle,
  IN  EFI_HANDLE                ControllerHandle
  );



/**
  Retrieves the list of protocol interface GUIDs that are installed on a handle in a buffer allocated
  from pool.

  @param  UserHandle             The handle from which to retrieve the list of
                                 protocol interface GUIDs.
  @param  ProtocolBuffer         A pointer to the list of protocol interface GUID
                                 pointers that are installed on Handle.
  @param  ProtocolBufferCount    A pointer to the number of GUID pointers present
                                 in ProtocolBuffer.

  @retval EFI_SUCCESS            The list of protocol interface GUIDs installed
                                 on Handle was returned in ProtocolBuffer. The
                                 number of protocol interface GUIDs was returned
                                 in ProtocolBufferCount.
  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_INVALID_PARAMETER  Handle is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER  ProtocolBuffer is NULL.
  @retval EFI_INVALID_PARAMETER  ProtocolBufferCount is NULL.
  @retval EFI_OUT_OF_RESOURCES   There is not enough pool memory to store the
                                 results.

**/
EFI_STATUS
EFIAPI
CoreProtocolsPerHandle (
  IN EFI_HANDLE       UserHandle,
  OUT EFI_GUID        ***ProtocolBuffer,
  OUT UINTN           *ProtocolBufferCount
  );



/**
  Add a new protocol notification record for the request protocol.

  @param  Protocol               The requested protocol to add the notify
                                 registration
  @param  Event                  The event to signal
  @param  Registration           Returns the registration record

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully returned the registration record
                                 that has been added

**/
EFI_STATUS
EFIAPI
CoreRegisterProtocolNotify (
  IN EFI_GUID       *Protocol,
  IN EFI_EVENT      Event,
  OUT  VOID         **Registration
  );



/**
  Locates the requested handle(s) and returns them in Buffer.

  @param  SearchType             The type of search to perform to locate the
                                 handles
  @param  Protocol               The protocol to search for
  @param  SearchKey              Dependant on SearchType
  @param  BufferSize             On input the size of Buffer.  On output the
                                 size of data returned.
  @param  Buffer                 The buffer to return the results in

  @retval EFI_BUFFER_TOO_SMALL   Buffer too small, required buffer size is
                                 returned in BufferSize.
  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully found the requested handle(s) and
                                 returns them in Buffer.

**/
EFI_STATUS
EFIAPI
CoreLocateHandle (
  IN EFI_LOCATE_SEARCH_TYPE   SearchType,
  IN EFI_GUID                 *Protocol   OPTIONAL,
  IN VOID                     *SearchKey  OPTIONAL,
  IN OUT UINTN                *BufferSize,
  OUT EFI_HANDLE              *Buffer
  );



/**
  Locates the handle to a device on the device path that best matches the specified protocol.

  @param  Protocol               The protocol to search for.
  @param  DevicePath             On input, a pointer to a pointer to the device
                                 path. On output, the device path pointer is
                                 modified to point to the remaining part of the
                                 devicepath.
  @param  Device                 A pointer to the returned device handle.

  @retval EFI_SUCCESS            The resulting handle was returned.
  @retval EFI_NOT_FOUND          No handles matched the search.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
EFI_STATUS
EFIAPI
CoreLocateDevicePath (
  IN EFI_GUID                       *Protocol,
  IN OUT EFI_DEVICE_PATH_PROTOCOL   **DevicePath,
  OUT EFI_HANDLE                    *Device
  );



/**
  Function returns an array of handles that support the requested protocol
  in a buffer allocated from pool. This is a version of CoreLocateHandle()
  that allocates a buffer for the caller.

  @param  SearchType             Specifies which handle(s) are to be returned.
  @param  Protocol               Provides the protocol to search by.    This
                                 parameter is only valid for SearchType
                                 ByProtocol.
  @param  SearchKey              Supplies the search key depending on the
                                 SearchType.
  @param  NumberHandles          The number of handles returned in Buffer.
  @param  Buffer                 A pointer to the buffer to return the requested
                                 array of  handles that support Protocol.

  @retval EFI_SUCCESS            The result array of handles was returned.
  @retval EFI_NOT_FOUND          No handles match the search.
  @retval EFI_OUT_OF_RESOURCES   There is not enough pool memory to store the
                                 matching results.
  @retval EFI_INVALID_PARAMETER  One or more paramters are not valid.

**/
EFI_STATUS
EFIAPI
CoreLocateHandleBuffer (
  IN EFI_LOCATE_SEARCH_TYPE       SearchType,
  IN EFI_GUID                     *Protocol OPTIONAL,
  IN VOID                         *SearchKey OPTIONAL,
  IN OUT UINTN                    *NumberHandles,
  OUT EFI_HANDLE                  **Buffer
  );



/**
  Return the first Protocol Interface that matches the Protocol GUID. If
  Registration is pasased in return a Protocol Instance that was just add
  to the system. If Retistration is NULL return the first Protocol Interface
  you find.

  @param  Protocol               The protocol to search for
  @param  Registration           Optional Registration Key returned from
                                 RegisterProtocolNotify()
  @param  Interface              Return the Protocol interface (instance).

  @retval EFI_SUCCESS            If a valid Interface is returned
  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_NOT_FOUND          Protocol interface not found

**/
EFI_STATUS
EFIAPI
CoreLocateProtocol (
  IN  EFI_GUID  *Protocol,
  IN  VOID      *Registration OPTIONAL,
  OUT VOID      **Interface
  );


/**
  return handle database key.


  @return Handle database key.

**/
UINT64
CoreGetHandleDatabaseKey (
  VOID
  );


/**
  Go connect any handles that were created or modified while a image executed.

  @param  Key                    The Key to show that the handle has been
                                 created/modified

**/
VOID
CoreConnectHandlesByKey (
  UINT64  Key
  );



/**
  Connects one or more drivers to a controller.

  @param  ControllerHandle                      Handle of the controller to be
                                                connected.
  @param  DriverImageHandle                     DriverImageHandle A pointer to an
                                                ordered list of driver image
                                                handles.
  @param  RemainingDevicePath                   RemainingDevicePath A pointer to
                                                the device path that specifies a
                                                child of the controller specified
                                                by ControllerHandle.
  @param  Recursive                             Whether the function would be
                                                called recursively or not.

  @return Status code.

**/
EFI_STATUS
EFIAPI
CoreConnectController (
  IN  EFI_HANDLE                ControllerHandle,
  IN  EFI_HANDLE                *DriverImageHandle    OPTIONAL,
  IN  EFI_DEVICE_PATH_PROTOCOL  *RemainingDevicePath  OPTIONAL,
  IN  BOOLEAN                   Recursive
  );



/**
  Disonnects a controller from a driver

  @param  ControllerHandle                      ControllerHandle The handle of
                                                the controller from which
                                                driver(s)  are to be
                                                disconnected.
  @param  DriverImageHandle                     DriverImageHandle The driver to
                                                disconnect from ControllerHandle.
  @param  ChildHandle                           ChildHandle The handle of the
                                                child to destroy.

  @retval EFI_SUCCESS                           One or more drivers were
                                                disconnected from the controller.
  @retval EFI_SUCCESS                           On entry, no drivers are managing
                                                ControllerHandle.
  @retval EFI_SUCCESS                           DriverImageHandle is not NULL,
                                                and on entry DriverImageHandle is
                                                not managing ControllerHandle.
  @retval EFI_INVALID_PARAMETER                 ControllerHandle is not a valid
                                                EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER                 DriverImageHandle is not NULL,
                                                and it is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER                 ChildHandle is not NULL, and it
                                                is not a valid EFI_HANDLE.
  @retval EFI_OUT_OF_RESOURCES                  There are not enough resources
                                                available to disconnect any
                                                drivers from ControllerHandle.
  @retval EFI_DEVICE_ERROR                      The controller could not be
                                                disconnected because of a device
                                                error.

**/
EFI_STATUS
EFIAPI
CoreDisconnectController (
  IN  EFI_HANDLE  ControllerHandle,
  IN  EFI_HANDLE  DriverImageHandle  OPTIONAL,
  IN  EFI_HANDLE  ChildHandle        OPTIONAL
  );



/**
  Allocates pages from the memory map.

  @param  Type                   The type of allocation to perform
  @param  MemoryType             The type of memory to turn the allocated pages
                                 into
  @param  NumberOfPages          The number of pages to allocate
  @param  Memory                 A pointer to receive the base allocated memory
                                 address

  @return Status. On success, Memory is filled in with the base address allocated
  @retval EFI_INVALID_PARAMETER  Parameters violate checking rules defined in
                                 spec.
  @retval EFI_NOT_FOUND          Could not allocate pages match the requirement.
  @retval EFI_OUT_OF_RESOURCES   No enough pages to allocate.
  @retval EFI_SUCCESS            Pages successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocatePages (
  IN EFI_ALLOCATE_TYPE      Type,
  IN EFI_MEMORY_TYPE        MemoryType,
  IN UINTN                  NumberOfPages,
  IN OUT EFI_PHYSICAL_ADDRESS  *Memory
  );



/**
  Frees previous allocated pages.

  @param  Memory                 Base address of memory being freed
  @param  NumberOfPages          The number of pages to free

  @retval EFI_NOT_FOUND          Could not find the entry that covers the range
  @retval EFI_INVALID_PARAMETER  Address not aligned
  @return EFI_SUCCESS         -Pages successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreePages (
  IN EFI_PHYSICAL_ADDRESS   Memory,
  IN UINTN                  NumberOfPages
  );



/**
  This function returns a copy of the current memory map. The map is an array of
  memory descriptors, each of which describes a contiguous block of memory.

  @param  MemoryMapSize          A pointer to the size, in bytes, of the
                                 MemoryMap buffer. On input, this is the size of
                                 the buffer allocated by the caller.  On output,
                                 it is the size of the buffer returned by the
                                 firmware  if the buffer was large enough, or the
                                 size of the buffer needed  to contain the map if
                                 the buffer was too small.
  @param  MemoryMap              A pointer to the buffer in which firmware places
                                 the current memory map.
  @param  MapKey                 A pointer to the location in which firmware
                                 returns the key for the current memory map.
  @param  DescriptorSize         A pointer to the location in which firmware
                                 returns the size, in bytes, of an individual
                                 EFI_MEMORY_DESCRIPTOR.
  @param  DescriptorVersion      A pointer to the location in which firmware
                                 returns the version number associated with the
                                 EFI_MEMORY_DESCRIPTOR.

  @retval EFI_SUCCESS            The memory map was returned in the MemoryMap
                                 buffer.
  @retval EFI_BUFFER_TOO_SMALL   The MemoryMap buffer was too small. The current
                                 buffer size needed to hold the memory map is
                                 returned in MemoryMapSize.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.

**/
EFI_STATUS
EFIAPI
CoreGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT UINTN                     *MapKey,
  OUT UINTN                     *DescriptorSize,
  OUT UINT32                    *DescriptorVersion
  );



/**
  Allocate pool of a particular type.

  @param  PoolType               Type of pool to allocate
  @param  Size                   The amount of pool to allocate
  @param  Buffer                 The address to return a pointer to the allocated
                                 pool

  @retval EFI_INVALID_PARAMETER  PoolType not valid
  @retval EFI_OUT_OF_RESOURCES   Size exceeds max pool size or allocation failed.
  @retval EFI_SUCCESS            Pool successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocatePool (
  IN EFI_MEMORY_TYPE  PoolType,
  IN UINTN            Size,
  OUT VOID            **Buffer
  );



/**
  Frees pool.

  @param  Buffer                 The allocated pool entry to free

  @retval EFI_INVALID_PARAMETER  Buffer is not a valid value.
  @retval EFI_SUCCESS            Pool successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreePool (
  IN VOID        *Buffer
  );



/**
  Loads an EFI image into memory and returns a handle to the image.

  @param  BootPolicy              If TRUE, indicates that the request originates
                                  from the boot manager, and that the boot
                                  manager is attempting to load FilePath as a
                                  boot selection.
  @param  ParentImageHandle       The caller's image handle.
  @param  FilePath                The specific file path from which the image is
                                  loaded.
  @param  SourceBuffer            If not NULL, a pointer to the memory location
                                  containing a copy of the image to be loaded.
  @param  SourceSize              The size in bytes of SourceBuffer.
  @param  ImageHandle             Pointer to the returned image handle that is
                                  created when the image is successfully loaded.

  @retval EFI_SUCCESS             The image was loaded into memory.
  @retval EFI_NOT_FOUND           The FilePath was not found.
  @retval EFI_INVALID_PARAMETER   One of the parameters has an invalid value.
  @retval EFI_UNSUPPORTED         The image type is not supported, or the device
                                  path cannot be parsed to locate the proper
                                  protocol for loading the file.
  @retval EFI_OUT_OF_RESOURCES    Image was not loaded due to insufficient
                                  resources.

**/
EFI_STATUS
EFIAPI
CoreLoadImage (
  IN BOOLEAN                    BootPolicy,
  IN EFI_HANDLE                 ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL   *FilePath,
  IN VOID                       *SourceBuffer   OPTIONAL,
  IN UINTN                      SourceSize,
  OUT EFI_HANDLE                *ImageHandle
  );



/**
  Unloads an image.

  @param  ImageHandle             Handle that identifies the image to be
                                  unloaded.

  @retval EFI_SUCCESS             The image has been unloaded.
  @retval EFI_UNSUPPORTED         The image has been sarted, and does not support
                                  unload.
  @retval EFI_INVALID_PARAMPETER  ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
CoreUnloadImage (
  IN EFI_HANDLE  ImageHandle
  );



/**
  Transfer control to a loaded image's entry point.

  @param  ImageHandle             Handle of image to be started.
  @param  ExitDataSize            Pointer of the size to ExitData
  @param  ExitData                Pointer to a pointer to a data buffer that
                                  includes a Null-terminated Unicode string,
                                  optionally followed by additional binary data.
                                  The string is a description that the caller may
                                  use to further indicate the reason for the
                                  image's exit.

  @retval EFI_INVALID_PARAMETER   Invalid parameter
  @retval EFI_OUT_OF_RESOURCES    No enough buffer to allocate
  @retval EFI_SUCCESS             Successfully transfer control to the image's
                                  entry point.

**/
EFI_STATUS
EFIAPI
CoreStartImage (
  IN EFI_HANDLE  ImageHandle,
  OUT UINTN      *ExitDataSize,
  OUT CHAR16     **ExitData  OPTIONAL
  );



/**
  Terminates the currently loaded EFI image and returns control to boot services.

  @param  ImageHandle             Handle that identifies the image. This
                                  parameter is passed to the image on entry.
  @param  Status                  The image's exit code.
  @param  ExitDataSize            The size, in bytes, of ExitData. Ignored if
                                  ExitStatus is EFI_SUCCESS.
  @param  ExitData                Pointer to a data buffer that includes a
                                  Null-terminated Unicode string, optionally
                                  followed by additional binary data. The string
                                  is a description that the caller may use to
                                  further indicate the reason for the image's
                                  exit.

  @retval EFI_INVALID_PARAMETER   Image handle is NULL or it is not current
                                  image.
  @retval EFI_SUCCESS             Successfully terminates the currently loaded
                                  EFI image.
  @retval EFI_ACCESS_DENIED       Should never reach there.
  @retval EFI_OUT_OF_RESOURCES    Could not allocate pool

**/
EFI_STATUS
EFIAPI
CoreExit (
  IN EFI_HANDLE  ImageHandle,
  IN EFI_STATUS  Status,
  IN UINTN       ExitDataSize,
  IN CHAR16      *ExitData  OPTIONAL
  );



/**
  Creates a general-purpose event structure.

  @param  Type                   The type of event to create and its mode and
                                 attributes
  @param  NotifyTpl              The task priority level of event notifications
  @param  NotifyFunction         Pointer to the events notification function
  @param  NotifyContext          Pointer to the notification functions context;
                                 corresponds to parameter "Context" in the
                                 notification function
  @param  Event                  Pointer to the newly created event if the call
                                 succeeds; undefined otherwise

  @retval EFI_SUCCESS            The event structure was created
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value
  @retval EFI_OUT_OF_RESOURCES   The event could not be allocated

**/
EFI_STATUS
EFIAPI
CoreCreateEvent (
  IN UINT32                   Type,
  IN EFI_TPL                  NotifyTpl,
  IN EFI_EVENT_NOTIFY         NotifyFunction, OPTIONAL
  IN VOID                     *NotifyContext, OPTIONAL
  OUT EFI_EVENT               *Event
  );



/**
  Creates a general-purpose event structure

  @param  Type                   The type of event to create and its mode and
                                 attributes
  @param  NotifyTpl              The task priority level of event notifications
  @param  NotifyFunction         Pointer to the events notification function
  @param  NotifyContext          Pointer to the notification functions context;
                                 corresponds to parameter "Context" in the
                                 notification function
  @param  EventGroup             GUID for EventGroup if NULL act the same as
                                 gBS->CreateEvent().
  @param  Event                  Pointer to the newly created event if the call
                                 succeeds; undefined otherwise

  @retval EFI_SUCCESS            The event structure was created
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value
  @retval EFI_OUT_OF_RESOURCES   The event could not be allocated

**/
EFI_STATUS
EFIAPI
CoreCreateEventEx (
  IN UINT32                   Type,
  IN EFI_TPL                  NotifyTpl,
  IN EFI_EVENT_NOTIFY         NotifyFunction, OPTIONAL
  IN CONST VOID               *NotifyContext, OPTIONAL
  IN CONST EFI_GUID           *EventGroup,    OPTIONAL
  OUT EFI_EVENT               *Event
  );



/**
  Sets the type of timer and the trigger time for a timer event.

  @param  UserEvent              The timer event that is to be signaled at the
                                 specified time
  @param  Type                   The type of time that is specified in
                                 TriggerTime
  @param  TriggerTime            The number of 100ns units until the timer
                                 expires

  @retval EFI_SUCCESS            The event has been set to be signaled at the
                                 requested time
  @retval EFI_INVALID_PARAMETER  Event or Type is not valid

**/
EFI_STATUS
EFIAPI
CoreSetTimer (
  IN EFI_EVENT            UserEvent,
  IN EFI_TIMER_DELAY      Type,
  IN UINT64               TriggerTime
  );



/**
  Signals the event.  Queues the event to be notified if needed.

  @param  UserEvent              The event to signal .

  @retval EFI_INVALID_PARAMETER  Parameters are not valid.
  @retval EFI_SUCCESS            The event was signaled.

**/
EFI_STATUS
EFIAPI
CoreSignalEvent (
  IN EFI_EVENT    UserEvent
  );



/**
  Stops execution until an event is signaled.

  @param  NumberOfEvents         The number of events in the UserEvents array
  @param  UserEvents             An array of EFI_EVENT
  @param  UserIndex              Pointer to the index of the event which
                                 satisfied the wait condition

  @retval EFI_SUCCESS            The event indicated by Index was signaled.
  @retval EFI_INVALID_PARAMETER  The event indicated by Index has a notification
                                 function or Event was not a valid type
  @retval EFI_UNSUPPORTED        The current TPL is not TPL_APPLICATION

**/
EFI_STATUS
EFIAPI
CoreWaitForEvent (
  IN UINTN        NumberOfEvents,
  IN EFI_EVENT    *UserEvents,
  OUT UINTN       *UserIndex
  );



/**
  Closes an event and frees the event structure.

  @param  UserEvent              Event to close

  @retval EFI_INVALID_PARAMETER  Parameters are not valid.
  @retval EFI_SUCCESS            The event has been closed

**/
EFI_STATUS
EFIAPI
CoreCloseEvent (
  IN EFI_EVENT    UserEvent
  );



/**
  Check the status of an event.

  @param  UserEvent              The event to check

  @retval EFI_SUCCESS            The event is in the signaled state
  @retval EFI_NOT_READY          The event is not in the signaled state
  @retval EFI_INVALID_PARAMETER  Event is of type EVT_NOTIFY_SIGNAL

**/
EFI_STATUS
EFIAPI
CoreCheckEvent (
  IN EFI_EVENT        UserEvent
  );


/**
  Adds reserved memory, system memory, or memory-mapped I/O resources to the
  global coherency domain of the processor.

  @param  GcdMemoryType          Memory type of the memory space.
  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.
  @param  Capabilities           alterable attributes of the memory space.

  @retval EFI_SUCCESS            Merged this memory space into GCD map.

**/
EFI_STATUS
EFIAPI
CoreAddMemorySpace (
  IN EFI_GCD_MEMORY_TYPE   GcdMemoryType,
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                Capabilities
  );


/**
  Allocates nonexistent memory, reserved memory, system memory, or memorymapped
  I/O resources from the global coherency domain of the processor.

  @param  GcdAllocateType        The type of allocate operation
  @param  GcdMemoryType          The desired memory type
  @param  Alignment              Align with 2^Alignment
  @param  Length                 Length to allocate
  @param  BaseAddress            Base address to allocate
  @param  ImageHandle            The image handle consume the allocated space.
  @param  DeviceHandle           The device handle consume the allocated space.

  @retval EFI_INVALID_PARAMETER  Invalid parameter.
  @retval EFI_NOT_FOUND          No descriptor contains the desired space.
  @retval EFI_SUCCESS            Memory space successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocateMemorySpace (
  IN     EFI_GCD_ALLOCATE_TYPE  GcdAllocateType,
  IN     EFI_GCD_MEMORY_TYPE    GcdMemoryType,
  IN     UINTN                  Alignment,
  IN     UINT64                 Length,
  IN OUT EFI_PHYSICAL_ADDRESS   *BaseAddress,
  IN     EFI_HANDLE             ImageHandle,
  IN     EFI_HANDLE             DeviceHandle OPTIONAL
  );


/**
  Frees nonexistent memory, reserved memory, system memory, or memory-mapped
  I/O resources from the global coherency domain of the processor.

  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.

  @retval EFI_SUCCESS            Space successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreeMemorySpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );


/**
  Removes reserved memory, system memory, or memory-mapped I/O resources from
  the global coherency domain of the processor.

  @param  BaseAddress            Base address of the memory space.
  @param  Length                 Length of the memory space.

  @retval EFI_SUCCESS            Successfully remove a segment of memory space.

**/
EFI_STATUS
EFIAPI
CoreRemoveMemorySpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );


/**
  Retrieves the descriptor for a memory region containing a specified address.

  @param  BaseAddress            Specified start address
  @param  Descriptor             Specified length

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_SUCCESS            Successfully get memory space descriptor.

**/
EFI_STATUS
EFIAPI
CoreGetMemorySpaceDescriptor (
  IN  EFI_PHYSICAL_ADDRESS             BaseAddress,
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *Descriptor
  );


/**
  Modifies the attributes for a memory region in the global coherency domain of the
  processor.

  @param  BaseAddress            Specified start address
  @param  Length                 Specified length
  @param  Attributes             Specified attributes

  @retval EFI_SUCCESS            Successfully set attribute of a segment of
                                 memory space.

**/
EFI_STATUS
EFIAPI
CoreSetMemorySpaceAttributes (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                Attributes
  );


/**
  Returns a map of the memory resources in the global coherency domain of the
  processor.

  @param  NumberOfDescriptors    Number of descriptors.
  @param  MemorySpaceMap         Descriptor array

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Successfully get memory space map.

**/
EFI_STATUS
EFIAPI
CoreGetMemorySpaceMap (
  OUT UINTN                            *NumberOfDescriptors,
  OUT EFI_GCD_MEMORY_SPACE_DESCRIPTOR  **MemorySpaceMap
  );


/**
  Adds reserved I/O or I/O resources to the global coherency domain of the processor.

  @param  GcdIoType              IO type of the segment.
  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Merged this segment into GCD map.
  @retval EFI_INVALID_PARAMETER  Parameter not valid

**/
EFI_STATUS
EFIAPI
CoreAddIoSpace (
  IN EFI_GCD_IO_TYPE       GcdIoType,
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );


/**
  Allocates nonexistent I/O, reserved I/O, or I/O resources from the global coherency
  domain of the processor.

  @param  GcdAllocateType        The type of allocate operation
  @param  GcdIoType              The desired IO type
  @param  Alignment              Align with 2^Alignment
  @param  Length                 Length to allocate
  @param  BaseAddress            Base address to allocate
  @param  ImageHandle            The image handle consume the allocated space.
  @param  DeviceHandle           The device handle consume the allocated space.

  @retval EFI_INVALID_PARAMETER  Invalid parameter.
  @retval EFI_NOT_FOUND          No descriptor contains the desired space.
  @retval EFI_SUCCESS            IO space successfully allocated.

**/
EFI_STATUS
EFIAPI
CoreAllocateIoSpace (
  IN     EFI_GCD_ALLOCATE_TYPE  GcdAllocateType,
  IN     EFI_GCD_IO_TYPE        GcdIoType,
  IN     UINTN                  Alignment,
  IN     UINT64                 Length,
  IN OUT EFI_PHYSICAL_ADDRESS   *BaseAddress,
  IN     EFI_HANDLE             ImageHandle,
  IN     EFI_HANDLE             DeviceHandle OPTIONAL
  );


/**
  Frees nonexistent I/O, reserved I/O, or I/O resources from the global coherency
  domain of the processor.

  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Space successfully freed.

**/
EFI_STATUS
EFIAPI
CoreFreeIoSpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );


/**
  Removes reserved I/O or I/O resources from the global coherency domain of the
  processor.

  @param  BaseAddress            Base address of the segment.
  @param  Length                 Length of the segment.

  @retval EFI_SUCCESS            Successfully removed a segment of IO space.

**/
EFI_STATUS
EFIAPI
CoreRemoveIoSpace (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  );


/**
  Retrieves the descriptor for an I/O region containing a specified address.

  @param  BaseAddress            Specified start address
  @param  Descriptor             Specified length

  @retval EFI_INVALID_PARAMETER  Descriptor is NULL.
  @retval EFI_SUCCESS            Successfully get the IO space descriptor.

**/
EFI_STATUS
EFIAPI
CoreGetIoSpaceDescriptor (
  IN  EFI_PHYSICAL_ADDRESS         BaseAddress,
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR  *Descriptor
  );


/**
  Returns a map of the I/O resources in the global coherency domain of the processor.

  @param  NumberOfDescriptors    Number of descriptors.
  @param  IoSpaceMap             Descriptor array

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Successfully get IO space map.

**/
EFI_STATUS
EFIAPI
CoreGetIoSpaceMap (
  OUT UINTN                        *NumberOfDescriptors,
  OUT EFI_GCD_IO_SPACE_DESCRIPTOR  **IoSpaceMap
  );


/**
  This is the main Dispatcher for DXE and it exits when there are no more
  drivers to run. Drain the mScheduledQueue and load and start a PE
  image for each driver. Search the mDiscoveredList to see if any driver can
  be placed on the mScheduledQueue. If no drivers are placed on the
  mScheduledQueue exit the function. On exit it is assumed the Bds()
  will be called, and when the Bds() exits the Dispatcher will be called
  again.

  @retval EFI_ALREADY_STARTED   The DXE Dispatcher is already running
  @retval EFI_NOT_FOUND         No DXE Drivers were dispatched
  @retval EFI_SUCCESS           One or more DXE Drivers were dispatched

**/
EFI_STATUS
EFIAPI
CoreDispatcher (
  VOID
  );

/**
  Check every driver and locate a matching one. If the driver is found, the Unrequested
  state flag is cleared.

  @param  FirmwareVolumeHandle  The handle of the Firmware Volume that contains
                                the firmware  file specified by DriverName.
  @param  DriverName            The Driver name to put in the Dependent state.

  @retval EFI_SUCCESS           The DriverName was found and it's SOR bit was
                                cleared
  @retval EFI_NOT_FOUND         The DriverName does not exist or it's SOR bit was
                                not set.

**/
EFI_STATUS
EFIAPI
CoreSchedule (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  );


/**
  Convert a driver from the Untrused back to the Scheduled state.

  @param  FirmwareVolumeHandle  The handle of the Firmware Volume that contains
                                the firmware  file specified by DriverName.
  @param  DriverName            The Driver name to put in the Scheduled state

  @retval EFI_SUCCESS           The file was found in the untrusted state, and it
                                was promoted  to the trusted state.
  @retval EFI_NOT_FOUND         The file was not found in the untrusted state.

**/
EFI_STATUS
EFIAPI
CoreTrust (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  );


/**
  Helper function called as part of the code needed
  to allocate the proper sized buffer for various
  EFI interfaces.

  @param  Status                 Current status
  @param  Buffer                 Current allocated buffer, or NULL
  @param  BufferSize             Current buffer size needed

  @retval TRUE                   if the buffer was reallocated and the caller
                                 should try the API again.
  @retval FALSE                  buffer could not be allocated and the caller
                                 should not try the API again.

**/
BOOLEAN
CoreGrowBuffer (
  IN OUT EFI_STATUS   *Status,
  IN OUT VOID         **Buffer,
  IN UINTN            BufferSize
  );


/**
  This routine is the driver initialization entry point.  It initializes the
  libraries, and registers two notification functions.  These notification
  functions are responsible for building the FV stack dynamically.

  @param  ImageHandle           The image handle.
  @param  SystemTable           The system table.

  @retval EFI_SUCCESS           Function successfully returned.

**/
EFI_STATUS
EFIAPI
FwVolDriverInit (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  );


/**
  Entry point of the section extraction code. Initializes an instance of the
  section extraction interface and installs it on a new handle.

  @param  ImageHandle   A handle for the image that is initializing this driver
  @param  SystemTable   A pointer to the EFI system table

  @retval EFI_SUCCESS           Driver initialized successfully
  @retval EFI_OUT_OF_RESOURCES  Could not allocate needed resources

**/
EFI_STATUS
EFIAPI
InitializeSectionExtraction (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  );


/**
  This DXE service routine is used to process a firmware volume. In
  particular, it can be called by BDS to process a single firmware
  volume found in a capsule.

  @param  FvHeader               pointer to a firmware volume header
  @param  Size                   the size of the buffer pointed to by FvHeader
  @param  FVProtocolHandle       the handle on which a firmware volume protocol
                                 was produced for the firmware volume passed in.

  @retval EFI_OUT_OF_RESOURCES   if an FVB could not be produced due to lack of
                                 system resources
  @retval EFI_VOLUME_CORRUPTED   if the volume was corrupted
  @retval EFI_SUCCESS            a firmware volume protocol was produced for the
                                 firmware volume

**/
EFI_STATUS
EFIAPI
CoreProcessFirmwareVolume (
  IN VOID                             *FvHeader,
  IN UINTN                            Size,
  OUT EFI_HANDLE                      *FVProtocolHandle
  );

//
//Functions used during debug buils
//

/**
  Displays Architectural protocols that were not loaded and are required for DXE
  core to function.  Only used in Debug Builds.

**/
VOID
CoreDisplayMissingArchProtocols (
  VOID
  );


/**
  Traverse the discovered list for any drivers that were discovered but not loaded
  because the dependency experessions evaluated to false.

**/
VOID
CoreDisplayDiscoveredNotDispatched (
  VOID
  );


/**
  Place holder function until all the Boot Services and Runtime Services are
  available.

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg0 (
  VOID
  );


/**
  Place holder function until all the Boot Services and Runtime Services are
  available.

  @param  Arg1                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg1 (
  UINTN Arg1
  );


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg2 (
  UINTN Arg1,
  UINTN Arg2
  );


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg3 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3
  );


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg4 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4
  );


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined
  @param  Arg5                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg5 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4,
  UINTN Arg5
  );


/**
  Given a compressed source buffer, this function retrieves the size of the
  uncompressed buffer and the size of the scratch buffer required to decompress
  the compressed source buffer.

  The GetInfo() function retrieves the size of the uncompressed buffer and the
  temporary scratch buffer required to decompress the buffer specified by Source
  and SourceSize. If the size of the uncompressed buffer or the size of the
  scratch buffer cannot be determined from the compressed data specified by
  Source and SourceData, then EFI_INVALID_PARAMETER is returned. Otherwise, the
  size of the uncompressed buffer is returned in DestinationSize, the size of
  the scratch buffer is returned in ScratchSize, and EFI_SUCCESS is returned.
  The GetInfo() function does not have scratch buffer available to perform a
  thorough checking of the validity of the source data. It just retrieves the
  "Original Size" field from the beginning bytes of the source data and output
  it as DestinationSize. And ScratchSize is specific to the decompression
  implementation.

  @param  This               A pointer to the EFI_DECOMPRESS_PROTOCOL instance.
  @param  Source             The source buffer containing the compressed data.
  @param  SourceSize         The size, in bytes, of the source buffer.
  @param  DestinationSize    A pointer to the size, in bytes, of the
                             uncompressed buffer that will be generated when the
                             compressed buffer specified by Source and
                             SourceSize is decompressed.
  @param  ScratchSize        A pointer to the size, in bytes, of the scratch
                             buffer that is required to decompress the
                             compressed buffer specified by Source and
                             SourceSize.

  @retval EFI_SUCCESS        The size of the uncompressed data was returned in
                             DestinationSize and the size of the scratch buffer
                             was returned in ScratchSize.
  @retval EFI_INVALID_PARAMETER The size of the uncompressed data or the size of
                                the scratch buffer cannot be determined from the
                                compressed data specified by Source and
                                SourceSize.

**/
EFI_STATUS
EFIAPI
DxeMainUefiDecompressGetInfo (
  IN EFI_DECOMPRESS_PROTOCOL            *This,
  IN   VOID                             *Source,
  IN   UINT32                           SourceSize,
  OUT  UINT32                           *DestinationSize,
  OUT  UINT32                           *ScratchSize
  );


/**
  Decompresses a compressed source buffer.

  The Decompress() function extracts decompressed data to its original form.
  This protocol is designed so that the decompression algorithm can be
  implemented without using any memory services. As a result, the Decompress()
  Function is not allowed to call AllocatePool() or AllocatePages() in its
  implementation. It is the caller's responsibility to allocate and free the
  Destination and Scratch buffers.
  If the compressed source data specified by Source and SourceSize is
  sucessfully decompressed into Destination, then EFI_SUCCESS is returned. If
  the compressed source data specified by Source and SourceSize is not in a
  valid compressed data format, then EFI_INVALID_PARAMETER is returned.

  @param  This                A pointer to the EFI_DECOMPRESS_PROTOCOL instance.
  @param  Source              The source buffer containing the compressed data.
  @param  SourceSize          SourceSizeThe size of source data.
  @param  Destination         On output, the destination buffer that contains
                              the uncompressed data.
  @param  DestinationSize     The size of the destination buffer.  The size of
                              the destination buffer needed is obtained from
                              EFI_DECOMPRESS_PROTOCOL.GetInfo().
  @param  Scratch             A temporary scratch buffer that is used to perform
                              the decompression.
  @param  ScratchSize         The size of scratch buffer. The size of the
                              scratch buffer needed is obtained from GetInfo().

  @retval EFI_SUCCESS         Decompression completed successfully, and the
                              uncompressed buffer is returned in Destination.
  @retval EFI_INVALID_PARAMETER  The source buffer specified by Source and
                                 SourceSize is corrupted (not in a valid
                                 compressed format).

**/
EFI_STATUS
EFIAPI
DxeMainUefiDecompress (
  IN     EFI_DECOMPRESS_PROTOCOL          *This,
  IN     VOID                             *Source,
  IN     UINT32                           SourceSize,
  IN OUT VOID                             *Destination,
  IN     UINT32                           DestinationSize,
  IN OUT VOID                             *Scratch,
  IN     UINT32                           ScratchSize
  );

/**
  SEP member function.  This function creates and returns a new section stream
  handle to represent the new section stream.

  @param  SectionStreamLength    Size in bytes of the section stream.
  @param  SectionStream          Buffer containing the new section stream.
  @param  SectionStreamHandle    A pointer to a caller allocated UINTN that on
                                 output contains the new section stream handle.

  @retval EFI_SUCCESS            The section stream is created successfully.
  @retval EFI_OUT_OF_RESOURCES   memory allocation failed.
  @retval EFI_INVALID_PARAMETER  Section stream does not end concident with end
                                 of last section.

**/
EFI_STATUS
EFIAPI
OpenSectionStream (
  IN     UINTN                                     SectionStreamLength,
  IN     VOID                                      *SectionStream,
     OUT UINTN                                     *SectionStreamHandle
  );



/**
  SEP member function.  Retrieves requested section from section stream.

  @param  SectionStreamHandle   The section stream from which to extract the
                                requested section.
  @param  SectionType           A pointer to the type of section to search for.
  @param  SectionDefinitionGuid If the section type is EFI_SECTION_GUID_DEFINED,
                                then SectionDefinitionGuid indicates which of
                                these types of sections to search for.
  @param  SectionInstance       Indicates which instance of the requested
                                section to return.
  @param  Buffer                Double indirection to buffer.  If *Buffer is
                                non-null on input, then the buffer is caller
                                allocated.  If Buffer is NULL, then the buffer
                                is callee allocated.  In either case, the
                                requried buffer size is returned in *BufferSize.
  @param  BufferSize            On input, indicates the size of *Buffer if
                                *Buffer is non-null on input.  On output,
                                indicates the required size (allocated size if
                                callee allocated) of *Buffer.
  @param  AuthenticationStatus  A pointer to a caller-allocated UINT32 that
                                indicates the authentication status of the
                                output buffer. If the input section's
                                GuidedSectionHeader.Attributes field
                                has the EFI_GUIDED_SECTION_AUTH_STATUS_VALID
                                bit as clear, AuthenticationStatus must return
                                zero. Both local bits (19:16) and aggregate
                                bits (3:0) in AuthenticationStatus are returned
                                by ExtractSection(). These bits reflect the
                                status of the extraction operation. The bit
                                pattern in both regions must be the same, as
                                the local and aggregate authentication statuses
                                have equivalent meaning at this level. If the
                                function returns anything other than
                                EFI_SUCCESS, the value of *AuthenticationStatus
                                is undefined.

  @retval EFI_SUCCESS           Section was retrieved successfully
  @retval EFI_PROTOCOL_ERROR    A GUID defined section was encountered in the
                                section stream with its
                                EFI_GUIDED_SECTION_PROCESSING_REQUIRED bit set,
                                but there was no corresponding GUIDed Section
                                Extraction Protocol in the handle database.
                                *Buffer is unmodified.
  @retval EFI_NOT_FOUND         An error was encountered when parsing the
                                SectionStream.  This indicates the SectionStream
                                is not correctly formatted.
  @retval EFI_NOT_FOUND         The requested section does not exist.
  @retval EFI_OUT_OF_RESOURCES  The system has insufficient resources to process
                                the request.
  @retval EFI_INVALID_PARAMETER The SectionStreamHandle does not exist.
  @retval EFI_WARN_TOO_SMALL    The size of the caller allocated input buffer is
                                insufficient to contain the requested section.
                                The input buffer is filled and section contents
                                are truncated.

**/
EFI_STATUS
EFIAPI
GetSection (
  IN UINTN                                              SectionStreamHandle,
  IN EFI_SECTION_TYPE                                   *SectionType,
  IN EFI_GUID                                           *SectionDefinitionGuid,
  IN UINTN                                              SectionInstance,
  IN VOID                                               **Buffer,
  IN OUT UINTN                                          *BufferSize,
  OUT UINT32                                            *AuthenticationStatus
  );


/**
  SEP member function.  Deletes an existing section stream

  @param  StreamHandleToClose    Indicates the stream to close

  @retval EFI_SUCCESS            The section stream is closed sucessfully.
  @retval EFI_OUT_OF_RESOURCES   Memory allocation failed.
  @retval EFI_INVALID_PARAMETER  Section stream does not end concident with end
                                 of last section.

**/
EFI_STATUS
EFIAPI
CloseSectionStream (
  IN  UINTN                                     StreamHandleToClose
  );

#endif
