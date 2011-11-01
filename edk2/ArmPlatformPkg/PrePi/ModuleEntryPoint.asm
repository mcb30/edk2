//
//  Copyright (c) 2011, ARM Limited. All rights reserved.
//
//  This program and the accompanying materials
//  are licensed and made available under the terms and conditions of the BSD License
//  which accompanies this distribution.  The full text of the license may be found at
//  http://opensource.org/licenses/bsd-license.php
//
//  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
//  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//
//

#include <AsmMacroIoLib.h>
#include <Base.h>
#include <Library/PcdLib.h>
#include <AutoGen.h>

  INCLUDE AsmMacroIoLib.inc
  
  IMPORT  CEntryPoint
  IMPORT  ArmReadMpidr
  IMPORT  ArmIsMpCore
  EXPORT  _ModuleEntryPoint

  PRESERVE8
  AREA    PrePiCoreEntryPoint, CODE, READONLY
  
StartupAddr        DCD      CEntryPoint

_ModuleEntryPoint
  // Get ID of this CPU in Multicore system
  bl    ArmReadMpidr
  LoadConstantToReg (FixedPcdGet32(PcdArmPrimaryCoreMask), r1)
  and   r5, r0, r1

_SetSVCMode
  // Enter SVC mode, Disable FIQ and IRQ
  mov     r1, #0x13|0x80|0x40
  msr     CPSR_c, r1

// Check if we can install the stack at the top of the System Memory or if we need
// to install the stacks at the bottom of the Firmware Device (case the FD is located
// at the top of the DRAM)
_SetupStackPosition
  // Compute Top of System Memory
  LoadConstantToReg (FixedPcdGet32(PcdSystemMemoryBase), r1)
  LoadConstantToReg (FixedPcdGet32(PcdSystemMemorySize), r2)
  add   r1, r1, r2      // r1 = SystemMemoryTop = PcdSystemMemoryBase + PcdSystemMemorySize

  // Calculate Top of the Firmware Device
  LoadConstantToReg (FixedPcdGet32(PcdFdBaseAddress), r2)
  LoadConstantToReg (FixedPcdGet32(PcdFdSize), r3)
  add   r3, r3, r2      // r4 = FdTop = PcdFdBaseAddress + PcdFdSize

  // UEFI Memory Size (stacks are allocated in this region)
  LoadConstantToReg (FixedPcdGet32(PcdSystemMemoryUefiRegionSize), r4)

  //
  // Reserve the memory for the UEFI region (contain stacks on its top)
  //

  // Calculate how much space there is between the top of the Firmware and the Top of the System Memory
  subs	r0, r1, r3	// r0 = SystemMemoryTop - FdTop
  bmi	_SetupStack	// Jump if negative (FdTop > SystemMemoryTop). Case when the PrePi is in XIP memory outside of the DRAM
  cmp	r0, r4
  bge	_SetupStack

  // Case the top of stacks is the FdBaseAddress
  mov	r1, r2

_SetupStack
  // r1 contains the top of the stack (and the UEFI Memory)

  // Calculate the Base of the UEFI Memory
  sub   r6, r1, r4

_GetStackBase
  // Compute Base of Normal stacks for CPU Cores
  // Is it MpCore system
  bl    ArmIsMpCore
  cmp   r0, #0
  // Case it is not an MP Core system. Just setup the primary core
  beq   _SetupUnicoreStack

_GetStackBaseMpCore
  // Stack for the primary core = PrimaryCoreStack
  LoadConstantToReg (FixedPcdGet32(PcdCPUCorePrimaryStackSize), r2)
  sub   r7, r1, r2
  // Stack for the secondary core = Number of Cluster * (4 Core per cluster) * SecondaryStackSize
  LoadConstantToReg (FixedPcdGet32(PcdClusterCount), r2)
  lsl   r2, r2, #2
  LoadConstantToReg (FixedPcdGet32(PcdCPUCoreSecondaryStackSize), r3)
  mul   r2, r2, r3
  sub   r7, r7, r2

  // The top of the Mpcore Stacks is in r1
  // The base of the MpCore Stacks is in r7

  // Is it the Primary Core ?
  LoadConstantToReg (FixedPcdGet32(PcdArmPrimaryCore), r4)
  cmp   r5, r4
  beq   _SetupPrimaryCoreStack

_SetupSecondaryCoreStack
  // Base of the stack for the secondary cores is in r7

  // Get the position of the cores (ClusterId * 4) + CoreId
  GetCorePositionInStack(r0, r5, r4)
  // The stack starts at the top of the stack region. Add '1' to the Core Position to get the top of the stack
  add   r0, r0, #1
  // Get the offset for the Secondary Stack
  mul   r0, r0, r3
  add   sp, r7, r0

  bne   _PrepareArguments

_SetupPrimaryCoreStack
  // The top of the Mpcore Stacks is in r1
  LoadConstantToReg (FixedPcdGet32(PcdPeiGlobalVariableSize), r2)

  // The reserved space for global variable must be 8-bytes aligned for pushing
  // 64-bit variable on the stack
  SetPrimaryStack (r1, r2, r3)

_SetGlobals
  // Set all the PrePi global variables to 0
  mov   r3, sp
  mov   r2, #0x0
_InitGlobals
  str   r2, [r3], #4
  cmp   r3, r1
  bne   _InitGlobals


_PrepareArguments
  mov   r0, r5
  mov   r1, r6
  mov   r2, r7
  mov   r3, sp

  // Move sec startup address into a data register
  // Ensure we're jumping to FV version of the code (not boot remapped alias)
  ldr   r4, StartupAddr

  // Jump to PrePiCore C code
  //    r0 = MpId
  //    r1 = UefiMemoryBase
  //    r2 = StacksBase
  //    r3 = GlobalVariableBase
  blx   r4

_NeverReturn
  b _NeverReturn

_SetupUnicoreStack
  // The top of the Unicore Stack is in r1
  LoadConstantToReg (FixedPcdGet32(PcdPeiGlobalVariableSize), r2)
  LoadConstantToReg (FixedPcdGet32(PcdCPUCorePrimaryStackSize), r3)

  // Calculate the bottom of the primary stack (StackBase)
  sub   r7, r1, r3

  // The reserved space for global variable must be 8-bytes aligned for pushing
  // 64-bit variable on the stack
  SetPrimaryStack (r1, r2, r3)

  b _SetGlobals

  END
