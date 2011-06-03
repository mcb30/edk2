/** @file
*  Header defining Versatile Express constants (Base addresses, sizes, flags)
*
*  Copyright (c) 2011, ARM Limited. All rights reserved.
*
*  This program and the accompanying materials
*  are licensed and made available under the terms and conditions of the BSD License
*  which accompanies this distribution.  The full text of the license may be found at
*  http://opensource.org/licenses/bsd-license.php
*
*  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
*  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
*
**/

#ifndef __VEXPRESSMOTHERBOARD_H_
#define __VEXPRESSMOTHERBOARD_H_

#include <ArmPlatform.h>

/***********************************************************************************
// Motherboard memory-mapped peripherals
************************************************************************************/

// Define MotherBoard SYS flags offsets (from ARM_VE_BOARD_PERIPH_BASE)
#define ARM_VE_SYS_LED_REG                        (ARM_VE_BOARD_PERIPH_BASE + 0x00008)
#define ARM_VE_SYS_FLAGS_REG                      (ARM_VE_BOARD_PERIPH_BASE + 0x00030)
#define ARM_VE_SYS_FLAGS_SET_REG                  (ARM_VE_BOARD_PERIPH_BASE + 0x00030)
#define ARM_VE_SYS_FLAGS_CLR_REG                  (ARM_VE_BOARD_PERIPH_BASE + 0x00034)
#define ARM_VE_SYS_FLAGS_NV_REG                   (ARM_VE_BOARD_PERIPH_BASE + 0x00038)
#define ARM_VE_SYS_FLAGS_NV_SET_REG               (ARM_VE_BOARD_PERIPH_BASE + 0x00038)
#define ARM_VE_SYS_FLAGS_NV_CLR_REG               (ARM_VE_BOARD_PERIPH_BASE + 0x0003C)
#define ARM_VE_SYS_FLASH                          (ARM_VE_BOARD_PERIPH_BASE + 0x0004C)
#define ARM_VE_SYS_PROCID0_REG                    (ARM_VE_BOARD_PERIPH_BASE + 0x00084)
#define ARM_VE_SYS_PROCID1_REG                    (ARM_VE_BOARD_PERIPH_BASE + 0x00088)
#define ARM_VE_SYS_CFGDATA_REG                    (ARM_VE_BOARD_PERIPH_BASE + 0x000A0)
#define ARM_VE_SYS_CFGCTRL_REG                    (ARM_VE_BOARD_PERIPH_BASE + 0x000A4)
#define ARM_VE_SYS_CFGSTAT_REG                    (ARM_VE_BOARD_PERIPH_BASE + 0x000A8)

// SP810 Controller
#define SP810_CTRL_BASE                           (ARM_VE_BOARD_PERIPH_BASE + 0x01000)

// Uart0
#define PL011_CONSOLE_UART_BASE                   (ARM_VE_BOARD_PERIPH_BASE + 0x09000)

// SP805 Watchdog on motherboard
#define SP805_WDOG_MOTHERBOARD_BASE               (ARM_VE_BOARD_PERIPH_BASE + 0x0F000)

// SP804 Timer Bases
#define SP804_TIMER0_BASE                         (ARM_VE_BOARD_PERIPH_BASE + 0x11000)
#define SP804_TIMER1_BASE                         (ARM_VE_BOARD_PERIPH_BASE + 0x11020)
#define SP804_TIMER2_BASE                         (ARM_VE_BOARD_PERIPH_BASE + 0x12000)
#define SP804_TIMER3_BASE                         (ARM_VE_BOARD_PERIPH_BASE + 0x12020)

// PL031 Real Time Clock
#define PL031_RTC_BASE                            (ARM_VE_BOARD_PERIPH_BASE + 0x17000)

// PL111 Colour LCD Controller - motherboard
#define PL111_CLCD_MOTHERBOARD_BASE               (ARM_VE_BOARD_PERIPH_BASE + 0x1F000)
#define PL111_CLCD_MOTHERBOARD_VIDEO_MODE_OSC_ID  1

// VRAM offset for the PL111 Colour LCD Controller on the motherboard
#define VRAM_MOTHERBOARD_BASE                     (ARM_VE_SMB_PERIPH_BASE   + 0x00000)

#define SYS_PROC_ID_UNSUPPORTED                   0xFF
#define SYS_PROC_ID_CORTEX_A9                     0x0C

//
// Sites where the peripheral is fitted
//
#define ARM_VE_UNSUPPORTED                        ~0
#define ARM_VE_MOTHERBOARD_SITE                   0
#define ARM_VE_DAUGHTERBOARD_1_SITE               1
#define ARM_VE_DAUGHTERBOARD_2_SITE               2

#endif /* VEXPRESSMOTHERBOARD_H_ */
