/*=============================================================================

                         Boot Downloader 
 
GENERAL DESCRIPTION
  This file contains the code to initiate a reset of the chip and
  transition to the into the downloader.

EXTERNALIZED FUNCTIONS
  boot_dload_transition
  boot_dload_entry
  boot_dload_is_dload_mode_set

INITIALIZATION AND SEQUENCING REQUIREMENTS
  None

Copyright 2014 - 2016 by Qualcomm Technologies, Inc.  All Rights Reserved.
=============================================================================*/


/*=============================================================================

                            EDIT HISTORY FOR MODULE

  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.


when       who     what, where, why
--------   ---     ------------------------------------------------------------
01/06/16   kedara  Update chip version detection logic
11/17/15   kedara  code cleanup
07/09/15   kedara  relocate GET_CHIP_VERSION macro to boot_target.h.
03/10/15   kedara  Go to emergency dload mode if USB D+ line is grounded.
02/19/15   kedara  Updates dload cookie masks for version 1.
09/03/14   ck      Refactored to match new pbl_sbl_shared header file
07/28/14   ck      Removed USB logic as it is not used in Loader, only in RamDump
07/18/14   kedara  Update TCSR_BOOT_MISC_DETECT register name.
05/12/14   kedara  Update register names for 8996 compilation.
03/18/14   ck      Updated boot_hw_reset calls as they now take a reset type parameter
01/10/14   ck      Removed static download mode variable as the BOOT_MISC_DETECT register should be used
01/06/14   ck      Modified boot_dload_transition_pbl_forced_dload to use BOOT_MISC_DETECT register
01/06/14   ck      Modified boot_dload_entry, boot_dload_is_dload_mode_set, and boot_dload_set_cookie
                   logic to reference BOOT_MISC_DETECT register for dload cookie
08/07/13   aus     Added support to check for D+ line to force PBL download mode
02/14/13   dh      Add a static variable to indicate if dload mode is set 
12/07/12   kedara  revert boot_dload_entry updates to not retain dload status.
11/16/12   dh      Add boot_dload_set_cookie
10/26/12   kedara  Update boot_dload_entry to retain dload status.
06/26/12   dh      Remove FEATURE_DLOAD_HW_RESET_DETECT from boot_dload_check
02/28/12   dh      use boot_shared_imem_cookie_ptr to refer to dload magic number
09/13/11   dh      Include boot_cache_mmu.h instead of cache_mmu.h
05/02/11   dh      flush the data cache after resetting dload magic number 
12/22/10   dxiang  Add support to read the dload cookie 
07/02/10   aus     Reordered the function calls
05/07/10   aus     Added dload support for Fusion
02/03/10   niting  Moved to DLOAD_ID_ADDR to cust file.
12/08/09   msm     Fixes made for HOSTDL
10/15/09   tbg     Corrected API for FEATURE_DLOAD_HW_RESET_DETECT
08/23/08   dhaval  Fix DLOAD transition from AMSS to BOOT with JTAG connected.
05/08/07   ty      Modify structure saved to IRAM to include serial number
03/26/07   tbg     Added support for FEATURE_DLOAD_HW_RESET_DETECT
01/24/07   ly      Add HS_USB support
10/13/05   sd      Initial revision.

=============================================================================*/


/*=============================================================================

                            INCLUDE FILES FOR MODULE

=============================================================================*/
#include "boot_dload.h"
#include "boot_cache_mmu.h"
#include "boothw_target.h"
#include "boot_shared_imem_cookie.h"
#include "boot_extern_qusb_edl_interface.h"
#include <stdbool.h>

/*=============================================================================

            LOCAL DEFINITIONS AND DECLARATIONS FOR MODULE

This section contains local definitions for constants, macros, types,
variables and other items needed by this module.

=============================================================================*/

/*=============================================================================
   
                              FUNCTION DEFINITIONS

=============================================================================*/

/*===========================================================================

FUNCTION  BOOT_DLOAD_ENTRY

DESCRIPTION
  Determines if identifier is present in BOOT_MISC_DETECT register to tell 
  SBL to enter the boot downloader, instead on continuing the normal boot 
  process.
  
DEPENDENCIES
  Data in BOOT_MISC_DETECT (or GCC_WIND_DOWN_TIMER for v1) is retained across a reset.
  
RETURN VALUE
  TRUE indicates downloader should be entered.

SIDE EFFECTS
  None

===========================================================================*/
boolean boot_dload_entry( void )
{
  /* Check to see if download ID is present. 
     For Bear family the cookie is now stored in the register BOOT_MISC_DETECT 
     and not IMEM.  This register is shared with PBL and maybe others.  Only
     one bit is needed and the mask SBL_BOOT_MISC_DETECT_MASK defines what
     section of the register SBL owns. */

  uint32 dload_flag =0x0;
  boolean status = FALSE;
  
  do
  {
    /* Check Chip version */
    if(CHIP_VERSION_V3_AND_ABOVE)
    {
      dload_flag = HWIO_TCSR_TCSR_BOOT_MISC_DETECT_INM(SBL_DLOAD_MODE_BIT_MASK);
      if (dload_flag)
      {
        /* Clear ID so the downloader is not entered again on the next boot. */
        HWIO_TCSR_TCSR_BOOT_MISC_DETECT_OUTM(SBL_DLOAD_MODE_BIT_MASK,0);
        status = TRUE;
        break;
      }
    }
    else
    {
      /*chip version 1 or 2*/
      dload_flag = HWIO_GCC_WIND_DOWN_TIMER_INM(SBL_DLOAD_MODE_BIT_MASK_V1)>>SBL_DLOAD_MODE_BIT_MASK_V1_SHFT;
  
      if (dload_flag)
      {
        /* Clear ID so the downloader is not entered again on the next boot. 
            Bits 20 to 23 are reserved for XBL dload cookies/
        */
        HWIO_OUT(GCC_WIND_DOWN_TIMER,(HWIO_IN(GCC_WIND_DOWN_TIMER) & 0xFF0FFFFF));

        status = TRUE;
        break;
      }
    }
  }while(0);

  return status;

} /* boot_dload_entry() */

/*===========================================================================

FUNCTION  BOOT_DLOAD_IS_DLOAD_MODE_SET

DESCRIPTION
  This function shall return if the dload cookie is set or not for the
  phone to go in download mode.

DEPENDENCIES
  Data in BOOT_MISC_DETECT (or GCC_WIND_DOWN_TIMER for v1) is retained across a reset.
  
RETURN VALUE
  TRUE indicates cookies are set
  FALSE cookies are not set
  
SIDE EFFECTS
  None

===========================================================================*/
boolean boot_dload_is_dload_mode_set( void )
{
  boolean status = FALSE;
  do
  {
    /* Check Chip version */
    if(CHIP_VERSION_V3_AND_ABOVE)
    {
      /* Evaluate dload mode bit that is in the BOOT_MISC_DETECT register */
      if (HWIO_TCSR_TCSR_BOOT_MISC_DETECT_INM(SBL_DLOAD_MODE_BIT_MASK))
      {
        status=TRUE;
        break;
      }
    }
    else
    {
      /* Chip version 1 or 2 */
      /* Evaluate dload mode bit that is in the GCC_WIND_DOWN_TIMER register */
      if (HWIO_GCC_WIND_DOWN_TIMER_INM(SBL_DLOAD_MODE_BIT_MASK_V1)>>SBL_DLOAD_MODE_BIT_MASK_V1_SHFT)
      {
        status = TRUE;
        break;
      }  
    }
  }while(0);
  
  return status;
}


/*===========================================================================
**  Function :  boot_dload_set_cookie
** ==========================================================================
*/
/*!
* 
* @brief
*   Set the SBL dload mode cookie
**        
* @par Dependencies
*  None
*   
*/
void boot_dload_set_cookie()
{
  /* Check Chip version */
  if(CHIP_VERSION_V3_AND_ABOVE)
  {
    HWIO_TCSR_TCSR_BOOT_MISC_DETECT_OUTM(SBL_DLOAD_MODE_BIT_MASK,
                                    SBL_DLOAD_MODE_BIT_MASK);
  }
  else
  {
    HWIO_OUT(GCC_WIND_DOWN_TIMER,(HWIO_IN(GCC_WIND_DOWN_TIMER) | SBL_DLOAD_MODE_BIT_MASK_V1));
  }
}


/*=============================================================================

**  Function :  boot_dload_transition_pbl_forced_dload

** ==========================================================================
*/
/*!
* 
* @brief
*   This function sets the magic numbers for PBL to detect and enter forced
*   download mode.  It then calls the target specific function to trigger a
*   system reset.
* 
* @par Dependencies
*   None
*   
* @retval
*   None
* 
* @par Side Effects
*   Set's PBL magic numbers to enter forced download, resets target, never to
*   return.
* 
*/
void boot_dload_transition_pbl_forced_dload( void )
{

  /* PBL uses the last four bits of BOOT_MISC_DETECT to trigger forced download.
     Preserve the other bits of the register. */
  uint32 register_value = 0;

  /* Check Chip version */
  if(CHIP_VERSION_V3_AND_ABOVE)
  {
    register_value =HWIO_TCSR_TCSR_BOOT_MISC_DETECT_INM(HWIO_TCSR_TCSR_BOOT_MISC_DETECT_RMSK);
     /* Clear the PBL masked area and then apply HS_USB value */
    register_value &= ~(FORCE_DLOAD_MASK);
    register_value |= FORCE_DLOAD_BOOT_USB;
     /* Write the new value back out to the register */
    HWIO_TCSR_TCSR_BOOT_MISC_DETECT_OUTM(FORCE_DLOAD_MASK,
                                register_value);
  }
  else
  {
    /* Chip version 1 or 2 */
    register_value = HWIO_GCC_WIND_DOWN_TIMER_INM(HWIO_GCC_WIND_DOWN_TIMER_RMSK);
    
    /* Clear the PBL masked area and then apply HS_USB value */
    register_value &= ~(FORCE_DLOAD_MASK_V1);
    /*Bits 16 through 19 are reserved for bootrom EDL bits*/
    register_value |= (FORCE_DLOAD_BOOT_USB << 16);
    
    /* Write the new value back out to the register */
    HWIO_OUT(GCC_WIND_DOWN_TIMER,register_value);      
      
  }
 
  
  boot_hw_reset(BOOT_WARM_RESET_TYPE);
} /* boot_dload_transition_pbl_forced_dload() */


/*===========================================================================

**  Function :  boot_init_for_dload

** ==========================================================================
*/
/*!
* 
* @brief
*   Wrapper function that calls smem_boot_debug_init().
*  
* @param[in] bl_shared_data Pointer to shared data structure
*  
* @par Dependencies
*   None
*   
* @retval
*   None                                                               
* 
* @par Side Effects
*   None
* 
*/
void boot_init_for_dload
( 
   bl_shared_data_type *bl_shared_data 
)
{
#ifdef BOOT_DISABLE_DCACHE_IN_DLOAD
  /* Disable cache and MMU */
  cache_mmu_disable();
#endif /* BOOT_DISABLE_DCACHE_IN_DLOAD */
 
} /* boot_smem_init_for_dload() */

/*===========================================================================

**  Function :  boot_dload_check

** ==========================================================================
*/
/*!
* 
* @brief
*   This function will check to see if the downloader should be entered
*   for QPST download, and enter the downloader if directed to.
*  
* @param[in] bl_shared_data Pointer to the shared data 
*
* @par Dependencies
*   Download ID must be present in IRAM if downloader is to be entered.
* 
* @retval
*   None
* 
* @par Side Effects
*   Boot may be halted and QPST downloader entered.
* 
*/
void boot_dload_check
( 
  bl_shared_data_type *bl_shared_data 
)
{
  /* Check whether USB D+ line is grounded. If it is, then enter
     PBL Download mode 
  */
  if(boot_qusb_pbl_dload_check())
  {
     boot_dload_transition_pbl_forced_dload();
  }

  /* Determine if the downloader should be entered at this time,
     instead of continuing with the normal boot process. */
  if ( boot_dload_entry( ) == TRUE )
  {
    /* Check the UEFI ram dump cookie, we enter download mode
       only if UEFI ram dump cookie is NOT set*/
    if ( !( boot_shared_imem_cookie_ptr != NULL &&
            boot_shared_imem_cookie_ptr->uefi_ram_dump_magic == 
            UEFI_CRASH_DUMP_MAGIC_NUM ) )
    {
      /* Enter downloader for QPST */  
      sbl_dload_entry();
    }
  }

  if (is_warm_reset())
  {
    boot_hw_reset(BOOT_HARD_RESET_TYPE);
  }
} /* boot_dload_check() */

#include <string.h>
#include <stdio.h>
#include "boot_extern_pmic_interface.h"
boolean is_warm_reset(void)
{
	uint64 regs;
	/* error, treat as force warm reset */
	if (PM_ERR_FLAG__SUCCESS != boot_pm_dev_get_power_on_reason(0, &regs))
		return TRUE;

	/* pon_pm_reason_status_t */
	return ((regs & 0xffff0000) != 0);
}
