/** @file XBLRamDump.c
  Top-Level Logic for XBLRamDump.c
  
  Copyright (c) 2014-2015, Qualcomm Technologies, Inc. All rights reserved.

**/

/*=============================================================================
                              EDIT HISTORY

 when       who     what, where, why
 --------   ---     -----------------------------------------------------------
 09/10/15   kpa     Use dcache_flush_region instead of mmu_flush_cache.
 08/24/15   ck      Added logic to enter PBL EDL if ramdump is not allowed
 09/30/14   ck      efs_boot_initialize must be called before any storage functions
 08/08/14   ck      Added boot_shared_functions_consumer.h
 07/28/14   ck      Initial revision

=============================================================================*/

#include "boot_target.h"
#include "boot_dload_debug.h"
#include "boot_raw_partition_ramdump.h"
#include "boot_sd_ramdump.h"
#include "boot_sahara.h"
#include "boot_extern_efs_interface.h"
#include "boot_shared_functions_consumer.h"
#include "pm_pon.h"

static int letv_get_sahara_mode(void)
{
    uint8 reg;
    pm_pon_get_spare_reg_data(0, PM_PON_DVDD_RB_SPARE, &reg);
    reg = (reg & 0x02) >> 1;

    return reg;
}

VOID XBLRamDumpMain( VOID )
{
  struct boot_sahara_interface* sbl_sahara_interface = NULL;

  /* Inform the shared functions library where the shared functions table is
     and verify that it was initialized by the producer. */
  boot_shared_functions_init();


  /* boot_efs_boot_initialize must be called before any storage functionality.
     Even if it was called in XBLLoader it is safe to call it again here. */
  boot_efs_boot_initialize();


  /* If download mode is not available then no need to continue and spin.
     Enter PBL EDL in this scenario. */
  if(!dload_mem_debug_supported())
  {
    boot_dload_transition_pbl_forced_dload();
  }


 /*-----------------------------------------------------------------------
   * Ram dump to eMMC raw partition, this function will reset device 
   * after successful dump collection if cookie is set 
   *----------------------------------------------------------------------*/
  boot_ram_dump_to_raw_parition();
  
  
#ifdef FEATURE_BOOT_RAMDUMPS_TO_SD_CARD   
  /*----------------------------------------------------------------------
   * Take the Ramdumps to SD card if  cookie file is
   *   present in SD card 
   *---------------------------------------------------------------------*/
  boot_ram_dumps_to_sd_card();
#endif /*FEATURE_BOOT_RAMDUMPS_TO_SD_CARD*/  

  if (letv_get_sahara_mode() == 0) {
    boot_hw_reset(BOOT_HARD_RESET_TYPE);
  }

  /* Enter Sahara */

  /* Get Sahara interface */
  sbl_sahara_interface = sbl_sahara_get_interface();
  BL_VERIFY(sbl_sahara_interface != NULL, BL_ERR_NULL_PTR);
  
  /* Set Sahara mode to memory debug */
  sbl_sahara_interface->sahara_mode = SAHARA_MODE_MEMORY_DEBUG;
  
  /* Flush the cache before calling into sahara so that all data is flushed to memory */  
  dcache_flush_region((void *)SCL_SBL1_DDR_ZI_BASE, SCL_SBL1_DDR_ZI_SIZE);
  dcache_flush_region((void *)SCL_SBL1_OCIMEM_DATA_BASE, SCL_SBL1_OCIMEM_DATA_SIZE);
  
  /* Enter Sahara */
  boot_sahara_entry(sbl_sahara_interface);
}

