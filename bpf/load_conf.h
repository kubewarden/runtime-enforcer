#pragma once

// read only config written by user space at load time
struct load_conf {
	__u64 cgrp_fs_magic;                              /* Cgroupv1 or Cgroupv2 */
	__u32 cgrpv1_subsys_idx;                          /* tracked cgroupv1 subsystem state index*/
	__u32 cgrp_hierarchy; /* tracked hierarchy ID */  // todo!: not sure this is useful
	__u8 debug_mode;                                  /* Enable debug mode */
	__u8 pad[7];
};  // All fields aligned so no 'packed' attribute.

const volatile struct load_conf load_time_config = {0};
