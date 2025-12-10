#pragma once

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_generated_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_generated_arm64.h"
#endif

// we apply the preserve_access_index attribute
#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

/* Represent old kernfs node present in 5.4 kernels and older
 * Used for RHEL7 support
 */
union kernfs_node_id {
	struct {
		/*
		 * blktrace will export this struct as a simplified 'struct
		 * fid' (which is a big data struction), so userspace can use
		 * it to find kernfs node. The layout must match the first two
		 * fields of 'struct fid' exactly.
		 */
		u32 ino;
		u32 generation;
	};
	u64 id;
};

/* Represent old kernfs node with the kernfs_node_id
 * union to read the id in 5.4 kernels and older
 */
struct kernfs_node___old {
	union kernfs_node_id id;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif
