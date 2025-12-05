// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "load_conf.h"
#include "helpers.h"
#include "string_maps.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// https://nakryiko.com/posts/bpf-core-reference-guide/#linux-kernel-version
extern int LINUX_KERNEL_VERSION __kconfig;

/////////////////////////
// Cgroup tracker map
/////////////////////////

#define TRACKER_MAP_MAX_ENTRIES 65536

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TRACKER_MAP_MAX_ENTRIES);
	__type(key, __u64);   /* cgroup id */
	__type(value, __u64); /* tracker cgroup id */
} cgtracker_map SEC(".maps");

static __always_inline __u64 cgrp_get_tracker_id(__u64 cgid) {
	__u64 *ret;
	ret = bpf_map_lookup_elem(&cgtracker_map, &cgid);
	return ret ? *ret : 0;
}

/////////////////////////
// cgroup helpers
/////////////////////////

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb /* Cgroupv1 pseudo FS */
#endif

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270 /* Cgroupv2 pseudo FS */
#endif

/**
 * get_cgroup_level() Returns the cgroup level
 * @cgrp: target cgroup
 *
 * Returns the cgroup level, or 0 if it can not be retrieved.
 */
static __always_inline __u32 get_cgroup_level(const struct cgroup *cgrp) {
	__u32 level = 0;

	bpf_probe_read_kernel(&level, sizeof(level), _(&cgrp->level));
	return level;
}

/* Represent old kernfs node with the kernfs_node_id
 * union to read the id in 5.4 kernels and older
 */
struct kernfs_node___old {
	union kernfs_node_id id;
};

/**
 * get_cgroup_kn_id() Returns the kernfs node id
 * @cgrp: target kernfs node
 *
 * Returns the kernfs node id on success, zero on failures.
 */
static __always_inline __u64 __get_cgroup_kn_id(const struct kernfs_node *kn) {
	__u64 id = 0;

	if(!kn)
		return id;

	/* Kernels prior to 5.5 have the kernfs_node_id, but distros (RHEL)
	 * seem to have kernfs_node_id defined for UAPI reasons even though
	 * its not used here directly. To resolve this walk struct for id.id
	 */
	if(bpf_core_field_exists(((struct kernfs_node___old *)0)->id.id)) {
		struct kernfs_node___old *old_kn;

		old_kn = (void *)kn;
		if(BPF_CORE_READ_INTO(&id, old_kn, id.id) != 0)
			return 0;
	} else {
		bpf_probe_read_kernel(&id, sizeof(id), _(&kn->id));
	}

	return id;
}

/**
 * __get_cgroup_kn() Returns the kernfs_node of the cgroup
 * @cgrp: target cgroup
 *
 * Returns the kernfs_node of the cgroup on success, NULL on failures.
 */
static __always_inline struct kernfs_node *__get_cgroup_kn(const struct cgroup *cgrp) {
	if(!cgrp) {
		return NULL;
	}
	struct kernfs_node *kn = NULL;
	bpf_probe_read_kernel(&kn, sizeof(cgrp->kn), _(&cgrp->kn));
	return kn;
}

/**
 * get_cgroup_id() Returns cgroup id
 * @cgrp: target cgroup
 *
 * Returns the cgroup id of the target cgroup on success, zero on failures.
 */
static __always_inline __u64 get_cgroup_id(const struct cgroup *cgrp) {
	struct kernfs_node *kn;
	kn = __get_cgroup_kn(cgrp);
	return __get_cgroup_kn_id(kn);
}

/**
 * get_task_cgroup() Returns the accurate or desired cgroup of the css of
 *    current task that we want to operate on.
 * @task: must be current task.
 * @cgrpfs_ver: cgroup file system magic.
 * @subsys_idx: index of the desired cgroup_subsys_state part of css_set.
 *    Passing a zero as a subsys_idx is fine assuming you want that.
 *
 * If on Cgroupv2 returns the default cgroup associated with the task css_set.
 * If on Cgroupv1 returns the cgroup indexed at subsys_idx of the task
 *    css_set.
 * On failures NULL is returned.
 *
 * To get cgroup and kernfs node information we want to operate on the right
 * cgroup hierarchy which is setup by user space. However due to the
 * incompatibility between cgroup v1 and v2; how user space initialize and
 * install cgroup controllers, etc, it can be difficult.
 *
 * Use this helper and pass the css index that you consider accurate and
 * which can be discovered at runtime in user space.
 * Usually it is the 'memory' or 'pids' indexes by reading /proc/cgroups
 * file in case of Cgroupv1 where each line number is the index starting
 * from zero without counting first comment line.
 */
static __always_inline struct cgroup *get_task_cgroup(struct task_struct *task,
                                                      __u64 cgrpfs_ver,
                                                      __u32 subsys_idx) {
	struct cgroup_subsys_state *subsys;
	struct css_set *cgroups;
	struct cgroup *cgrp = NULL;

	bpf_probe_read_kernel(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if(unlikely(!cgroups)) {
		// todo!: we could use atomic_counters/send messages in case of errors
		return NULL;
	}

// See https://github.com/cilium/tetragon/pull/3574
#ifndef __RHEL7_BPF_PROG
	/* If we are in Cgroupv2 return the default css_set cgroup */
	if(cgrpfs_ver == CGROUP2_SUPER_MAGIC) {
		bpf_probe_read_kernel(&cgrp, sizeof(cgrp), _(&cgroups->dfl_cgrp));
		// cgrp could be NULL in case of failures
		return cgrp;
	}
#endif

	/* We are interested only in the cpuset, memory or pids controllers
	 * which are indexed at 0, 4 and 11 respectively assuming all controllers
	 * are compiled in.
	 * When we use the controllers indexes we will first discover these indexes
	 * dynamically in user space which will work on all setups from reading
	 * file: /proc/cgroups. If we fail to discover the indexes then passing
	 * a default index zero should be fine assuming we also want that.
	 *
	 * Reference: https://elixir.bootlin.com/linux/v5.19/source/include/linux/cgroup_subsys.h
	 *
	 * Notes:
	 * Newer controllers should be appended at the end. controllers
	 * that are not upstreamed may mess the calculation here
	 * especially if they happen to be before the desired subsys_idx,
	 * we fail.
	 */
	if(unlikely(subsys_idx > pids_cgrp_id)) {
		return NULL;
	}

	/* Read css from the passed subsys index to ensure that we operate
	 * on the desired controller. This allows user space to be flexible
	 * and chose the right per cgroup subsystem to use in order to
	 * support as much as workload as possible. It also reduces errors
	 * in a significant way.
	 */
	bpf_probe_read_kernel(&subsys, sizeof(subsys), _(&cgroups->subsys[subsys_idx]));
	if(unlikely(!subsys)) {
		return NULL;
	}

	bpf_probe_read_kernel(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
	// cgrp could be NULL in case of failures
	return cgrp;
}

/**
 * tg_get_current_cgroup_id() Returns the accurate cgroup id of current task.
 *
 * It works similar to __tg_get_current_cgroup_id, but computes the cgrp if it is needed.
 * Returns the cgroup id of current task on success, zero on failures.
 */
static __always_inline __u64 tg_get_current_cgroup_id(void) {
	// Try the bpf helper on the default hierarchy if available
	// and if we are running in unified cgroupv2
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_cgroup_id) &&
	   load_time_config.cgrp_fs_magic == CGROUP2_SUPER_MAGIC) {
		return bpf_get_current_cgroup_id();
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct cgroup *cgrp = get_task_cgroup(task,
	                                      load_time_config.cgrp_fs_magic,
	                                      load_time_config.cgrpv1_subsys_idx);
	if(!cgrp) {
		return 0;
	}
	return get_cgroup_id(cgrp);
}

static __always_inline __u64 get_cgroup_id_from_curr_task() {
	__u64 cgroupid = tg_get_current_cgroup_id();
	if(!cgroupid)
		return 0;

	__u64 trackerid = cgrp_get_tracker_id(cgroupid);
	if(trackerid)
		cgroupid = trackerid;

	return cgroupid;
}

/////////////////////////
// Nested cgroup tracker
/////////////////////////

/* new kernel cgroup definition */
struct cgroup___new {
	int level;
	struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

static __always_inline __u64 cgroup_get_parent_id(struct cgroup *cgrp) {
	struct cgroup___new *cgrp_new = (struct cgroup___new *)cgrp;

	// for newer kernels, we can access use ->ancestors to retrieve the parent
	if(bpf_core_field_exists(cgrp_new->ancestors)) {
		int level = get_cgroup_level(cgrp);

		if(level <= 0)
			return 0;
		return BPF_CORE_READ(cgrp_new, ancestors[level - 1], kn, id);
	}

	// otherwise, go over the parent pointer
	struct cgroup_subsys_state *parent_css = BPF_CORE_READ(cgrp, self.parent);

	if(parent_css) {
		struct cgroup *parent = container_of(parent_css, struct cgroup, self);
		__u64 parent_cgid = get_cgroup_id(parent);
		return parent_cgid;
	}

	return 0;
}

SEC("tp_btf/cgroup_mkdir")
int tg_cgtracker_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
	__u64 cgid = get_cgroup_id(cgrp);
	if(cgid == 0) {
		return 0;
	}
	__u64 cgid_parent = cgroup_get_parent_id(cgrp);
	if(cgid_parent == 0) {
		return 0;
	}

	// Check if parent cgroup is being tracked
	__u64 *cgid_tracker = bpf_map_lookup_elem(&cgtracker_map, &cgid_parent);
	if(cgid_tracker) {
		// if parent is being tracked, track the new cgroup too
		// todo!: add some metrics here
		bpf_map_update_elem(&cgtracker_map, &cgid, cgid_tracker, BPF_ANY);
	}
	return 0;
}

SEC("tp_btf/cgroup_release")
int tg_cgtracker_cgroup_release(struct bpf_raw_tracepoint_args *ctx) {
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
	__u64 cgid = get_cgroup_id(cgrp);
	if(cgid) {
		bpf_map_delete_elem(&cgtracker_map, &cgid);
	}
	return 0;
}

/////////////////////////
// Execve events
/////////////////////////

// A single buffer shared between all CPUs
#define BUF_DIM 8 * 1024 * 1024

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_DIM);
} ringbuf_monitoring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_DIM);
} ringbuf_execve SEC(".maps");

struct process_evt {
	__u64 cgid;
	__u64 cg_tracker_id;
	char comm[16];
};

// Force emitting struct event into the ELF.
const struct process_evt *unused __attribute__((unused));

SEC("tp_btf/sched_process_exec")
int BPF_PROG(execve_send, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
	struct process_evt *e = bpf_ringbuf_reserve(&ringbuf_execve, sizeof(*e), 0);
	if(!e) {
		// todo!: implement some metrics if we are dropping events
		bpf_printk("cannot reserve space in ringbuf");
		return 0;
	}
	e->cgid = tg_get_current_cgroup_id();
	e->cg_tracker_id = cgrp_get_tracker_id(e->cgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_printk("sent execve event, comm: %s, cgid: %d, cg_tracker_id: %d\n",
	           e->comm,
	           e->cgid,
	           e->cg_tracker_id);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/////////////////////////
// Enforcing
/////////////////////////

#define CGROUP_TO_POLICY_MAX_ENTRIES 65536
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CGROUP_TO_POLICY_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);   /* Key is the cgrpid */
	__type(value, __u64); /* Value is the policy id */
} cg_to_policy_map SEC(".maps");

#define POLICY_MAP_MAX_ENTRIES 65536
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);  /* Key is the policy id */
	__type(value, __u8); /* mode of the policy (e.g. enforce, monitor) */
} policy_mode_map SEC(".maps");

static __always_inline u16 string_padded_len(u16 len) {
	u16 padded_len = len;

	if(len < STRING_MAPS_SIZE_5) {
		if(len % STRING_MAPS_KEY_INC_SIZE != 0) {
			padded_len = ((len / STRING_MAPS_KEY_INC_SIZE) + 1) * STRING_MAPS_KEY_INC_SIZE;
		}
		return padded_len;
	}

	if(len <= STRING_MAPS_SIZE_6 - 2)
		return STRING_MAPS_SIZE_6 - 2;

	if(LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
		return STRING_MAPS_SIZE_7 - 2;
	}

	if(len <= STRING_MAPS_SIZE_7 - 2)
		return STRING_MAPS_SIZE_7 - 2;
	if(len <= STRING_MAPS_SIZE_8 - 2)
		return STRING_MAPS_SIZE_8 - 2;
	if(len <= STRING_MAPS_SIZE_9 - 2)
		return STRING_MAPS_SIZE_9 - 2;
	return STRING_MAPS_SIZE_10 - 2;
}

static __always_inline int string_map_index(u16 padded_len) {
	if(padded_len < STRING_MAPS_SIZE_5)
		return (padded_len / STRING_MAPS_KEY_INC_SIZE) - 1;

	if(LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
		if(padded_len == STRING_MAPS_SIZE_6 - 2)
			return 6;
		return 7;
	}

	switch(padded_len) {
	case STRING_MAPS_SIZE_6 - 2:
		return 6;
	case STRING_MAPS_SIZE_7 - 2:
		return 7;
	case STRING_MAPS_SIZE_8 - 2:
		return 8;
	case STRING_MAPS_SIZE_9 - 2:
		return 9;
	}
	return 10;
}

SEC("fmod_ret/security_bprm_creds_for_exec")
int BPF_PROG(enforce_cgroup_policy, struct linux_binprm *bprm) {
	__u64 cgid = get_cgroup_id_from_curr_task();
	if(cgid == 0) {
		// we return if we cannot get cgroup id, since our logic is based on cgroup ids
		return 0;
	}

	__u64 *policy_id = bpf_map_lookup_elem(&cg_to_policy_map, &cgid);
	if(!policy_id) {
		// no policy associated with this cgroup
		return 0;
	}

	// todo!: We need to extract the binary path now. We have 2 main ways:
	// 1.
	// https://github.com/Andreagit97/tetragon/blob/657f19eb85569de48314875d3e0f9f63d81ecc90/bpf/lib/bpf_d_path.h#L328
	// 2.
	// https://github.com/falcosecurity/libs/blob/f9a1b9343fb4b256087857bdb97492fc25c69c0c/driver/modern_bpf/helpers/store/auxmap_store_params.h#L1800
	// See what is the best way to do it
	//
	// struct file *file = bprm->file;
	// if(file == NULL) {
	// 	return 0;
	// }
	// struct path *path_arg = file->f_path;
	// ...

	// 5.11+ kernels support hash key lengths > 512 bytes
	// https://github.com/cilium/tetragon/commit/834b5fe7d4063928cf7b89f61252637d833ca018

	// if(LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0)) {
	// 	// This should be impossible since we are evaluating a path, but just in case
	// 	if(buflen > STRING_MAPS_SIZE_10 - 2 || !buflen) {
	// 		return 0;
	// 	}
	// } else {
	// 	if(buflen > STRING_MAPS_SIZE_7 - 2 || !buflen) {
	// 		return 0;
	// 	}
	// }

	// Calculate padded string length

	// u16 padded_len = string_padded_len(len);

	// Check if we have entries for this padded length.
	// Do this before we copy data for efficiency.

	// int index = string_map_index(padded_len);

	struct process_evt *e = bpf_ringbuf_reserve(&ringbuf_monitoring, sizeof(*e), 0);
	if(!e) {
		bpf_printk("Failed to reserve ring buffer monitoring space\n");
		return 0;
	}

	e->cgid = tg_get_current_cgroup_id();
	e->cg_tracker_id = cgrp_get_tracker_id(e->cgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_printk("Enforce policy  id %d, comm: %s\n", *policy_id, e->comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
