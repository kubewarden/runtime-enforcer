// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "load_conf.h"
#include "debug.h"
#include "helpers.h"
#include "string_maps.h"
#include "d_path_resolution.h"

// cspell:ignore kconfig

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
	__uint(map_flags, BPF_F_NO_PREALLOC);
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

// Some of these cgroup helpers are taken and adapted from Tetragon
// https://github.com/cilium/tetragon/pull/369

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
static __always_inline u32 get_cgroup_level(const struct cgroup *cgrp) {
	__u32 level = 0;

	bpf_core_read(&level, sizeof(level), &cgrp->level);
	return level;
}

/**
 * get_cgroup_kn_id() Returns the kernfs node id
 * @cgrp: target kernfs node
 *
 * Returns the kernfs node id on success, zero on failures.
 */
static __always_inline __u64 __get_cgroup_kn_id(const struct kernfs_node *kn) {
	__u64 id = 0;

	if(!kn) {
		return id;
	}

	/* Kernels prior to 5.5 have the kernfs_node_id, but distros (RHEL)
	 * seem to have kernfs_node_id defined for UAPI reasons even though
	 * its not used here directly. To resolve this walk struct for id.id
	 */
	if(bpf_core_field_exists(((struct kernfs_node___old *)0)->id.id)) {
		struct kernfs_node___old *old_kn;

		old_kn = (void *)kn;
		if(BPF_CORE_READ_INTO(&id, old_kn, id.id) != 0) {
			return 0;
		}
	} else {
		bpf_core_read(&id, sizeof(id), &kn->id);
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
	bpf_core_read(&kn, sizeof(cgrp->kn), &cgrp->kn);
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
 * @cgrp_fs_ver: cgroup file system magic.
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
                                                      __u64 cgrp_fs_ver,
                                                      __u32 subsys_idx) {
	struct cgroup_subsys_state *subsys;
	struct css_set *cgroups;
	struct cgroup *cgrp = NULL;

	bpf_core_read(&cgroups, sizeof(cgroups), &task->cgroups);
	if(unlikely(!cgroups)) {
		return NULL;
	}

// See https://github.com/cilium/tetragon/pull/3574
// todo!: check our RHEL7 compatibility
#ifndef __RHEL7__
	/* If we are in Cgroupv2 return the default css_set cgroup */
	if(cgrp_fs_ver == CGROUP2_SUPER_MAGIC) {
		bpf_core_read(&cgrp, sizeof(cgrp), &cgroups->dfl_cgrp);
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
	 * that are not upstream may mess the calculation here
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
	bpf_core_read(&subsys, sizeof(subsys), &cgroups->subsys[subsys_idx]);
	if(unlikely(!subsys)) {
		return NULL;
	}

	bpf_core_read(&cgrp, sizeof(cgrp), &subsys->cgroup);
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

static __always_inline __u64 get_tracker_id_from_curr_task() {
	__u64 cgroupid = tg_get_current_cgroup_id();
	if(!cgroupid) {
		return 0;
	}

	__u64 trackerid = cgrp_get_tracker_id(cgroupid);
	if(!trackerid) {
		return 0;
	}

	return trackerid;
}

// exec_in_host_mnt_ns reports whether the current task is executing while still
// in the host init mount namespace. The OCI runtime bootstrap (e.g. `runc init`)
// execs before joining the container mount namespace, so it runs in the host
// mount namespace; workload execs always run in the container's own mount
// namespace. Returns false (disabled) when the reference inode is unknown (0),
// keeping the previous fail-open behavior.
static __always_inline bool exec_in_host_mnt_ns(void) {
	__u64 ref = load_time_config.host_mnt_ns_inum;
	if(ref == 0) {
		return false;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	return (__u64)inum == ref;
}

/////////////////////////
// Log helpers
/////////////////////////

static __always_inline void emit_log_event_args(log_code code, u64 arg1, u64 arg2) {
	struct log_evt *evt = bpf_ringbuf_reserve(&ringbuf_logs, sizeof(struct log_evt), 0);
	if(!evt) {
		bpf_printk("Failed to reserve space for log event in ring buffer\n");
		return;
	}
	evt->code = code;
	if(bpf_get_current_comm(evt->comm, TASK_COMM_LEN)) {
		// we don't fail we just print the error
		bpf_printk("Failed to get comm for log event\n");
	}
	evt->cg_tracker_id = get_tracker_id_from_curr_task();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	evt->pid = pid_tgid & 0xFFFFFFFF;
	evt->tgid = pid_tgid >> 32;
	evt->arg1 = arg1;
	evt->arg2 = arg2;
	bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_log_event(log_code code) {
	emit_log_event_args(code, 0, 0);
}

static __always_inline void emit_log_event_1(log_code code, u64 arg1) {
	emit_log_event_args(code, arg1, 0);
}

static __always_inline void emit_log_event_2(log_code code, u64 arg1, u64 arg2) {
	emit_log_event_args(code, arg1, arg2);
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
		u32 level = get_cgroup_level(cgrp);

		if(level <= 0) {
			return 0;
		}
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
		emit_log_event(LOG_FAIL_TO_RESOLVE_CGROUP_ID);
		return 0;
	}
	__u64 cgid_parent = cgroup_get_parent_id(cgrp);
	if(cgid_parent == 0) {
		emit_log_event(LOG_FAIL_TO_RESOLVE_PARENT_CGROUP_ID);
		return 0;
	}

	// Check if parent cgroup is being tracked
	__u64 *cgid_tracker = bpf_map_lookup_elem(&cgtracker_map, &cgid_parent);
	if(cgid_tracker) {
		// if parent is being tracked, track the new cgroup too
		bpf_map_update_elem(&cgtracker_map, &cgid, cgid_tracker, BPF_ANY);
	}
	return 0;
}

SEC("tp_btf/cgroup_release")
int tg_cgtracker_cgroup_release(struct bpf_raw_tracepoint_args *ctx) {
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
	__u64 cgid = get_cgroup_id(cgrp);
	if(cgid == 0) {
		emit_log_event(LOG_FAIL_TO_RESOLVE_CGROUP_ID);
		return 0;
	}
	bpf_map_delete_elem(&cgtracker_map, &cgid);
	return 0;
}

/////////////////////////
// Execve events
/////////////////////////

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_DIM);
} ringbuf_monitoring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, BUF_DIM);
} ringbuf_execve SEC(".maps");

struct process_evt {
	u64 cg_tracker_id;
	u16 path_len;
	u8 mode;  // enforce or protect, todo!: this information is not needed by the learning event so
	          // we can also decide to split the event structures
	// MAX_PATH_LEN for the final path +
	// MAX_PATH_LEN for storing the progressive path +
	// MAX_PATH_LEN of empty space for padding when we do the string map lookups
	char path[MAX_PATH_LEN * 3];
	// todo!: we need to add the atomic value for concurrency, see
	// https://github.com/falcosecurity/libs/issues/2719
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct process_evt);
} process_evt_storage_map SEC(".maps");

// Force emitting struct event into the ELF.
const struct process_evt *unused_process_evt __attribute__((unused));

static __always_inline u32 populate_evt_with_path(struct process_evt *evt,
                                                  struct linux_binprm *bprm) {
	struct file *file = bprm->file;
	if(file == NULL) {
		emit_log_event(LOG_MISSING_FILE_STRUCT);
		return 0;
	}
	struct path *path_arg = &file->f_path;
	u32 current_offset = bpf_d_path_approx(path_arg, evt->path);
	if(current_offset == 0) {
		emit_log_event(LOG_FAIL_TO_RESOLVE_PATH);
		return 0;
	}
	if(current_offset == MAX_PATH_LEN * 2) {
		emit_log_event(LOG_EMPTY_PATH);
		return 0;
	}
	// path_len doesn't contain the string terminator `\0`, the userspace doesn't need it.
	evt->path_len = MAX_PATH_LEN * 2 - current_offset;
	return current_offset;
}

static __always_inline struct process_evt *get_process_evt() {
	int zero = 0;
	struct process_evt *evt =
	        (struct process_evt *)bpf_map_lookup_elem(&process_evt_storage_map, &zero);
	if(!evt) {
		emit_log_event_1(LOG_FAIL_TO_LOOKUP_EVT_MAP, (u32)(bpf_get_smp_processor_id()));
		return NULL;
	}
	return evt;
}

/////////////////////////
// Monitoring/Enforcing
/////////////////////////

#define CGROUP_TO_POLICY_MAX_ENTRIES 65536
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CGROUP_TO_POLICY_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);   /* Key is the cgrp id */
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

#define POLICY_MODE_MONITOR 1
#define POLICY_MODE_PROTECT 2
#define EPERM 1

static __always_inline u16 string_padded_len(u16 len) {
	u16 padded_len = len;

	if(len < STRING_MAPS_SIZE_5) {
		if(len % STRING_MAPS_KEY_INC_SIZE != 0) {
			padded_len = ((len / STRING_MAPS_KEY_INC_SIZE) + 1) * STRING_MAPS_KEY_INC_SIZE;
		}
		return padded_len;
	}

	if(len <= STRING_MAPS_SIZE_6) {
		return STRING_MAPS_SIZE_6;
	}

	if(len <= STRING_MAPS_SIZE_7) {
		return STRING_MAPS_SIZE_7;
	}

	if(len <= STRING_MAPS_SIZE_8) {
		return STRING_MAPS_SIZE_8;
	}

	if(len <= STRING_MAPS_SIZE_9) {
		return STRING_MAPS_SIZE_9;
	}

	return STRING_MAPS_SIZE_10;
}

static __always_inline int string_map_index(u16 padded_len) {
	if(padded_len < STRING_MAPS_SIZE_5) {
		return (padded_len / STRING_MAPS_KEY_INC_SIZE) - 1;
	}

	switch(padded_len) {
	case STRING_MAPS_SIZE_6:
		return 6;
	case STRING_MAPS_SIZE_7:
		return 7;
	case STRING_MAPS_SIZE_8:
		return 8;
	case STRING_MAPS_SIZE_9:
		return 9;
	case STRING_MAPS_SIZE_10:
	default:
		return 10;
	}
}

SEC("fmod_ret/security_bprm_creds_for_exec")
int BPF_PROG(enforce_cgroup_policy, struct linux_binprm *bprm) {
	__u64 cg_tracker_id = get_tracker_id_from_curr_task();
	if(cg_tracker_id == 0) {
		// we return if we cannot get cgroup id, since our logic is based on cgroup ids.
		// This is not an error, the userspace will populate the cgtracker_map only for the cgroups
		// associated with containers, so all non-container cgroups will be ignored.
		return 0;
	}

	if(exec_in_host_mnt_ns()) {
		// The OCI runtime bootstrap (e.g. `runc init` / setns) execs while still
		// in the host init mount namespace; it only enters the container mount
		// namespace (setns/pivot_root) AFTER this execve. Every real workload exec
		// runs in the container's own mount namespace. So an exec that is charged
		// to a tracked container cgroup but still runs in the host mount namespace
		// is a runtime bootstrap, not a workload binary: suppress reporting, never
		// deny, and never learn it.
		return 0;
	}

	__u64 *policy_id = bpf_map_lookup_elem(&cg_to_policy_map, &cg_tracker_id);
	if(!policy_id) {
		// if learning is disabled, nothing to do, we can return
		if(!load_time_config.learning_enabled) {
			return 0;
		}

		// No policy associated with this cgroup.
		// Emit the event to the learning ringbuf so that the userspace can learn from it.
		// This is critical because the LSM hook `security_bprm_creds_for_exec` is called
		// for each binary in the binfmt chain (e.g., script AND interpreter), while the
		// `sched_process_exec` tracepoint only fires once for the final binary. Without
		// this, shebang scripts (e.g., docker-entrypoint.sh) would never be learned and
		// would be blocked when the policy is enforced.
		struct process_evt *levt = get_process_evt();
		if(!levt) {
			return 0;
		}
		levt->cg_tracker_id = cg_tracker_id;
		levt->mode = 0;

		u32 loffset = populate_evt_with_path(levt, bprm);
		if(loffset == 0) {
			return 0;
		}

		long lerr = bpf_probe_read_kernel(levt->path,
		                                  SAFE_PATH_LEN(levt->path_len + 1),
		                                  &levt->path[SAFE_PATH_ACCESS(loffset)]);
		if(lerr != 0) {
			emit_log_event(LOG_FAIL_TO_COPY_EXEC_PATH);
			return 0;
		}

		// this is used for debug during development is never used in production
		bpf_printk("sent execve event, path: %s, cg_tracker_id: %d",
		           levt->path,
		           levt->cg_tracker_id);

		lerr = bpf_ringbuf_output(&ringbuf_execve, levt, 19 + SAFE_PATH_LEN(levt->path_len), 0);
		if(lerr != 0) {
			emit_log_event(LOG_DROP_EXEC_EVENT);
		}
		return 0;
	}

	struct process_evt *evt = get_process_evt();
	if(!evt) {
		return 0;
	}

	evt->cg_tracker_id = cg_tracker_id;

	u32 current_offset = populate_evt_with_path(evt, bprm);
	if(current_offset == 0) {
		return 0;
	}

	///////////////////////////////
	// We now do the comparison
	///////////////////////////////

	// Only 5.11+ kernels support hash key lengths > 512 bytes
	// https://github.com/cilium/tetragon/commit/834b5fe7d4063928cf7b89f61252637d833ca018
	// From now on, we are sure that evt->path_len is <= STRING_MAPS_SIZE_7 if on <5.11
	if(LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
		if(evt->path_len > STRING_MAPS_SIZE_7) {
			emit_log_event(LOG_PATH_LEN_TOO_LONG);
			return 0;
		}
	}

	int padded_len = string_padded_len(evt->path_len);
	int index = string_map_index(padded_len);
	void *string_map = get_policy_string_map(index, policy_id);
	// if `string_map` is NULL it means that the userspace never populated a map for this path
	// length. This is an optimization userspace side and expected behavior. We should consider
	// the missing map as a not allowed event.
	__u8 *match = NULL;
	if(string_map) {
		// Note that string_map will contain strings padded with extra NUL bytes
		// (e.g.`/usr/bin/cat\0\0\0\0\0\0\0`). To have a fair comparison we need to account for the
		// padding and that's the reason why our third segment in the buffer is full of NUL bytes.
		//
		//  buf   | MAX_PATH_LEN | MAX_PATH_LEN | MAX_PATH_LEN |
		//                          /usr/bin/cat\0\0\0\0\0\0\0
		//                          ^
		// current_offset points here
		match = bpf_map_lookup_elem(string_map, &evt->path[SAFE_PATH_ACCESS(current_offset)]);
	}

	if(match != NULL) {
		// We have this binary in the list so we do nothing
		return 0;
	}

	///////////////////////////////
	// We send the event
	///////////////////////////////

	// here we are copying the resolved path into the first segment of the buffer.
	// please note: in the first segment of the path we will already have the path written by
	// the previous program execution, what we are doing here is to overwrite the path with the new
	// content. Example:
	// - previous: `/usr/bin/nginx-controller\0`
	// - new one:  `/usr/bin/cat\0x-controller\0`
	// we need the +1 because we want to copy also the `\0` terminator
	long err = bpf_probe_read_kernel(evt->path,
	                                 SAFE_PATH_LEN(evt->path_len + 1),
	                                 &evt->path[SAFE_PATH_ACCESS(current_offset)]);
	if(err != 0) {
		emit_log_event(LOG_FAIL_TO_COPY_EXEC_PATH);
		return 0;
	}

	// We check if we are in monitoring or enforcing mode for this policy
	__u8 *mode = bpf_map_lookup_elem(&policy_mode_map, policy_id);
	if(!mode) {
		// With our current code this is an error.
		emit_log_event_1(LOG_POLICY_MODE_MISSING, *policy_id);
		return 0;
	}
	bpf_printk("Mode %d for policy id %d", *mode, *policy_id);
	evt->mode = *mode;

	err = bpf_ringbuf_output(&ringbuf_monitoring, evt, 19 + SAFE_PATH_LEN(evt->path_len), 0);
	if(err != 0) {
		emit_log_event_2(LOG_DROP_VIOLATION, *policy_id, evt->mode);
	}

	bpf_printk("sent enforce event, path: %s, cg_tracker_id: %d", evt->path, evt->cg_tracker_id);
	bpf_printk("mode: %d", evt->mode);

	if(*mode == POLICY_MODE_MONITOR) {
		return 0;
	}
	// We are in enforcing mode
	return -EPERM;
}
