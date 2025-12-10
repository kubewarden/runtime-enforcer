#pragma once

#define POLICY_STR_OUTER_MAX_ENTRIES 1
#define POLICY_STR_INNER_MAX_ENTRIES 1

/* Taken from https://github.com/cilium/tetragon/pull/1408
 * To facilitate an arbitrary number of strings that can be matched on, string matching
 * uses a hash look up. The problem with this is that the key to a hash has to be a fixed
 * size, so if the maximum string length is 128 bytes, then all stored strings will be
 * 128 bytes long (padded with 0s) and the string to be looked up also has to be padded
 * with 0s to 128 bytes. This means that a short string will be hashed as if it is 128
 * bytes long.
 *
 * The BPF hash maps use jhash for key hashing. See include/linux/jhash.h. This requires
 * approximately 1 CPU cycle per byte, so in the example above, hashing every string,
 * regardless of length, will take ~128 cycles, which is clearly inefficient. See
 * https://fosdem.org/2023/schedule/event/bpf_hashing/ for details.
 *
 * jhash hashes in 12 byte blocks (3 x u32). For all lengths >12, a number of 12 byte
 * blocks are hashed, and the remainder is hashed using a combination of single byte
 * loads/shifts, followed by a final mix. It appears that the most efficient use of
 * jhash is with lengths equal to 12k + 1, minimising the number of single byte loads/
 * shifts.
 *
 * In order to reduce the amount of hashing of padded 0s, we opt to store string matches
 * in multiple hashes, with increasing key sizes, where the key size is one more than a
 * multiple of 12. Each string to be stored is placed in the hash that has the smallest
 * key size that can accommodate it (and is padded to the key size). Strings to be looked
 * up are equally padded to the smallest key size that can accommodate them, and then
 * looked up in the related map.
 *
 * The chosen key sizes are 25, 49, 73, 97, 121, 145, 258, 514, 1026, 2050, 4098 (11 maps).
 * The first 6 are sized for common uses and to minimise the hashing of empty bytes. The
 * following 5 maps notionally double in size, with lengths equal to 2^k + 2. On kernels
 * <5.11, the last four maps are replaced with a single map with key size 512. This is due
 * to key size limitations on kernels <5.11.
 */
#define STRING_MAPS_KEY_INC_SIZE 24
#define STRING_MAPS_SIZE_0 (1 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_1 (2 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_2 (3 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_3 (4 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_4 (5 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_5 (6 * STRING_MAPS_KEY_INC_SIZE)
#define STRING_MAPS_SIZE_6 (256)
#define STRING_MAPS_SIZE_7 (512)
#define STRING_MAPS_SIZE_8 (1024)
#define STRING_MAPS_SIZE_9 (2048)
#define STRING_MAPS_SIZE_10 (4096)

// todo!: we want to compile only once so we should avoid the ifdef. We should probably not create
// maps > 8. Test it, if it is feasible
//
// #ifdef __V511_BPF_PROG
// #define STRING_MAPS_SIZE_7  (512 + 2)
// #define STRING_MAPS_SIZE_8  (1024 + 2)
// #define STRING_MAPS_SIZE_9  (2048 + 2)
// #define STRING_MAPS_SIZE_10 (4096 + 2)
// #else
// #define STRING_MAPS_SIZE_7 (512)
// #endif

#define DEFINE_POLICY_STR_HASH_OF_MAPS(N)                              \
	struct {                                                           \
		__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);                       \
		__uint(max_entries, POLICY_STR_OUTER_MAX_ENTRIES);             \
		__uint(map_flags, BPF_F_NO_PREALLOC);                          \
		__type(key, __u64);                                            \
		__array(                                                       \
		        values,                                                \
		        struct {                                               \
			        __uint(type, BPF_MAP_TYPE_HASH);                   \
			        __uint(max_entries, POLICY_STR_INNER_MAX_ENTRIES); \
			        __type(key, __u8[STRING_MAPS_SIZE_##N]);           \
			        __type(value, __u8);                               \
		        });                                                    \
	} pol_str_maps_##N SEC(".maps");

DEFINE_POLICY_STR_HASH_OF_MAPS(0)
DEFINE_POLICY_STR_HASH_OF_MAPS(1)
DEFINE_POLICY_STR_HASH_OF_MAPS(2)
DEFINE_POLICY_STR_HASH_OF_MAPS(3)
DEFINE_POLICY_STR_HASH_OF_MAPS(4)
DEFINE_POLICY_STR_HASH_OF_MAPS(5)
DEFINE_POLICY_STR_HASH_OF_MAPS(6)
DEFINE_POLICY_STR_HASH_OF_MAPS(7)
DEFINE_POLICY_STR_HASH_OF_MAPS(8)
DEFINE_POLICY_STR_HASH_OF_MAPS(9)
DEFINE_POLICY_STR_HASH_OF_MAPS(10)

static __always_inline void* get_policy_string_map(int index, u64* policy_id) {
	switch(index) {
	case 0:
		return bpf_map_lookup_elem(&pol_str_maps_0, policy_id);
	case 1:
		return bpf_map_lookup_elem(&pol_str_maps_1, policy_id);
	case 2:
		return bpf_map_lookup_elem(&pol_str_maps_2, policy_id);
	case 3:
		return bpf_map_lookup_elem(&pol_str_maps_3, policy_id);
	case 4:
		return bpf_map_lookup_elem(&pol_str_maps_4, policy_id);
	case 5:
		return bpf_map_lookup_elem(&pol_str_maps_5, policy_id);
	case 6:
		return bpf_map_lookup_elem(&pol_str_maps_6, policy_id);
	case 7:
		return bpf_map_lookup_elem(&pol_str_maps_7, policy_id);
	case 8:
		return bpf_map_lookup_elem(&pol_str_maps_8, policy_id);
	case 9:
		return bpf_map_lookup_elem(&pol_str_maps_9, policy_id);
	case 10:
		return bpf_map_lookup_elem(&pol_str_maps_10, policy_id);
	}
	return 0;
}

// todo!: same as before for `__V511_BPF_PROG`
// #ifdef __V511_BPF_PROG
// DEFINE_POLICY_STR_HASH_OF_MAPS(8)
// DEFINE_POLICY_STR_HASH_OF_MAPS(9)
// DEFINE_POLICY_STR_HASH_OF_MAPS(10)
// #endif
