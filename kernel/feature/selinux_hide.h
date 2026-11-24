// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

// selinux_hide's list, hand-rolled hazard pointers via C11 atomics

#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

static int sepol_expected_argc(u32 cmd);

// flex array
struct ksu_hide_buf {
	size_t len;
	char data[];
} __attribute__((aligned(sizeof(size_t))));

// types
// :type1:\0:type2:\0:type3:\0
static struct ksu_hide_buf *ksu_hide_type_list __read_mostly = nullptr;

// rules
// :src1:\0:tgt1:\0:src2:\0:tgt2:\0:src3:\0:tgt3:\0
static struct ksu_hide_buf *ksu_hide_rule_list __read_mostly = nullptr;

static DEFINE_MUTEX(selinux_hide_list_mutex);

static struct ksu_hide_buf *__percpu *ksu_selinux_hide_hazptr_slot __read_mostly = nullptr;

static inline void ksu_selinux_hide_alloc_hazptr_slot(void)
{
	ksu_selinux_hide_hazptr_slot = alloc_percpu(struct ksu_hide_buf *);

	// asshole assert nofail.
	if (!ksu_selinux_hide_hazptr_slot) {
		__builtin_trap();
		__builtin_unreachable();
	}

	unsigned int cpu;
	for_each_possible_cpu(cpu) {
		struct ksu_hide_buf **slot = per_cpu_ptr(ksu_selinux_hide_hazptr_slot, cpu);
		pr_info("selinux_hide: hazptr_slot: 0x%lx cpu: %u \n", (uintptr_t)slot, cpu );
	}
}

// NOTE: can ret null on uninitialized state
static inline struct ksu_hide_buf *ksu_selinux_hide_get_buf(struct ksu_hide_buf **g_buf)
{
	// reader has to pin its own slot
	preempt_disable();
	struct ksu_hide_buf **slot = this_cpu_ptr(ksu_selinux_hide_hazptr_slot);
	struct ksu_hide_buf *buf;

check_buf:
	buf = __atomic_load_n(g_buf, __ATOMIC_ACQUIRE);
	__atomic_store_n(slot, buf, __ATOMIC_RELEASE);
	/* The pin must be globally visible before the second lookup. */
	__atomic_thread_fence(__ATOMIC_SEQ_CST);

	if (buf != __atomic_load_n(g_buf, __ATOMIC_ACQUIRE))
		goto check_buf;

	return buf;
}

static inline void ksu_selinux_hide_put_buf(struct ksu_hide_buf **unused)
{
	struct ksu_hide_buf **slot = this_cpu_ptr(ksu_selinux_hide_hazptr_slot);
	__atomic_store_n(slot, NULL, __ATOMIC_RELEASE);
	
	preempt_enable();
}

static inline void ksu_selinux_hide_hazptr_free(struct ksu_hide_buf *old_ptr)
{
	if (!old_ptr)
		return;

	// acquire it on ALL cpus!
	// only free it once ALL slots say that their slot no longer contains old ptr
	unsigned int cpu;
	for_each_possible_cpu(cpu) {
		struct ksu_hide_buf **slot = per_cpu_ptr(ksu_selinux_hide_hazptr_slot, cpu);
		while (__atomic_load_n(slot, __ATOMIC_ACQUIRE) == old_ptr)
			cpu_relax();
	}

	kfree(old_ptr);
}

static noinline void ksu_add_shit_to_list(u32 cmd, const char *args[])
{
	if (!args || !args[0])
		return;

	guarded_mutex_lock(&selinux_hide_list_mutex);

	int argc = sepol_expected_argc(cmd);

	if (cmd == KSU_SEPOLICY_CMD_TYPE || cmd == KSU_SEPOLICY_CMD_TYPE_ATTR || cmd == KSU_SEPOLICY_CMD_TYPE_STATE || cmd == KSU_SEPOLICY_CMD_ATTR) {
		
		const char *name = args[0];
		size_t needed_len = strlen(name) + 3; // :type:\0

		if (!ksu_hide_type_list)
			goto skip_type_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_type_list->len > offset) {
			const char *current_type = ksu_hide_type_list->data + offset;

			char tmp_buf[64];
			snprintf(tmp_buf, sizeof(tmp_buf), ":%s:", name);

			if (!strcmp(current_type, tmp_buf))
				return;

			offset = offset + strlen(current_type) + 1;
		}

	skip_type_dup_check:;
		size_t old_len = (ksu_hide_type_list) ? ksu_hide_type_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL | __GFP_NOFAIL);
		new_ptr->len = new_total_len;

		if (ksu_hide_type_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_type_list->data, old_len);

		char *w_ptr = new_ptr->data + old_len;
		sprintf(w_ptr, ":%s:", name);

		struct ksu_hide_buf *old_ptr = __atomic_exchange_n(&ksu_hide_type_list, new_ptr, __ATOMIC_ACQ_REL);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		ksu_selinux_hide_hazptr_free(old_ptr);

		pr_info("selinux_hide: tracking type: %s\n", w_ptr);


	} else if (argc >= 2) {

		if (!args[1])
			return;

		const char *src = args[0];
		const char *tgt = args[1];

		size_t src_needed = strlen(src) + 3; // :src:\0
		size_t tgt_needed = strlen(tgt) + 3; // :tgt:\0
		size_t needed_len = src_needed + tgt_needed;

		if (!ksu_hide_rule_list)
			goto skip_rule_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_rule_list->len > offset) {
			const char *src_chk = ksu_hide_rule_list->data + offset;
			size_t src_sz = strlen(src_chk) + 1; // for \0

			const char *tgt_chk = src_chk + src_sz;
			size_t tgt_sz = strlen(tgt_chk) + 1; // for \0

			char src_buf[64], tgt_buf[64];
			snprintf(src_buf, sizeof(src_buf), ":%s:", src);
			snprintf(tgt_buf, sizeof(tgt_buf), ":%s:", tgt);

			if (!strcmp(src_chk, src_buf) && !strcmp(tgt_chk, tgt_buf))
				return;

			offset = offset + src_sz + tgt_sz;
		}

	skip_rule_dup_check:;
		size_t old_len = (ksu_hide_rule_list) ? ksu_hide_rule_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL | __GFP_NOFAIL);
		new_ptr->len = new_total_len;

		if (ksu_hide_rule_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_rule_list->data, old_len);

		char *w_ptr_src = new_ptr->data + old_len;
		sprintf(w_ptr_src, ":%s:", src);

		char *w_ptr_tgt = w_ptr_src + strlen(w_ptr_src) + 1;
		sprintf(w_ptr_tgt, ":%s:", tgt);

		struct ksu_hide_buf *old_ptr = __atomic_exchange_n(&ksu_hide_rule_list, new_ptr, __ATOMIC_ACQ_REL);
		__atomic_thread_fence(__ATOMIC_SEQ_CST);
		ksu_selinux_hide_hazptr_free(old_ptr);

		pr_info("selinux_hide: tracking rule: %s %s\n", w_ptr_src, w_ptr_tgt);

	}

	return;
}

static __always_inline bool ksu_should_destroy_context(char *str, size_t limit, const bool types_only)
{
	if (!str)
		return false;

	kick_all_cpus_sync();
{ // scope++
	struct ksu_hide_buf *type_buf __cleanup(ksu_selinux_hide_put_buf) = ksu_selinux_hide_get_buf(&ksu_hide_type_list);
	if (unlikely(!type_buf))
		goto check_rule;

	size_t offset = 0;
	while (type_buf->len > offset) {
		const char *current_entry = type_buf->data + offset;

		if (strnstr(str, current_entry, limit))
			return true;

		offset = offset + strlen(current_entry) + 1;
	}
} // scope--

check_rule:
	if (types_only)
		return false;

	// double strstr
	const char *str2 = strnchr(str, limit, ' ');
	if (!str2)
		return false;

{ // scope++
	struct ksu_hide_buf *rule_buf __cleanup(ksu_selinux_hide_put_buf) = ksu_selinux_hide_get_buf(&ksu_hide_rule_list);
	if (unlikely(!rule_buf))
		return false;
	
	size_t offset = 0;
	while (rule_buf->len > offset) {
		const char *src_rule = rule_buf->data + offset;
		size_t src_sz = strlen(src_rule) + 1;

		const char *tgt_rule = src_rule + src_sz;
		size_t tgt_sz = strlen(tgt_rule) + 1;

		if (strnstr(str, src_rule, str2 - str) && strnstr(str2, tgt_rule, limit - (str2 - str)))
			return true;

		offset = offset + src_sz + tgt_sz;
	}
} // scope--
	return false;
}

static __always_inline void replace_after_second_colon(char *str, size_t bound)
{
	if (!str)
		return;

	const char *first = __builtin_memchr(str, ':', bound);
	if (!first)
		return;

	char *second = __builtin_memchr(first, ':', bound - (first - str));
	if (!second || !second[1] || !second[2])
		return;

	if (second[2] != '6')
		second[2] = '6';
	else
		second[2] = '7';
}

static noinline void do_useless_alloc(size_t sz)
{
	volatile uint32_t random = get_random_u32();
	volatile uint8_t *s = (volatile uint8_t *)&random;
	volatile int n = ((s[0] ?: 64) + (s[1] ?: 32) + (s[2] ?: 16) + (s[3] ?: 8)) / 2;
	volatile char *stack = __builtin_alloca(n);

	if (sz > 256)
		sz = 256;

	volatile char *heap __zoffstack(sz * 4 + n);
	memset_explicit(heap, s[0], sz * 4 + n);
	memset_explicit(stack, s[1], n);
}

struct ksu_hide_span {
	size_t start;
	size_t end;
};

static __always_inline bool ksu_hide_type_span(const char *str, size_t limit,
						struct ksu_hide_span *span)
{
	const char *first, *second, *third;
	size_t start, remaining;

	if (!str || !span)
		return false;

	limit = strnlen(str, limit);
	first = __builtin_memchr(str, ':', limit);
	if (!first || first == str)
		return false;

	remaining = limit - (first - str + 1);
	second = __builtin_memchr(first + 1, ':', remaining);
	if (!second || second == first + 1)
		return false;

	start = second - str + 1;
	if (start >= limit)
		return false;

	third = __builtin_memchr(str + start, ':', limit - start);
	span->start = start;
	span->end = third ? (size_t)(third - str) : limit;
	return span->end > start;
}

static __always_inline bool ksu_hide_span_matches(const char *entry, const char *str,
						   const struct ksu_hide_span *span)
{
	size_t entry_len = strlen(entry);
	size_t type_len = span->end - span->start;

	return entry_len == type_len + 2 && entry[0] == ':' &&
		entry[type_len + 1] == ':' &&
		!memcmp(entry + 1, str + span->start, type_len);
}

static __always_inline bool ksu_hide_type_in_list(struct ksu_hide_buf *type_buf,
						   const char *str,
						   const struct ksu_hide_span *span)
{
	size_t offset = 0;
	bool found = false;

	if (!type_buf)
		return false;

	while (offset < type_buf->len) {
		const char *entry = type_buf->data + offset;

		found |= ksu_hide_span_matches(entry, str, span);
		offset += strlen(entry) + 1;
	}
	return found;
}

static __always_inline bool ksu_hide_sanitize_context(char *str, size_t limit)
{
	struct ksu_hide_span span;
	bool found;

	if (!ksu_hide_type_span(str, limit, &span))
		return false;

	{
		struct ksu_hide_buf *type_buf __cleanup(ksu_selinux_hide_put_buf) =
			ksu_selinux_hide_get_buf(&ksu_hide_type_list);
		found = ksu_hide_type_in_list(type_buf, str, &span);
	}

	if (found)
		str[span.start] = '!';
	return found;
}

static __always_inline bool ksu_hide_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static __always_inline bool ksu_hide_next_token(const char *str, size_t limit,
						 size_t *offset, struct ksu_hide_span *token)
{
	size_t pos = *offset;

	while (pos < limit && ksu_hide_space(str[pos]))
		pos++;
	if (pos == limit)
		return false;

	token->start = pos;
	while (pos < limit && !ksu_hide_space(str[pos]))
		pos++;
	token->end = pos;
	*offset = pos;
	return true;
}

static __always_inline bool ksu_hide_access_class_valid(const char *str,
							 const struct ksu_hide_span *token)
{
	size_t pos = token->start;

	if (pos < token->end && (str[pos] == '+' || str[pos] == '-'))
		pos++;
	return pos < token->end && str[pos] >= '0' && str[pos] <= '9';
}

static __always_inline bool ksu_hide_sanitize_access(char *str, size_t limit)
{
	struct ksu_hide_span source, target, class, source_type, target_type;
	size_t offset = 0;
	bool source_hidden, target_hidden, rule_hidden = false;

	if (!str)
		return false;
	limit = strnlen(str, limit);
	if (!ksu_hide_next_token(str, limit, &offset, &source) ||
	    !ksu_hide_next_token(str, limit, &offset, &target) ||
	    !ksu_hide_next_token(str, limit, &offset, &class) ||
	    !ksu_hide_access_class_valid(str, &class))
		return false;

	if (!ksu_hide_type_span(str + source.start, source.end - source.start, &source_type) ||
	    !ksu_hide_type_span(str + target.start, target.end - target.start, &target_type))
		return false;

	source_type.start += source.start;
	source_type.end += source.start;
	target_type.start += target.start;
	target_type.end += target.start;

	{
		struct ksu_hide_buf *type_buf __cleanup(ksu_selinux_hide_put_buf) =
			ksu_selinux_hide_get_buf(&ksu_hide_type_list);
		source_hidden = ksu_hide_type_in_list(type_buf, str, &source_type);
		target_hidden = ksu_hide_type_in_list(type_buf, str, &target_type);
	}

	{
		struct ksu_hide_buf *rule_buf __cleanup(ksu_selinux_hide_put_buf) =
			ksu_selinux_hide_get_buf(&ksu_hide_rule_list);
		size_t rule_offset = 0;

		while (rule_buf && rule_offset < rule_buf->len) {
			const char *src_rule = rule_buf->data + rule_offset;
			const char *tgt_rule = src_rule + strlen(src_rule) + 1;

			/* Keep the work independent of which side matches. */
			rule_hidden |= (unsigned)ksu_hide_span_matches(src_rule, str, &source_type) &
				(unsigned)ksu_hide_span_matches(tgt_rule, str, &target_type);
			rule_offset = tgt_rule - rule_buf->data + strlen(tgt_rule) + 1;
		}
	}

	if (source_hidden)
		str[source_type.start] = '!';
	if (target_hidden || rule_hidden)
		str[target_type.start] = '!';
	return source_hidden || target_hidden || rule_hidden;
}

#endif
