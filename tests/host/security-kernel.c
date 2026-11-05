// SPDX-License-Identifier: GPL-2.0-only
/* Linked into the disposable QEMU kernel only, never the phone image. */
#include <linux/init.h>
#include <linux/hid.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <net/sock.h>

#define VERIFY(x) do { if (!(x)) panic("security regression: %s:%d: %s", __func__, __LINE__, #x); } while (0)

static struct sk_buff *shared_packet(void)
{
	struct sk_buff *skb = alloc_skb(128, GFP_KERNEL);
	struct page *page = alloc_page(GFP_KERNEL);

	VERIFY(skb && page);
	memset(page_address(page), 0x5a, PAGE_SIZE);
	skb_add_rx_frag(skb, 0, page, 0, 512, PAGE_SIZE);
	skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
	return skb;
}

static void test_shared_fragments(void)
{
	struct sk_buff *source, *target, *copy;
	bool stolen;
	int delta;

	source = shared_packet();
	copy = pskb_copy(source, GFP_KERNEL);
	VERIFY(copy && skb_has_shared_frag(copy));
	VERIFY(skb_frag_page(&skb_shinfo(copy)->frags[0]) ==
	       skb_frag_page(&skb_shinfo(source)->frags[0]));
	kfree_skb(copy);
	kfree_skb(source);
	pr_info("PASS security_kernel_shared_copy\n");

	source = shared_packet();
	target = alloc_skb(128, GFP_KERNEL);
	VERIFY(target);
	VERIFY(skb_shift(target, source, 256) == 256);
	VERIFY(skb_has_shared_frag(target) && target->len == 256 && source->len == 256);
	kfree_skb(target);
	kfree_skb(source);
	pr_info("PASS security_kernel_shared_shift\n");

	source = shared_packet();
	target = alloc_skb(0, GFP_KERNEL);
	VERIFY(target);
	VERIFY(skb_try_coalesce(target, source, &stolen, &delta));
	VERIFY(!stolen && skb_has_shared_frag(target) && target->len == 512);
	kfree_skb_partial(source, stolen);
	kfree_skb(target);
	pr_info("PASS security_kernel_shared_coalesce\n");

	source = shared_packet();
	target = alloc_skb(128, GFP_KERNEL);
	VERIFY(target);
	memset(NAPI_GRO_CB(source), 0, sizeof(*NAPI_GRO_CB(source)));
	memset(NAPI_GRO_CB(target), 0, sizeof(*NAPI_GRO_CB(target)));
	NAPI_GRO_CB(target)->last = target;
	VERIFY(!skb_gro_receive(&target, source));
	VERIFY(skb_has_shared_frag(target) && target->len == 512);
	VERIFY(NAPI_GRO_CB(source)->free == NAPI_GRO_FREE);
	kfree_skb(source);
	kfree_skb(target);
	pr_info("PASS security_kernel_shared_gro\n");
}

static int __init security_backport_test(void)
{
	struct hid_device *hid = kzalloc(sizeof(*hid), GFP_KERNEL);

	VERIFY(hid);
	hid->report_enum[HID_INPUT_REPORT].numbered = 1;
	/* NULL data is safe only if zero length is rejected before report-ID read. */
	VERIFY(hid_report_raw_event(hid, HID_INPUT_REPORT, NULL, 0, 0) == -EINVAL);
	kfree(hid);
	pr_info("PASS security_kernel_hid_empty_report\n");
	test_shared_fragments();
	return 0;
}
late_initcall(security_backport_test);
