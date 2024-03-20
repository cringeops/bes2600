#include <linux/module.h>
#include <linux/usb.h>
#include "bes2600.h"
#include "sbus.h"
#include "wsm.h"
#include "bes2600_driver_mode.h"
#include "bes_chardev.h"
#include "hwio.h"

#define BES2600_USB_PIPE_INVALID BES2600_USB_PIPE_MAX

#define BES2600_USB_VENDOR_REQUEST  ( USB_TYPE_VENDOR | USB_RECIP_DEVICE )
#define BES2600_USB_VENDOR_REQ_IN   ( USB_DIR_IN | BES2600_USB_VENDOR_REQUEST )  /* 0xC0 */
#define BES2600_USB_VENDOR_REQ_OUT  ( USB_DIR_OUT | BES2600_USB_VENDOR_REQUEST ) /* 0x40 */

#define BES2600_USB_VENDOR_REQ_REG_READ        (1)
#define BES2600_USB_VENDOR_REQ_REG_WRITE       (2)

struct bes2600_enum_usb_dev {
	struct usb_device *udev;
	bool removed;
	bool need_enum;
};

static struct bes2600_enum_usb_dev usb_enum = {
	.udev = NULL,
	.removed = false,
};

struct sbus_priv;
/* usb device object */
struct bes2600_usb_pipe {
	struct list_head urb_list_head;
	struct usb_anchor urb_submitted;
	u32 urb_alloc;
	u32 urb_cnt;
	u32 urb_cnt_thresh;
	atomic_t urb_pending_cnt;
	unsigned int usb_pipe_handle;
	u32 flags;
	u8 ep_address;
	u8 logical_pipe_num;
	struct sbus_priv *ar_usb;
	u16 max_packet_size;
	struct work_struct io_complete_work;
	struct sk_buff_head io_comp_queue;
	struct usb_endpoint_descriptor *ep_desc;
};

struct sbus_priv {
	/* protects pipe->urb_list_head and  pipe->urb_cnt */
	spinlock_t cs_lock;
	struct bes2600_common	*core;

	struct usb_device *udev;
	struct usb_interface *interface;
	struct bes2600_usb_pipe pipes[BES2600_USB_PIPE_MAX];
	spinlock_t rx_queue_lock;
	struct sk_buff_head rx_queue;
	void *btdev;

	spinlock_t status_lock;
	sbus_irq_handler usb_irq_handler;
	void *irq_data;
	u32 int_control_reg;
	u32 int_status_reg;
	u32 io_dmabuf;
	struct mutex sbus_mutex;
};

#define BES2600_USB_PIPE_FLAG_TX    (1 << 0)

/* usb urb object */
struct bes2600_urb_context {
	struct list_head link;
	struct bes2600_usb_pipe *pipe;
	struct sk_buff *skb;
	struct urb *urb;
};

/* constants */
#define TX_URB_COUNT            49
#define RX_URB_COUNT            32
#define BES2600_USB_RX_BUFFER_SIZE  8192


/* USB endpoint definitions */
#define BES2600_USB_EP_ADDR_CTRL_IN             0x81
#define BES2600_USB_EP_ADDR_WLAN_IN             0x82
#define BES2600_USB_EP_ADDR_BT_IN               0x83

#define BES2600_USB_EP_ADDR_CTRL_OUT            0x01
#define BES2600_USB_EP_ADDR_WLAN_OUT            0x02
#define BES2600_USB_EP_ADDR_BT_OUT              0x03

/* function declarations */
static void bes2600_usb_recv_complete(struct urb *urb);

#define BES2600_USB_IS_BULK_EP(attr) (((attr) & 3) == 0x02)
#define BES2600_USB_IS_INT_EP(attr)  (((attr) & 3) == 0x03)
#define BES2600_USB_IS_ISOC_EP(attr)  (((attr) & 3) == 0x01)
#define BES2600_USB_IS_DIR_IN(addr)  ((addr) & 0x80)

static void bes2600_usb_irq_handler(struct sbus_priv *ar_usb)
{
	sbus_irq_handler handler = NULL;
	void *priv_data = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ar_usb->status_lock,flags);
	handler = ar_usb->usb_irq_handler;
	priv_data = ar_usb->irq_data;
	spin_unlock_irqrestore(&ar_usb->status_lock,flags);

	if(handler != 0)
		handler(priv_data);
}

static int bes2600_usb_test_control_reg(struct sbus_priv *ar_usb, int bitval)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&ar_usb->status_lock,flags);
	ret = ar_usb->int_control_reg & bitval;
	spin_unlock_irqrestore(&ar_usb->status_lock,flags);
	return ret;
}

static void bes2600_usb_set_status_reg(struct sbus_priv *ar_usb, int bitval)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&ar_usb->status_lock,flags);
	ret = ar_usb->int_status_reg |= bitval;
	spin_unlock_irqrestore(&ar_usb->status_lock,flags);
}

/* pipe/urb operations */
static struct bes2600_urb_context *
bes2600_usb_alloc_urb_from_pipe(struct bes2600_usb_pipe *pipe)
{
	struct bes2600_urb_context *urb_context = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pipe->ar_usb->cs_lock, flags);
	if (!list_empty(&pipe->urb_list_head)) {
		urb_context =
		    list_first_entry(&pipe->urb_list_head,
				     struct bes2600_urb_context, link);
		list_del(&urb_context->link);
		pipe->urb_cnt--;
	}
	spin_unlock_irqrestore(&pipe->ar_usb->cs_lock, flags);

	return urb_context;
}

static void bes2600_usb_free_urb_to_pipe(struct bes2600_usb_pipe *pipe,
					struct bes2600_urb_context *urb_context)
{
	unsigned long flags;

	spin_lock_irqsave(&pipe->ar_usb->cs_lock, flags);
	pipe->urb_cnt++;

	list_add(&urb_context->link, &pipe->urb_list_head);
	spin_unlock_irqrestore(&pipe->ar_usb->cs_lock, flags);
}

static void bes2600_usb_cleanup_recv_urb(struct bes2600_urb_context *urb_context)
{
	if (urb_context->skb) {
		dev_kfree_skb(urb_context->skb);
		urb_context->skb = NULL;
	}
	bes2600_usb_free_urb_to_pipe(urb_context->pipe, urb_context);
}

static inline struct sbus_priv *bes2600_usb_priv(struct bes2600_common *core)
{
	return (struct sbus_priv *)core->sbus_priv;
}

/* pipe resource allocation/cleanup */
static int bes2600_usb_alloc_pipe_resources(struct bes2600_usb_pipe *pipe,
					   int urb_cnt)
{
	struct bes2600_urb_context *urb_context;
	int status = 0, i;

	INIT_LIST_HEAD(&pipe->urb_list_head);
	init_usb_anchor(&pipe->urb_submitted);

	for (i = 0; i < urb_cnt; i++) {
		urb_context = kzalloc(sizeof(struct bes2600_urb_context),
				      GFP_KERNEL);
		if (urb_context == NULL) {
			status = -ENOMEM;
			goto fail_alloc_pipe_resources;
		}

		urb_context->urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (urb_context->urb == NULL) {
			kfree(urb_context);
			status = -ENOMEM;
			goto fail_alloc_pipe_resources;
		}
		urb_context->pipe = pipe;

		/*
		 * we are only allocate the urb contexts here, the actual URB
		 * is allocated from the kernel as needed to do a transaction
		 */
		pipe->urb_alloc++;
		bes2600_usb_free_urb_to_pipe(pipe, urb_context);
	}

	bes2600_dbg(BES2600_DBG_USB,
		   "bes2600 usb: alloc resources lpipe:%d hpipe:0x%X urbs:%d\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->urb_alloc);

fail_alloc_pipe_resources:
	return status;
}

static void bes2600_usb_free_pipe_resources(struct bes2600_usb_pipe *pipe)
{
	struct bes2600_urb_context *urb_context;

	if (pipe->ar_usb == NULL) {
		/* nothing allocated for this pipe */
		return;
	}

	bes2600_dbg(BES2600_DBG_USB,
		   "bes2600 usb: free resources lpipe:%d"
		   "hpipe:0x%X urbs:%d avail:%d\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->urb_alloc, pipe->urb_cnt);

	if (pipe->urb_alloc != pipe->urb_cnt) {
		bes2600_dbg(BES2600_DBG_USB,
			   "bes2600 usb: urb leak! lpipe:%d"
			   "hpipe:0x%X urbs:%d avail:%d\n",
			   pipe->logical_pipe_num, pipe->usb_pipe_handle,
			   pipe->urb_alloc, pipe->urb_cnt);
	}

	while (true) {
		urb_context = bes2600_usb_alloc_urb_from_pipe(pipe);
		if (urb_context == NULL)
			break;
		usb_free_urb(urb_context->urb);
		urb_context->urb = NULL;
		kfree(urb_context);
	}
}

static void bes2600_usb_cleanup_pipe_resources(struct sbus_priv *ar_usb)
{
	int i;

	for (i = 0; i < BES2600_USB_PIPE_MAX; i++){
		if ((i != BES2600_USB_PIPE_RX_BT) &&
		   (i != BES2600_USB_PIPE_TX_BT))
			bes2600_usb_free_pipe_resources(&ar_usb->pipes[i]);
	}
}

static u8 bes2600_usb_get_logical_pipe_num(struct sbus_priv *ar_usb,
					  u8 ep_address, int *urb_count)
{
	u8 pipe_num = BES2600_USB_PIPE_INVALID;

	switch (ep_address) {
	case BES2600_USB_EP_ADDR_CTRL_IN:
		pipe_num = BES2600_USB_PIPE_RX_CTRL;
		*urb_count = RX_URB_COUNT;
		break;
	case BES2600_USB_EP_ADDR_WLAN_IN:
		pipe_num = BES2600_USB_PIPE_RX_WLAN;
		*urb_count = RX_URB_COUNT;
		break;
	case BES2600_USB_EP_ADDR_BT_IN:
		pipe_num = BES2600_USB_PIPE_RX_BT;
		*urb_count = RX_URB_COUNT;
		break;
	case BES2600_USB_EP_ADDR_CTRL_OUT:
		pipe_num = BES2600_USB_PIPE_TX_CTRL;
		*urb_count = TX_URB_COUNT;
		break;
	case BES2600_USB_EP_ADDR_WLAN_OUT:
		pipe_num = BES2600_USB_PIPE_TX_WLAN;
		*urb_count = TX_URB_COUNT;
		break;
	case BES2600_USB_EP_ADDR_BT_OUT:
		pipe_num = BES2600_USB_PIPE_TX_BT;
		*urb_count = TX_URB_COUNT;
		break;
	default:
		/* note: there may be endpoints not currently used */
		break;
	}

	return pipe_num;
}

static int bes2600_usb_setup_pipe_resources(struct sbus_priv *ar_usb)
{
	struct usb_interface *interface = ar_usb->interface;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
	struct usb_endpoint_descriptor *endpoint;
	struct bes2600_usb_pipe *pipe;
	int i, urbcount, status = 0;
	u8 pipe_num;

	bes2600_dbg(BES2600_DBG_USB, "setting up USB Pipes using interface\n");

	/* walk decriptors and setup pipes */
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (BES2600_USB_IS_BULK_EP(endpoint->bmAttributes)) {
			bes2600_dbg(BES2600_DBG_USB,
				   "%s Bulk Ep:0x%2.2X maxpktsz:%d\n",
				   BES2600_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize));
		} else if (BES2600_USB_IS_INT_EP(endpoint->bmAttributes)) {
			bes2600_dbg(BES2600_DBG_USB,
				   "%s Int Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   BES2600_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize),
				   endpoint->bInterval);
		} else if (BES2600_USB_IS_ISOC_EP(endpoint->bmAttributes)) {
			/* TODO for ISO */
			bes2600_dbg(BES2600_DBG_USB,
				   "%s ISOC Ep:0x%2.2X maxpktsz:%d interval:%d\n",
				   BES2600_USB_IS_DIR_IN
				   (endpoint->bEndpointAddress) ?
				   "RX" : "TX", endpoint->bEndpointAddress,
				   le16_to_cpu(endpoint->wMaxPacketSize),
				   endpoint->bInterval);
		}
		urbcount = 0;

		pipe_num =
		    bes2600_usb_get_logical_pipe_num(ar_usb,
						    endpoint->bEndpointAddress,
						    &urbcount);
		if (pipe_num == BES2600_USB_PIPE_INVALID)
			continue;

		pipe = &ar_usb->pipes[pipe_num];
		if (pipe->ar_usb != NULL) {
			/* hmmm..pipe was already setup */
			continue;
		}

		atomic_set(&pipe->urb_pending_cnt, 0);
		pipe->ar_usb = ar_usb;
		pipe->logical_pipe_num = pipe_num;
		pipe->ep_address = endpoint->bEndpointAddress;
		pipe->max_packet_size = le16_to_cpu(endpoint->wMaxPacketSize);

		if (BES2600_USB_IS_BULK_EP(endpoint->bmAttributes)) {
			if (BES2600_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvbulkpipe(ar_usb->udev,
						    pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndbulkpipe(ar_usb->udev,
						    pipe->ep_address);
			}
		} else if (BES2600_USB_IS_INT_EP(endpoint->bmAttributes)) {
			if (BES2600_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvintpipe(ar_usb->udev,
						   pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndintpipe(ar_usb->udev,
						   pipe->ep_address);
			}
		} else if (BES2600_USB_IS_ISOC_EP(endpoint->bmAttributes)) {
			/* TODO for ISO */
			if (BES2600_USB_IS_DIR_IN(pipe->ep_address)) {
				pipe->usb_pipe_handle =
				    usb_rcvisocpipe(ar_usb->udev,
						    pipe->ep_address);
			} else {
				pipe->usb_pipe_handle =
				    usb_sndisocpipe(ar_usb->udev,
						    pipe->ep_address);
			}
		}

		pipe->ep_desc = endpoint;

		if (!BES2600_USB_IS_DIR_IN(pipe->ep_address))
			pipe->flags |= BES2600_USB_PIPE_FLAG_TX;

		if((pipe_num != BES2600_USB_PIPE_RX_BT) &&
			(pipe_num !=  BES2600_USB_PIPE_TX_BT)){
			status = bes2600_usb_alloc_pipe_resources(pipe, urbcount);
			if (status != 0)
				break;
		}
	}
#ifdef CONFIG_BES2600_BT
	status = bes2600_btusb_setup_pipes(ar_usb);
#endif

	return status;
}

/* pipe operations */
static void bes2600_usb_post_recv_transfers(struct bes2600_usb_pipe *recv_pipe,
					   int buffer_length)
{
	struct bes2600_urb_context *urb_context;
	struct urb *urb;
	int usb_status;

	while (true) {
		urb_context = bes2600_usb_alloc_urb_from_pipe(recv_pipe);
		if (urb_context == NULL)
			break;

		urb_context->skb = dev_alloc_skb(buffer_length);
		if (urb_context->skb == NULL)
			goto err_cleanup_urb;

		urb = urb_context->urb;
		BUG_ON(!urb);
		usb_fill_bulk_urb(urb,
				  recv_pipe->ar_usb->udev,
				  recv_pipe->usb_pipe_handle,
				  urb_context->skb->data,
				  buffer_length,
				  bes2600_usb_recv_complete, urb_context);

		bes2600_dbg(BES2600_DBG_USB,
			   "bes2600 usb: bulk recv submit:%d, 0x%X (ep:0x%2.2X), %d bytes buf:0x%p\n",
			   recv_pipe->logical_pipe_num,
			   recv_pipe->usb_pipe_handle, recv_pipe->ep_address,
			   buffer_length, urb_context->skb);

		usb_anchor_urb(urb, &recv_pipe->urb_submitted);
		usb_status = usb_submit_urb(urb, GFP_ATOMIC);
		if (usb_status) {
			bes2600_dbg(BES2600_DBG_USB,
				   "bes2600 usb : usb bulk recv failed %d\n",
				   usb_status);
			usb_unanchor_urb(urb);
			goto err_cleanup_urb;
		}
	}
	return;

err_cleanup_urb:
	bes2600_usb_cleanup_recv_urb(urb_context);
	return;
}

static void bes2600_usb_flush_all(struct sbus_priv *ar_usb)
{
	int i;

	for (i = 0; i < BES2600_USB_PIPE_MAX; i++) {
		if ((i != BES2600_USB_PIPE_RX_BT) &&
		   (i !=  BES2600_USB_PIPE_TX_BT)){
			if (ar_usb->pipes[i].ar_usb != NULL)
				usb_kill_anchored_urbs(&ar_usb->pipes[i].urb_submitted);
		}
	}

	/*
	 * Flushing any pending I/O may schedule work this call will block
	 * until all scheduled work runs to completion.
	 */
	flush_scheduled_work();
}

static void bes2600_usb_start_recv_pipes(struct sbus_priv *ar_usb)
{
	ar_usb->pipes[BES2600_USB_PIPE_RX_WLAN].urb_cnt_thresh = 1;
	bes2600_usb_post_recv_transfers(&ar_usb->pipes[BES2600_USB_PIPE_RX_WLAN], BES2600_USB_RX_BUFFER_SIZE);
}

void bes2600_recv_buf_put(struct sbus_priv *ar_usb, struct sk_buff *skb)
{
	unsigned long flags;
	if (!skb)
		return;

	spin_lock_irqsave(&ar_usb->rx_queue_lock, flags);
	skb_queue_tail(&ar_usb->rx_queue, skb);
	spin_unlock_irqrestore(&ar_usb->rx_queue_lock, flags);
}

struct sk_buff *bes2600_recv_buf_get(struct sbus_priv *ar_usb)
{
	unsigned long flags;
	struct sk_buff *skb = NULL;

	spin_lock_irqsave(&ar_usb->rx_queue_lock, flags);
	skb = skb_dequeue(&ar_usb->rx_queue);
	spin_unlock_irqrestore(&ar_usb->rx_queue_lock, flags);

	return skb;
}
/* hif usb rx/tx completion functions */
static void bes2600_usb_recv_complete(struct urb *urb)
{
	struct bes2600_urb_context *urb_context = urb->context;
	struct bes2600_usb_pipe *pipe = urb_context->pipe;
	struct sk_buff *skb = NULL;
	int status = 0;

	bes2600_dbg(BES2600_DBG_USB,
		   "%s: recv pipe: %d, stat:%d, len:%d urb:0x%p\n", __func__,
		   pipe->logical_pipe_num, urb->status, urb->actual_length,
		   urb);

	if (urb->status != 0) {
		status = -EIO;
		switch (urb->status) {
		case -ECONNRESET:
		case -ENOENT:
		case -ESHUTDOWN:
			/*
			 * no need to spew these errors when device
			 * removed or urb killed due to driver shutdown
			 */
			status = -ECANCELED;
			break;
		default:
			bes2600_dbg(BES2600_DBG_USB,
				   "%s recv pipe: %d (ep:0x%2.2X), failed:%d\n",
				   __func__, pipe->logical_pipe_num,
				   pipe->ep_address, urb->status);
			break;
		}
		goto cleanup_recv_urb;
	}

	if (urb->actual_length == 0)
		goto cleanup_recv_urb;

	skb = urb_context->skb;
	skb_put(skb, urb->actual_length);

	/* we are going to pass it up */
	urb_context->skb = NULL;

	// set virtual register
	if(bes2600_usb_test_control_reg(pipe->ar_usb, BES_USB_FW_RX_INDICATION))
		bes2600_usb_set_status_reg(pipe->ar_usb, BES_USB_FW_RX_INDICATION);

	/* note: queue implements a lock */
#ifndef BES2600_RX_IN_BH
	skb_queue_tail(&pipe->io_comp_queue, skb);
	schedule_work(&pipe->io_complete_work);
#else
	bes2600_recv_buf_put(pipe->ar_usb, skb);
	bes2600_usb_irq_handler(pipe->ar_usb);
#endif
cleanup_recv_urb:
	bes2600_usb_cleanup_recv_urb(urb_context);
	usb_unanchor_urb(urb);

	if (status == 0 &&
	    pipe->urb_cnt >= pipe->urb_cnt_thresh) {
		/* our free urbs are piling up, post more transfers */
		bes2600_usb_post_recv_transfers(pipe, BES2600_USB_RX_BUFFER_SIZE);
	}
}

static void bes2600_usb_transmit_complete(struct urb *urb)
{
	struct bes2600_urb_context *urb_context = urb->context;
	struct bes2600_usb_pipe *pipe = urb_context->pipe;
	struct sk_buff *skb;

	bes2600_dbg(BES2600_DBG_USB, "%s: pipe: %d, stat:%d, len:%d\n",
		   __func__, pipe->logical_pipe_num, urb->status, urb->actual_length);

	if (urb->status != 0) {
		bes2600_err(BES2600_DBG_USB,
			   "%s:  pipe: %d, failed:%d\n",
			   __func__, pipe->logical_pipe_num, urb->status);
	}

	skb = urb_context->skb;
	urb_context->skb = NULL;
	bes2600_usb_free_urb_to_pipe(urb_context->pipe, urb_context);
	usb_unanchor_urb(urb);

	atomic_sub(1, &pipe->urb_pending_cnt);

	// set virtual register
	if(!urb->status && bes2600_usb_test_control_reg(pipe->ar_usb, BES_USB_FW_TX_DONE))
		bes2600_usb_set_status_reg(pipe->ar_usb, BES_USB_FW_TX_DONE);

	// notify tx done event
	bes2600_usb_irq_handler(pipe->ar_usb);

	/* note: queue implements a lock */
	//skb_queue_tail(&pipe->io_comp_queue, skb);
	//schedule_work(&pipe->io_complete_work);
}
int wsm_release_tx_buffer(struct bes2600_common *priv, int count);
void bes2600_bh_wakeup(struct bes2600_common *hw_priv);

void bes2600_usb_rx_complete(struct bes2600_common *priv, struct sk_buff *skb)
{
	static u8 data[1600];
	static u32 cnt = 0;

	struct wsm_hdr *wsm;
	size_t wsm_len;
	u16 wsm_id;
	u8 wsm_seq;
	u32 confirm_label = 0x0; /* wsm to mcu cmd cnfirm label */

	wsm = (struct wsm_hdr *)skb->data;
	wsm_len = __le16_to_cpu(wsm->len);
	if (WARN_ON(wsm_len > skb->len))
		goto err;

	if (priv->wsm_enable_wsm_dumps)
		bes2600_dbg_dump(BES2600_DBG_SPI, "<--", skb->data, wsm_len);

	wsm_id  = __le16_to_cpu(wsm->id) & 0xFFF;
	wsm_seq = (__le16_to_cpu(wsm->id) >> 13) & 7;

	skb_trim(skb, wsm_len);

	if (wsm_id == 0x0800) {
		wsm_handle_exception(priv,
				     &skb->data[sizeof(*wsm)],
				     wsm_len - sizeof(*wsm));
		bes2600_err(BES2600_DBG_SYS, "wsm exception.!\n");
		goto err;
	} else if ((wsm_seq != priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)])) {
		bes2600_err(BES2600_DBG_SYS, "seq error %u. %u. 0x%x.", wsm_seq, priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)], wsm_id);
		goto err;
	}
	priv->wsm_rx_seq[WSM_TXRX_SEQ_IDX(wsm_id)] = (wsm_seq + 1) & 7;

	if (IS_DRIVER_TO_MCU_CMD(wsm_id))
		confirm_label = __le32_to_cpu(((struct wsm_mcu_hdr *)wsm)->handle_label);

	if (WSM_CONFIRM_CONDITION(wsm_id, confirm_label)) {
		int rc = wsm_release_tx_buffer(priv, 1);
		if (WARN_ON(rc < 0))
			return;
	}

	bes2600_bh_wakeup(priv);

	/* bes2600_wsm_rx takes care on SKB livetime */
	//if (WARN_ON(wsm_handle_rx(priv, wsm_id, wsm, &skb)))
	if ((wsm_handle_rx(priv, wsm_id, wsm, &skb)))
		goto err;

	if (skb) {
		dev_kfree_skb(skb);
		skb = NULL;
	}
	return;
err:
	if (skb) {
		dev_kfree_skb(skb);
		skb = NULL;
	}

	if(cnt++ >= 0)
		priv->sbus_ops->pipe_send(priv->sbus_priv, BES2600_USB_PIPE_TX_WLAN, 200, data);
	return;
}

void bes2600_tx_complete(struct bes2600_common *core, struct sk_buff *skb)
{
	//bes2600_htc_tx_complete(core, skb);
}
EXPORT_SYMBOL(bes2600_tx_complete);

void bes2600_rx_complete(struct bes2600_common *core, struct sk_buff *skb, u8 pipe)
{
	//bes2600_htc_rx_complete(core, skb, pipe);

	if (!bes2600_chrdev_is_bus_error())
		bes2600_usb_rx_complete(core, skb);
	else if (skb) {
		dev_kfree_skb(skb);
	}
}
EXPORT_SYMBOL(bes2600_rx_complete);


static void bes2600_usb_io_comp_work(struct work_struct *work)
{
	struct bes2600_usb_pipe *pipe = container_of(work,
						    struct bes2600_usb_pipe,
						    io_complete_work);
	struct sbus_priv *ar_usb;
	struct sk_buff *skb;

	ar_usb = pipe->ar_usb;

	while ((skb = skb_dequeue(&pipe->io_comp_queue))) {
		if (pipe->flags & BES2600_USB_PIPE_FLAG_TX) {
			bes2600_dbg(BES2600_DBG_USB,
				   "bes2600 usb xmit callback buf:0x%p\n", skb);
			bes2600_tx_complete(ar_usb->core, skb);
		} else {
			bes2600_dbg(BES2600_DBG_USB,
				   "bes2600 usb recv callback buf:0x%p\n", skb);
			bes2600_rx_complete(ar_usb->core, skb,
						pipe->logical_pipe_num);
		}
	}
}

static int bes2600_usb_send(struct sbus_priv *self, u8 PipeID, u32 len, u8 *data)
{
	struct sbus_priv *device = self;
	struct bes2600_usb_pipe *pipe = &device->pipes[PipeID];
	struct bes2600_urb_context *urb_context;
	int usb_status, status = 0;
	struct urb *urb;
	int send_cnt = atomic_read(&pipe->urb_pending_cnt);

	bes2600_dbg(BES2600_DBG_USB, "+%s pipe : %d, buf:0x%p, send_cnt:%d.\n",
		  	 __func__, PipeID, data, send_cnt);

	if (bes2600_chrdev_is_bus_error()) {
		bes2600_tx_loop_pipe_send(self->core, data, len);
		return 0;
	}

	urb_context = bes2600_usb_alloc_urb_from_pipe(pipe);

	if (urb_context == NULL) {
		/*
		 * TODO: it is possible to run out of urbs if
		 * 2 endpoints map to the same pipe ID
		 */
		bes2600_err(BES2600_DBG_USB, "%s pipe:%d no urbs left. URB Cnt : %d\n",
			   	__func__, PipeID, pipe->urb_cnt);
		status = -ENOMEM;
		goto fail_hif_send;
	}

	urb_context->skb = (struct sk_buff *)data;
	urb = urb_context->urb;
	BUG_ON(!urb);
	usb_fill_bulk_urb(urb,
			  device->udev,
			  pipe->usb_pipe_handle,
			  data,
			  len,
			  bes2600_usb_transmit_complete, urb_context);

	if ((len % pipe->max_packet_size) == 0) {
		/* hit a max packet boundary on this pipe */
		urb->transfer_flags |= URB_ZERO_PACKET;
	}

	bes2600_dbg(BES2600_DBG_USB,
		   "athusb bulk send submit:%d, 0x%X (ep:0x%2.2X), %d bytes\n",
		   pipe->logical_pipe_num, pipe->usb_pipe_handle,
		   pipe->ep_address, len);

	usb_anchor_urb(urb, &pipe->urb_submitted);
	usb_status = usb_submit_urb(urb, GFP_ATOMIC);

	atomic_add(1, &pipe->urb_pending_cnt);

	if (usb_status) {
		bes2600_err(BES2600_DBG_USB,
			   "bes2600 usb : usb bulk transmit failed %d\n",
			   usb_status);
		usb_unanchor_urb(urb);
		bes2600_usb_free_urb_to_pipe(urb_context->pipe,
					    urb_context);
		atomic_sub(1, &pipe->urb_pending_cnt);
		status = -EINVAL;
	}
fail_hif_send:
	return status;
}

static void * bes2600_usb_read(struct sbus_priv *self)
{
	if (bes2600_chrdev_is_bus_error())
		return (void *)bes2600_tx_loop_read(self->core);

	return (void *)bes2600_recv_buf_get(self);
}

static void bes2600_usb_destroy(struct sbus_priv *ar_usb)
{
	bes2600_usb_flush_all(ar_usb);

	bes2600_usb_cleanup_pipe_resources(ar_usb);

	usb_set_intfdata(ar_usb->interface, NULL);

	kfree(ar_usb);
}

static struct sbus_priv *bes2600_usb_create(struct usb_interface *interface)
{
	struct usb_device *dev = interface_to_usbdev(interface);
	struct sbus_priv *ar_usb;
	struct bes2600_usb_pipe *pipe;
	int status = 0;
	int i;

	ar_usb = kzalloc(sizeof(struct sbus_priv), GFP_KERNEL);
	if (ar_usb == NULL)
		goto fail_bes2600_usb_create;

	usb_set_intfdata(interface, ar_usb);
	spin_lock_init(&(ar_usb->cs_lock));
	mutex_init(&ar_usb->sbus_mutex);
	ar_usb->udev = dev;
	ar_usb->interface = interface;
	ar_usb->core = NULL;

	for (i = 0; i < BES2600_USB_PIPE_MAX; i++) {
		if((i != BES2600_USB_PIPE_RX_BT) &&
		   (i != BES2600_USB_PIPE_TX_BT)){
			pipe = &ar_usb->pipes[i];
			INIT_WORK(&pipe->io_complete_work,
				  bes2600_usb_io_comp_work);
			skb_queue_head_init(&pipe->io_comp_queue);
		}
	}

	spin_lock_init(&ar_usb->rx_queue_lock);
	skb_queue_head_init(&ar_usb->rx_queue);

	spin_lock_init(&ar_usb->status_lock);
	ar_usb->usb_irq_handler = NULL;
	ar_usb->irq_data = NULL;
	ar_usb->int_control_reg = 0;
	ar_usb->int_status_reg = 0;

	status = bes2600_usb_setup_pipe_resources(ar_usb);

fail_bes2600_usb_create:
	if (status != 0) {
		bes2600_usb_destroy(ar_usb);
		ar_usb = NULL;
	}
	return ar_usb;
}

void bes2600_core_release(struct bes2600_common *self);

static void bes2600_usb_device_detached(struct usb_interface *interface)
{
	struct sbus_priv *self = usb_get_intfdata(interface);
	if (self) {
		if (self->core) {
			bes2600_core_release(self->core);
			self->core = NULL;
		}
		bes2600_usb_destroy(self);
	}
}

static int bes2600_usb_init(struct sbus_priv *self, struct bes2600_common *core)
{
	int queue_empty = -1;

	self->core = core;
	spin_lock_bh(&self->status_lock);
	self->int_status_reg = 0;
	self->int_control_reg = 0;
	spin_unlock_bh(&self->status_lock);

	spin_lock_bh(&self->rx_queue_lock);
	queue_empty = skb_queue_empty(&self->rx_queue);
	spin_unlock_bh(&self->rx_queue_lock);

	/* revoke rx work if firmware ready arrived before bes2600 probe done */
	if (!queue_empty) {
		bes2600_irq_handler(core);
	}

	return 0;
}

static int bes2600_usb_memcpy_fromio(struct sbus_priv *self,
				     unsigned int addr,
				     void *dst, int count)
{
	return 0;
}

static int bes2600_usb_memcpy_toio(struct sbus_priv *self,
				   unsigned int addr,
				   const void *src, int count)
{
	return 0;
}

static void bes2600_usb_lock(struct sbus_priv *self)
{
}

static void bes2600_usb_unlock(struct sbus_priv *self)
{
}

static size_t bes2600_usb_align_size(struct sbus_priv *self, size_t size)
{
	return size;
}

int bes2600_usb_irq_subscribe(struct sbus_priv *self, sbus_irq_handler handler, void *priv)
{
	spin_lock_bh(&self->status_lock);
	self->usb_irq_handler = handler;
	self->irq_data = priv;
	spin_unlock_bh(&self->status_lock);
	return 0;
}

int bes2600_usb_irq_unsubscribe(struct sbus_priv *self)
{
	spin_lock_bh(&self->status_lock);
	self->usb_irq_handler = NULL;
	self->irq_data = NULL;
	spin_unlock_bh(&self->status_lock);
	return 0;
}

int bes2600_usb_reset(struct sbus_priv *self)
{
	self->core = NULL;
	spin_lock_bh(&self->status_lock);
	self->int_status_reg = 0;
	self->int_control_reg = 0;
	spin_unlock_bh(&self->status_lock);
	return 0;
}

int bes2600_usb_set_block_size(struct sbus_priv *self, size_t size)
{
	return 0;
}

static int bes2600_usb_reg_read(struct sbus_priv *self, u32 reg, void *dst, int count)
{
	int ret = 0;
	unsigned long flags;
	if(reg == BES_USB_CONTROL_REG) {
		spin_lock_irqsave(&self->status_lock,flags);
		*((u32 *)dst) = self->int_control_reg;
		spin_unlock_irqrestore(&self->status_lock,flags);
	}
	else if(reg == BES_USB_STATUS_REG) {
		spin_lock_irqsave(&self->status_lock,flags);
		*((u32 *)dst) = self->int_status_reg;
		spin_unlock_irqrestore(&self->status_lock,flags);
	}
	else
		ret = -EINVAL;

	return ret;
}

static int bes2600_usb_reg_write(struct sbus_priv *self, u32 reg, const void *src, int count)
{
	int ret = 0;
	unsigned long flags;
	if(reg == BES_USB_CONTROL_REG) {
		spin_lock_irqsave(&self->status_lock,flags);
		self->int_control_reg = *((u32 *)src);
		spin_unlock_irqrestore(&self->status_lock,flags);
	}
	else if(reg == BES_USB_STATUS_REG) {
		spin_lock_irqsave(&self->status_lock,flags);
		self->int_status_reg = *((u32 *)src);
		spin_unlock_irqrestore(&self->status_lock,flags);
	}
	else
		ret = -EINVAL;

	return ret;
}

static int bes2600_usb_ioread(struct sbus_priv *sbus_priv, u32 *r_val)
{
	u32 val;
	int ret = 0;

	sbus_priv->io_dmabuf = 0;
	ret = usb_control_msg(sbus_priv->udev, usb_rcvctrlpipe(sbus_priv->udev, 0),
	                      BES2600_USB_VENDOR_REQ_REG_READ, BES2600_USB_VENDOR_REQ_IN,
	                      0, 0, &sbus_priv->io_dmabuf, sizeof(sbus_priv->io_dmabuf), HZ / 2);

	if (ret == sizeof(sbus_priv->io_dmabuf)) {
		val = le32_to_cpu(sbus_priv->io_dmabuf);
		*r_val = val;
		ret = 0;
	} else {
		ret = -EIO;
	}

	return ret;
}

int bes2600_usb_iowrite(struct sbus_priv *sbus_priv, u32 val)
{
	int ret = 0;

	sbus_priv->io_dmabuf = cpu_to_le32(val);
	ret = usb_control_msg(sbus_priv->udev, usb_sndctrlpipe(sbus_priv->udev, 0),
	                      BES2600_USB_VENDOR_REQ_REG_WRITE, BES2600_USB_VENDOR_REQ_OUT,
	                      0, 0, &sbus_priv->io_dmabuf, sizeof(sbus_priv->io_dmabuf), HZ / 2);

	if (ret > 0)
		ret = 0;

	return ret;
}

static int bes2600_usb_reboot(struct sbus_priv *self)
{
	int ret;

	mutex_lock(&self->sbus_mutex);
	ret = bes2600_usb_iowrite(self, BES_SLAVE_STATUS_REBOOT);
	mutex_unlock(&self->sbus_mutex);

	return ret;
}

static void bes2600_check_usb_dev_state(void)
{
	if (usb_enum.udev && !usb_enum.removed)
		usb_enum.need_enum = true;
	else
		usb_enum.need_enum = false;
}

static void bes2600_enum_usb_dev(void)
{
	int ret;
	u32 *val;

	if (!usb_enum.need_enum)
		return;

	val = kmalloc(sizeof(*val), GFP_KERNEL);
	if (!val) {
		ret = -ENOMEM;
		goto exit;
	}

	*val = cpu_to_le32(BES_SLAVE_STATUS_REBOOT);
	ret = usb_control_msg(usb_enum.udev, usb_sndctrlpipe(usb_enum.udev, 0),
	                      BES2600_USB_VENDOR_REQ_REG_WRITE, BES2600_USB_VENDOR_REQ_OUT,
	                      0, 0, val, sizeof(*val), HZ / 2);

	kfree(val);
	usb_enum.removed = false;

exit:
	if (ret <= 0)
		bes2600_err(BES2600_DBG_USB, "%s fail, ret: %d\n", __func__, ret);
}

int bes2600_usb_wait_status(struct sbus_priv *sbus_priv, u32 rd_status, bool target_val, u32 wait, u32 timeout)
{
	int ret = 0;
	u8 retry = 0;
	u32 val = 0;
	u32 retry_max = timeout / wait;

	do {
		msleep(wait);
		ret = bes2600_usb_ioread(sbus_priv, &val);
	} while(!((ret == 0) && (((val & rd_status) == target_val * rd_status))) && ++retry < retry_max);

	bes2600_dbg(BES2600_DBG_USB, "%s, val: %u, rd_status: %u, wait: %u, timeout: %u, retry_max: %u, retry: %u\n", __func__,
	val, rd_status, wait, timeout, retry_max, retry);

	if (!ret && (((val & rd_status) != target_val * rd_status)))
		ret = -ETIMEDOUT;

	if (ret)
		bes2600_err(BES2600_DBG_USB, "%s failed, ret: %d\n", __func__, ret);

	return ret;
}

static int bes2600_usb_active(struct sbus_priv *self, int sub_system)
{
	u16 cfg;
	u8 cfm = 0;
	int ret = 0;

	/* nosignal mode only allow SUBSYSTEM_WIFI */
	if (!bes2600_chrdev_is_signal_mode() && sub_system != SUBSYSTEM_WIFI)
		return -EINVAL;

	/* don't read/write usb when usb error */
	if (bes2600_chrdev_is_bus_error())
		return 0;

	/* prevent concurrent access */
	mutex_lock(&self->sbus_mutex);

	/* set config and confirm value */
	if (sub_system == SUBSYSTEM_MCU) {
		cfg = BES_SUBSYSTEM_MCU_ACTIVE;
		cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
	} else if (sub_system == SUBSYSTEM_WIFI) {
		cfg = BES_SUBSYSTEM_WIFI_ACTIVE;
		cfm = BES_SLAVE_STATUS_WIFI_READY;
	} else if (sub_system == SUBSYSTEM_BT) {
		cfg = BES_SUBSYSTEM_BT_ACTIVE;
		cfm = BES_SLAVE_STATUS_BT_READY;
	} else if (sub_system == SUBSYSTEM_BT_LP) {
		cfg = BES_SUBSYSTEM_BT_WAKEUP;
		cfm = BES_SLAVE_STATUS_BT_WAKE_READY;
	} else {
		mutex_unlock(&self->sbus_mutex);
		return -EINVAL;
	}

	ret = bes2600_usb_iowrite(self, cfg);
	if (ret) {
		bes2600_err(BES2600_DBG_USB, "%s failed, ret: %d\n", __func__, ret);
		goto err;
	}

	ret = bes2600_usb_wait_status(self, cfm, true, 5, 100);
	if (ret)
		bes2600_err(BES2600_DBG_USB, "%s, %u confirm failed\n", __func__, cfm);

	mutex_unlock(&self->sbus_mutex);

	return ret;

err:
	mutex_unlock(&self->sbus_mutex);

	bes2600_chrdev_wifi_force_close(self->core, false);
	return -ENODEV;
}

static int bes2600_usb_deactive(struct sbus_priv *self, int sub_system)
{
	u16 cfg;
	u8 cfm = 0;
	int ret = 0;

	/* nosignal mode only allow SUBSYSTEM_WIFI */
	if (!bes2600_chrdev_is_signal_mode() && sub_system != SUBSYSTEM_WIFI)
		return -EINVAL;

	/* don't read/write usb when usb error */
	if (bes2600_chrdev_is_bus_error())
		return 0;

	/* prevent concurrent access */
	mutex_lock(&self->sbus_mutex);

	/* set config and confirm value */
	if (sub_system == SUBSYSTEM_MCU) {
		cfg = BES_SUBSYSTEM_MCU_DEACTIVE;
		cfm = BES_SLAVE_STATUS_MCU_WAKEUP_READY;
	} else if (sub_system == SUBSYSTEM_WIFI) {
		cfg = BES_SUBSYSTEM_WIFI_DEACTIVE;
		cfm = BES_SLAVE_STATUS_WIFI_READY;
	} else if(sub_system == SUBSYSTEM_BT) {
		cfg = BES_SUBSYSTEM_BT_DEACTIVE;
		cfm = BES_SLAVE_STATUS_BT_READY;
	} else if(sub_system == SUBSYSTEM_BT_LP) {
		cfg = BES_SUBSYSTEM_BT_SLEEP;
		cfm = BES_SLAVE_STATUS_BT_WAKE_READY;
	} else {
		mutex_unlock(&self->sbus_mutex);
		return -EINVAL;
	}

	ret = bes2600_usb_iowrite(self, cfg);
	if (ret) {
		bes2600_err(BES2600_DBG_USB, "%s failed, ret: %d\n", __func__, ret);
		goto err;
	}

	ret = bes2600_usb_wait_status(self, cfm, false, 5, 100);
	if (ret)
		bes2600_err(BES2600_DBG_USB, "%s, %u confirm failed\n", __func__, cfm);

	mutex_unlock(&self->sbus_mutex);

	return ret;

err:
	mutex_unlock(&self->sbus_mutex);

	bes2600_chrdev_wifi_force_close(self->core, false);
	return -ENODEV;
}

static struct sbus_ops bes2600_usb_ops = {
	.init				= bes2600_usb_init,
	.sbus_memcpy_fromio	= bes2600_usb_memcpy_fromio,
	.sbus_memcpy_toio	= bes2600_usb_memcpy_toio,
	.lock			= bes2600_usb_lock,
	.unlock			= bes2600_usb_unlock,
	.irq_subscribe		= bes2600_usb_irq_subscribe,
	.irq_unsubscribe	= bes2600_usb_irq_unsubscribe,
	.reset			= bes2600_usb_reset,
	.align_size		= bes2600_usb_align_size,
	.set_block_size	= bes2600_usb_set_block_size,
	.pipe_send = bes2600_usb_send,
	.pipe_read = bes2600_usb_read,
	.sbus_reg_read = bes2600_usb_reg_read,
	.sbus_reg_write = bes2600_usb_reg_write,
	.sbus_active	= bes2600_usb_active,
	.sbus_deactive	= bes2600_usb_deactive,
	.reboot			= bes2600_usb_reboot,
};


/* bes2600 usb driver registered functions */
static int bes2600_usb_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	struct usb_device *dev = NULL;
	struct sbus_priv *self = NULL;
	int vendor_id, product_id;
	int ret = 0;

	bes2600_chrdev_update_signal_mode();
	bes2600_dbg(BES2600_DBG_USB, "%s type:%d sig_mode:%d\n", __func__,
			bes2600_chrdev_get_fw_type(), bes2600_chrdev_is_signal_mode());

	bes2600_chrdev_bus_probe_notify();

	dev = interface_to_usbdev(interface);
	usb_get_dev(dev);

	usb_enum.udev = dev;
	usb_enum.removed = false;

	vendor_id = le16_to_cpu(dev->descriptor.idVendor);
	product_id = le16_to_cpu(dev->descriptor.idProduct);
	bes2600_dbg(BES2600_DBG_USB, "vendor_id = %04x\n", vendor_id);
	bes2600_dbg(BES2600_DBG_USB, "product_id = %04x\n", product_id);

	if (interface->cur_altsetting)
		bes2600_dbg(BES2600_DBG_USB, "USB Interface %d\n",
			   interface->cur_altsetting->desc.bInterfaceNumber);


	if (dev->speed == USB_SPEED_HIGH)
		bes2600_dbg(BES2600_DBG_USB, "USB 2.0 Host\n");
	else
		bes2600_dbg(BES2600_DBG_USB, "USB 1.1 Host\n");

	self = bes2600_usb_create(interface);

	if (self == NULL) {
		ret = -ENOMEM;
		bes2600_dbg(BES2600_DBG_USB, "USB create failed!\n");
		goto err_usb_put;
	}

	bes2600_usb_start_recv_pipes(self);

	//bes2600_reg_set_object(&bes2600_usb_ops, self);
	ret = bes2600_load_firmware(&bes2600_usb_ops, self);
	if (ret)
		goto err_core_free;

	/* for wifi closed case */
	if (!bes2600_chrdev_is_wifi_opened())
		goto out;

	ret = bes2600_core_probe(&bes2600_usb_ops, self, &self->udev->dev, &self->core);
	if (ret) {
		bes2600_err(BES2600_DBG_USB, "Failed to init bes2600 core: %d\n", ret);
		goto err_core_free;
	}

out:
	bes2600_chrdev_set_sbus_priv_data(self, false);
	return 0;

err_core_free:
#ifdef CONFIG_BES2600_BT
	bes2600_btusb_uninit(interface);
#endif
	bes2600_usb_destroy(self);
err_usb_put:
	usb_put_dev(dev);
	bes2600_chrdev_set_sbus_priv_data(NULL, true);
	usb_set_intfdata(interface, NULL);

	return 0;
}

int bes2600_register_net_dev(struct sbus_priv *bus_priv)
{
	int status = 0;
	BUG_ON(!bus_priv);
	status = bes2600_core_probe(&bes2600_usb_ops,
			      bus_priv, &bus_priv->udev->dev, &bus_priv->core);
	return status;
}

int bes2600_unregister_net_dev(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	if (bus_priv->core) {
		bes2600_core_release(bus_priv->core);
		bus_priv->core = NULL;
	}
	return 0;
}

bool bes2600_is_net_dev_created(struct sbus_priv *bus_priv)
{
	BUG_ON(!bus_priv);
	return (bus_priv->core != NULL);
}

static void bes2600_usb_remove(struct usb_interface *interface)
{
	struct sbus_priv *self = usb_get_intfdata(interface);

	if (self) {
#ifdef CONFIG_BES2600_BT
		bes2600_btusb_uninit(interface);
#endif
		usb_put_dev(interface_to_usbdev(interface));
		bes2600_chrdev_usb_remove(self->core);
		bes2600_usb_device_detached(interface);
	}
	bes2600_chrdev_set_sbus_priv_data(NULL, false);
	usb_enum.removed = true;
}

#ifdef CONFIG_PM
static int bes2600_usb_pm_suspend(struct usb_interface *interface,
			      pm_message_t message)
{
	struct sbus_priv *device;
	device = usb_get_intfdata(interface);

	bes2600_usb_flush_all(device);
	return 0;
}
static int bes2600_usb_pm_resume(struct usb_interface *interface)
{
	struct sbus_priv *device;
	device = usb_get_intfdata(interface);

	bes2600_usb_post_recv_transfers(&device->pipes[BES2600_USB_PIPE_RX_WLAN],
				       BES2600_USB_RX_BUFFER_SIZE);

	return 0;
}
#else
#define bes2600_usb_pm_suspend NULL
#define bes2600_usb_pm_resume NULL
#endif

/* table of devices that work with this driver */
static const struct usb_device_id bes2600_usb_ids[] = {
	{USB_DEVICE(0xBE57, 0x0104)},
	{USB_DEVICE(0xBE57, 0x2002)},
	{USB_DEVICE(0xBE57, 0x2003)},
	{ /* Terminating entry */ },
};

MODULE_DEVICE_TABLE(usb, bes2600_usb_ids);

static struct usb_driver bes2600_usb_driver = {
	.name = "bes2600_usb",
	.probe = bes2600_usb_probe,
	.suspend = bes2600_usb_pm_suspend,
	.resume = bes2600_usb_pm_resume,
	.disconnect = bes2600_usb_remove,
	.id_table = bes2600_usb_ids,
	.supports_autosuspend = true,
	.disable_hub_initiated_lpm = 1,
};

static int __init bes2600_usb_module_init(void)
{
	int ret;

	bes2600_info(BES2600_DBG_USB, "------Driver: bes2600.ko version :%s\n", BES2600_DRV_VERSION);

	bes2600_chrdev_update_signal_mode();

	ret = bes2600_chrdev_init(&bes2600_usb_ops);
	if(ret)
		goto err_chardev;

	bes2600_chrdev_start_bus_probe();

	ret = usb_register_driver(&bes2600_usb_driver , THIS_MODULE, "BES2600");
	if (ret)
		goto err_register;

	return 0;

err_register:
	bes2600_chrdev_free();
err_chardev:
	return ret;
}

static void __exit bes2600_usb_module_exit(void)
{
	bes2600_check_usb_dev_state();
	usb_deregister(&bes2600_usb_driver);
	bes2600_chrdev_free();
	bes2600_enum_usb_dev();
}

module_init(bes2600_usb_module_init);
module_exit(bes2600_usb_module_exit);

MODULE_AUTHOR("Bestechnic, Inc.");
MODULE_DESCRIPTION("Driver support for BES2600 wireless USB devices");
MODULE_LICENSE("Dual BSD/GPL");
