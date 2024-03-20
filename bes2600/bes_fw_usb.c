/*
* Mac80211 driver for BES2600 device
*
* Copyright (c) 2022, Bestechnic
* Author:
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation.
*/
#include "bes_fw_common.h"
#include "bes2600.h"
#include "hwio.h"
#include "sbus.h"
#include "bes2600_driver_mode.h"
#include <linux/string.h>
#include "bes_chardev.h"
#include "hwio.h"
#include "bes2600_factory.h"

#define BES2600_USB_TX_BUFFER_SIZE 8192

struct platform_fw_t {
	struct completion completion_tx;
	struct completion completion_rx;
	const struct sbus_ops *sbus_ops;
	struct sbus_priv *sbus_priv;
	wait_queue_head_t dpd_q;
	bool get_dpd;
	atomic_t dpd_rx;
};

int bes2600_usb_iowrite(struct sbus_priv *sbus_priv, u32 val);
int bes2600_usb_wait_status(struct sbus_priv *sbus_priv, u32 rd_status,
                            bool target_val, u32 wait, u32 timeout);

static void bes_fw_irq_handler(void *priv)
{
	struct platform_fw_t *fw_data = (struct platform_fw_t *)priv;
	u32 ctrl_reg, status_reg;

	// read status and control register
	fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &ctrl_reg, 1);
	fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
	bes2600_dbg(BES2600_DBG_DOWNLOAD, "%s ctrl_reg:0x%08x status_reg:0x%08x\n", __func__, ctrl_reg, status_reg);

	// notify tx done event
	if ((ctrl_reg & BES_USB_FW_TX_DONE) != 0 &&
	    (status_reg & BES_USB_FW_TX_DONE) != 0) {
		status_reg &= ~BES_USB_FW_TX_DONE;
		fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
		complete(&fw_data->completion_tx);
	}

	// notify rx indication event
	if ((ctrl_reg & BES_USB_FW_RX_INDICATION) != 0 &&
	    (status_reg & BES_USB_FW_RX_INDICATION) != 0) {
		status_reg &= ~BES_USB_FW_RX_INDICATION;
		fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_STATUS_REG, &status_reg, 1);
		if (fw_data->get_dpd) {
			atomic_add_return(1, &fw_data->dpd_rx);
			wake_up(&fw_data->dpd_q);
		} else {
			complete(&fw_data->completion_rx);
		}
	}
}

static int bes_usb_fw_write(struct platform_fw_t *fw_data, u8* data, size_t len)
{
	size_t length = 0;
	int ret = 0;
	long time_left;
	u32 control_reg = 0;

	// align data size, makes it suite for usb transfer
	length = fw_data->sbus_ops->align_size(fw_data->sbus_priv, len);

	// enable tx done notification
	fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
	control_reg |= BES_USB_FW_TX_DONE;
	fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

	// send firmware data to device
	ret = fw_data->sbus_ops->pipe_send(fw_data->sbus_priv, BES2600_USB_PIPE_TX_WLAN, length, data);
	if(ret < 0) {
		fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
		control_reg &= ~BES_USB_FW_TX_DONE;
		fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
		return ret;
	}

	// wait for sending done of firmware data
	time_left = wait_for_completion_interruptible_timeout(&fw_data->completion_tx, HZ * 3);
	if(time_left == 0)
		ret = -ETIMEDOUT;
	else if(time_left < 0)
		ret = time_left;

	// turn off tx done notification
	fw_data->sbus_ops->sbus_reg_read(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
	control_reg &= ~BES_USB_FW_TX_DONE;
	fw_data->sbus_ops->sbus_reg_write(fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

	return ret;
}

static int bes_usb_fw_download_xmit(struct platform_fw_t *fw_data, u8* data, size_t len, u8 frame_num)
{
	int ret;
	struct sk_buff *skb = NULL;

	ret = bes_usb_fw_write(fw_data, data, len);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "write data err:%d\n", ret);
		goto err;
	}

	ret = wait_for_completion_interruptible_timeout(&fw_data->completion_rx, HZ * 3);
	if(ret <= 0) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "usb receive download data response timeout or interrupt\n");
		ret = -ETIMEDOUT;
		goto err;
	}

	skb = fw_data->sbus_ops->pipe_read(fw_data->sbus_priv);
	WARN_ON(!skb);

	ret = bes_frame_rsp_check(skb->data, frame_num);
	dev_kfree_skb(skb);

	if (ret)
		bes2600_err(BES2600_DBG_DOWNLOAD, "rsp data ckeck err:%d\n", ret);

err:
	return ret;
}

static int bes_usb_fw_write_mem(struct platform_fw_t *fw_data, const struct fw_info_t *fw_info,
                                const u8 *data, struct fw_crc_t *crc32_t, bool fw_dl)
{
	int ret;
	u8 frame_num, last_frame_num;
	u16 tx_size = BES2600_USB_TX_BUFFER_SIZE;
	u32 length = 0;
	u32 code_length = fw_info->len;
	const u8 *data_p;
	u8 *short_buf = NULL, *long_buf = NULL;
	struct fw_msg_hdr_t header;
	struct download_fw_t download_addr;
	struct run_fw_t run_addr;
	u8 retry_cnt = 0;

retry:
	frame_num = 0;
	data_p = data;

	/* construct download information frame */
	header.type = FRAME_HEADER_DOWNLOAD_INFO;
	header.seq = frame_num;
	header.len = sizeof(struct fw_info_t);
	last_frame_num = frame_num;
	frame_num++;

	short_buf = kzalloc(512, GFP_KERNEL);
	if (!short_buf) {
		ret = -ENOMEM;
		goto err1;
	}

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)fw_info, sizeof(struct fw_info_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	if (tx_size > length) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "%s", "tx download firmware info\n");
	} else {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s:%d bes slave has no enough buffer%d/%d\n", __func__, __LINE__, tx_size, length);
		goto err1;
	}

	ret = bes_usb_fw_download_xmit(fw_data, short_buf, length, last_frame_num);
	if (ret)
		goto err1;

	/* allocate memory for store download data frame */
	long_buf = kmalloc(BES2600_USB_TX_BUFFER_SIZE, GFP_KERNEL);
	if (!long_buf) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "%s:%d fw failed to allocate memory\n",__func__, __LINE__);
		ret = -ENOMEM;
		goto err1;
	}
	download_addr.addr = fw_info->addr;

	/* download data */
	while (code_length) {
		if ((code_length + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t)) < tx_size) {
			length = code_length + sizeof(struct download_fw_t);
		} else {
			length = tx_size - sizeof(struct fw_msg_hdr_t);
		}

		header.type = FRAME_HEADER_DOWNLOAD_DATA;
		header.seq = frame_num;
		header.len = length;
		last_frame_num = frame_num;
		frame_num++;

		memcpy(long_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
		memcpy(long_buf + sizeof(struct fw_msg_hdr_t), &download_addr.addr, sizeof(struct download_fw_t));
		length -= sizeof(struct download_fw_t);//real data length
		memcpy(long_buf + sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t), data_p, length);

		length += (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));

		bes2600_dbg(BES2600_DBG_DOWNLOAD, "tx_download_custom_data:%x %d\n", download_addr.addr, length);

		ret = bes_usb_fw_download_xmit(fw_data, long_buf, length, last_frame_num);
		if (ret)
			goto err2;

		length -= (sizeof(struct fw_msg_hdr_t) + sizeof(struct download_fw_t));
		code_length -= length;
		data_p += length;
		download_addr.addr += length;
		bes2600_dbg(BES2600_DBG_DOWNLOAD, "already tx fw size:%x/%x\n", download_addr.addr - fw_info->addr, fw_info->len);
	}

	/* notify device: the firmware download is complete */
	header.type = FRAME_HEADER_DOWNLOAD_END;
	header.seq = frame_num;
	header.len = sizeof(struct fw_crc_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&crc32_t->crc32, sizeof(struct fw_crc_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_info(BES2600_DBG_DOWNLOAD, "tx download firmware complete command\n");

	ret = bes_usb_fw_download_xmit(fw_data, short_buf, length, last_frame_num);
	if (ret)
		goto err2;

	if (!fw_dl)
		goto err2;

	/* notify device: run firmware */
	run_addr.addr = fw_info->addr;
	header.type = FRAME_HEADER_RUN_CODE;
	header.seq = frame_num;
	header.len = sizeof(struct run_fw_t);
	last_frame_num = frame_num;
	frame_num++;

	memcpy(short_buf, (u8 *)&header, sizeof(struct fw_msg_hdr_t));
	memcpy(short_buf + sizeof(struct fw_msg_hdr_t), (u8 *)&run_addr.addr, sizeof(struct run_fw_t));
	length = BES_FW_MSG_TOTAL_LEN(header);

	bes2600_info(BES2600_DBG_DOWNLOAD, "tx run firmware command:0x%X\n", run_addr.addr);

	ret = bes_usb_fw_download_xmit(fw_data, short_buf, length, last_frame_num);
	if (ret)
		goto err2;

err2:
	if (long_buf != NULL)
		kfree(long_buf);
err1:
	if (short_buf != NULL)
		kfree(short_buf);

	if (ret && retry_cnt < 3) {
		retry_cnt++;
		goto retry;
	}

	return ret;
}

static int bes_usb_fw_send_custom_data(struct platform_fw_t *fw_data, const u32 addr, const u8 *data, const u32 data_len)
{
	int ret;
	struct fw_crc_t data_crc32;
	const struct fw_info_t fw_info = {
		.len = data_len,
		.addr = addr,
	};

	data_crc32.crc32 = 0;
	data_crc32.crc32 ^= 0xffffffffL;
	data_crc32.crc32 = crc32_le(data_crc32.crc32, data, data_len);
	data_crc32.crc32 ^= 0xffffffffL;

	ret = bes_usb_fw_write_mem(fw_data, &fw_info, data, &data_crc32, false);

	return ret;
}

static int bes_usb_firmware_download(struct platform_fw_t *fw_data, const char *fw_name)
{
	int ret;
	u32 code_length = 0;
	const u8 *fw_ver_ptr;
	const u8 *data_p;
	const struct firmware *fw_bin;
	struct fw_info_t fw_info;
	struct fw_crc_t crc32_t;

	/* get firmware data */
	ret = request_firmware(&fw_bin, fw_name, NULL);
	if (ret) {
		bes2600_err(BES2600_DBG_DOWNLOAD, "request firmware err:%d\n", ret);
		return ret;
	}

	/* parse firmware information */
	bes2600_info(BES2600_DBG_DOWNLOAD, "%s fw.size=%ld\n", __func__, fw_bin->size);
	bes_parse_fw_info(fw_bin->data, fw_bin->size, &fw_info.addr, &crc32_t.crc32);
	bes2600_info(BES2600_DBG_DOWNLOAD, "------load addr  :0x%08X\n", fw_info.addr);
	bes2600_info(BES2600_DBG_DOWNLOAD, "------data crc   :0x%08X\n", crc32_t.crc32);
	code_length = fw_bin->size - CODE_DATA_USELESS_SIZE;
	bes2600_info(BES2600_DBG_DOWNLOAD, "------code size  :%d\n", code_length);

	fw_ver_ptr = bes2600_get_firmware_version_info(fw_bin->data, fw_bin->size);
	if(fw_ver_ptr == NULL)
		bes2600_err(BES2600_DBG_DOWNLOAD, "------Firmware version get failed\n");
	else
		bes2600_info(BES2600_DBG_DOWNLOAD, "------Firmware: %s version :%s\n", fw_name ,fw_ver_ptr);

	fw_info.len = code_length;
	data_p = fw_bin->data;

	ret = bes_usb_fw_write_mem(fw_data, &fw_info, data_p, &crc32_t, true);

	release_firmware(fw_bin);

	return ret;
}

static int bes_usb_read_dpd_data(struct platform_fw_t *fw_data)
{
	int ret = 0;
	u8 *dpd_data;
	u8 *dpd_data_tmp;
	u32 remain = DPD_BIN_SIZE;
	struct sk_buff *skb = NULL;

	dpd_data = bes2600_chrdev_get_dpd_buffer(DPD_BIN_FILE_SIZE);
	if (!dpd_data) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = bes2600_usb_wait_status(fw_data->sbus_priv, BES_SLAVE_STATUS_DPD_READY, true, 100, 5000);
	if (ret)
		goto free_dpd;

	ret = bes2600_usb_iowrite(fw_data->sbus_priv, BES_SLAVE_STATUS_SEND_DPD_READY);
	if (ret) {
		bes2600_err(BES2600_DBG_USB, "%s failed, ret: %d\n", __func__, ret);
		goto free_dpd;
	}

	dpd_data_tmp = dpd_data;
	while (remain > 0 && remain <= DPD_BIN_FILE_SIZE) {
		ret = wait_event_timeout(fw_data->dpd_q, atomic_read(&fw_data->dpd_rx), HZ * 3);
		if (ret <= 0) {
			bes2600_err(BES2600_DBG_DOWNLOAD, "wait dpd data err:%d\n", ret);
			ret = - ETIMEDOUT;
			goto free_dpd;
		}

		/* get dpd data */
		skb = fw_data->sbus_ops->pipe_read(fw_data->sbus_priv);
		BUG_ON(!skb);

		memcpy(dpd_data_tmp, skb->data, skb->len);

		dpd_data_tmp += skb->len;
		remain -= skb->len;

		atomic_dec(&fw_data->dpd_rx);
	}

	if (remain != 0)
		ret = -EIO;
	else
		ret = 0;

	if (!ret)
		ret = bes2600_chrdev_update_dpd_data();

	if (ret)
		goto free_dpd;

	return 0;

free_dpd:
	bes2600_chrdev_free_dpd_data();
exit:
	bes2600_err(BES2600_DBG_DOWNLOAD, "%s get dpd data failed, err: %d\n", __func__, ret);
	return ret;
}

static int bes_usb_wait_mcu_ready(struct platform_fw_t *fw_data)
{
	int ret;
	u32 cfm = BES_SLAVE_STATUS_MCU_READY;

	ret = bes2600_usb_wait_status(fw_data->sbus_priv, cfm, true, 25, 200);
	if (ret)
		bes2600_err(BES2600_DBG_USB, "%s, wait mcu ready failed\n", __func__);
	else
		bes2600_info(BES2600_DBG_USB, "firmware is downloaded successfully and is already running\n");

	return ret;
}

static int __bes2600_load_firmware_usb(struct platform_fw_t *fw_data)
{
	int ret = 0;
	const char *fw_name_tbl[3];
	int fw_type = bes2600_chrdev_get_fw_type();
	const u8 *dpd_data = NULL;
	u32 dpd_data_len = 0;

	fw_name_tbl[0] = BES2600_LOAD_FW_NAME;
	fw_name_tbl[1] = BES2600_LOAD_NOSIGNAL_FW_NAME;
	fw_name_tbl[2] = BES2600_LOAD_BTRF_FW_NAME;

	dpd_data = bes2600_chrdev_get_dpd_data(&dpd_data_len);

	if (dpd_data) {
		/* send dpd data */
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 download dpd data.\n");
		ret = bes_usb_fw_send_custom_data(fw_data, BES2600_DPD_ADDR, dpd_data, dpd_data_len);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download dpd data failed.\n");
	} else {
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 download firmware.\n");
		ret = bes_usb_firmware_download(fw_data, BES2600_LOAD_BOOT_NAME);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download dpd cali firmware failed\n");
	}

	if (ret)
		return ret;

	if (!dpd_data) {
		fw_data->get_dpd = true;
		ret = bes_usb_read_dpd_data(fw_data);
		fw_data->get_dpd = false;
	}

	/* for wifi non-signal mode, download second firmware directly */
	if (!ret && bes2600_chrdev_check_system_close()) {
		bes2600_info(BES2600_DBG_DOWNLOAD, "bes2600 device power down.\n");
		ret = bes2600_chrdev_do_system_close(fw_data->sbus_ops, fw_data->sbus_priv);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "device down fail.\n");
	} else if (!ret) {
		ret = bes_usb_firmware_download(fw_data, fw_name_tbl[fw_type]);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download normal firmware failed.\n");

		if (!ret)
			ret = bes_usb_wait_mcu_ready(fw_data);
	}

	return ret;
}

static int _bes2600_load_firmware_usb(struct platform_fw_t *fw_data)
{
	int ret = 0;
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
	u8 *factory_data = NULL;
	u8 *file_buffer = NULL;
	u32 factory_data_len = 0;
#endif


#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
	if (!(file_buffer = bes2600_factory_get_file_buffer()))
		return -ENOMEM;

	bes2600_factory_lock();
#ifdef FACTORY_SAVE_MULTI_PATH
	if (!(factory_data = bes2600_get_factory_cali_data(file_buffer, &factory_data_len, FACTORY_PATH)) &&
		!(factory_data = bes2600_get_factory_cali_data(file_buffer, &factory_data_len, FACTORY_DEFAULT_PATH))) {
#else
	if (!(factory_data = bes2600_get_factory_cali_data(file_buffer, &factory_data_len, FACTORY_PATH))) {
#endif
		bes2600_warn(BES2600_DBG_DOWNLOAD, "factory cali data get failed.\n");
	} else {
		bes2600_factory_data_check(factory_data);
		factory_little_endian_cvrt(factory_data);
		ret = bes_usb_fw_send_custom_data(fw_data, BES2600_FACTORY_ADDR, factory_data, factory_data_len);
		bes2600_err_with_cond(ret, BES2600_DBG_DOWNLOAD, "download factory data failed.\n");
	}

	bes2600_factory_free_file_buffer(file_buffer);
	bes2600_factory_unlock();
#endif

	ret = __bes2600_load_firmware_usb(fw_data);

	return ret;
}

int bes2600_load_firmware_usb(struct sbus_ops *ops, struct sbus_priv *priv)
{
	int ret;
	struct platform_fw_t *temp_fw_data;
	u32 control_reg = 0;

	temp_fw_data = kzalloc(sizeof(struct platform_fw_t), GFP_KERNEL);
	if (!temp_fw_data)
		return -ENOMEM;

	init_completion(&temp_fw_data->completion_rx);
	init_completion(&temp_fw_data->completion_tx);
	init_waitqueue_head(&temp_fw_data->dpd_q);
	atomic_set(&temp_fw_data->dpd_rx, 0);
	temp_fw_data->get_dpd = false;
	temp_fw_data->sbus_ops = ops;
	temp_fw_data->sbus_priv = priv;

	// enable rx indication
	temp_fw_data->sbus_ops->sbus_reg_read(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
	control_reg |= BES_USB_FW_RX_INDICATION;
	temp_fw_data->sbus_ops->sbus_reg_write(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

	// subscribe irq handler
	temp_fw_data->sbus_ops->irq_subscribe(temp_fw_data->sbus_priv,
			(sbus_irq_handler)bes_fw_irq_handler, temp_fw_data);

	ret = _bes2600_load_firmware_usb(temp_fw_data);
	// unsubscribe irq handler
	temp_fw_data->sbus_ops->irq_unsubscribe(temp_fw_data->sbus_priv);

	// disable rx indication
	temp_fw_data->sbus_ops->sbus_reg_read(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);
	control_reg &= ~BES_USB_FW_RX_INDICATION;
	temp_fw_data->sbus_ops->sbus_reg_write(temp_fw_data->sbus_priv, BES_USB_CONTROL_REG, &control_reg, 1);

	kfree(temp_fw_data);

	return ret;
}
