/*
 * WSM host interface (HI) implementation for
 * BES2600 mac80211 drivers.
 *
 * Copyright (c) 2022, Bestechnic
 * Author:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/etherdevice.h>

#include "bes2600.h"
#include "wsm.h"
#include "bh.h"
#include "debug.h"
#include "itp.h"
#ifdef ROAM_OFFLOAD
#include "sta.h"
#endif /*ROAM_OFFLOAD*/
#ifdef CONFIG_BES2600_TESTMODE
#include "bes_nl80211_testmode_msg.h"
#endif
#include "bes_chardev.h"
#include "bes2600_factory.h"
#include "epta_coex.h"
#include "epta_request.h"

#define WSM_CMD_TIMEOUT		(6 * HZ) /* With respect to interrupt loss */
#define WSM_CMD_JOIN_TIMEOUT	(7 * HZ) /* Join timeout is 5 sec. in FW   */
#define WSM_CMD_START_TIMEOUT	(7 * HZ)
#define WSM_CMD_RESET_TIMEOUT	(7 * HZ) /* 2 sec. timeout was observed.   */
#define WSM_CMD_DEFAULT_TIMEOUT	(7 * HZ)
#define WSM_SKIP(buf, size)						\
	do {								\
		if (unlikely((buf)->data + size > (buf)->end))		\
			goto underflow;					\
		(buf)->data += size;					\
	} while (0)

#define WSM_GET(buf, ptr, size)						\
	do {								\
		if (unlikely((buf)->data + size > (buf)->end))		\
			goto underflow;					\
		memcpy(ptr, (buf)->data, size);				\
		(buf)->data += size;					\
	} while (0)

#define __WSM_GET(buf, type, cvt)					\
	({								\
		type val;						\
		if (unlikely((buf)->data + sizeof(type) > (buf)->end))	\
			goto underflow;					\
		val = cvt(*(type *)(buf)->data);			\
		(buf)->data += sizeof(type);				\
		val;							\
	})

#define WSM_GET8(buf)  __WSM_GET(buf, u8, (u8))
#define WSM_GET16(buf) __WSM_GET(buf, u16, __le16_to_cpu)
#define WSM_GET32(buf) __WSM_GET(buf, u32, __le32_to_cpu)

#define WSM_PUT(buf, ptr, size)						\
	do {								\
		if (unlikely((buf)->data + size > (buf)->end))		\
			if (unlikely(wsm_buf_reserve((buf), size)))	\
				goto nomem;				\
		memcpy((buf)->data, ptr, size);				\
		(buf)->data += size;					\
	} while (0)

#define __WSM_PUT(buf, val, type, cvt)					\
	do {								\
		if (unlikely((buf)->data + sizeof(type) > (buf)->end))	\
			if (unlikely(wsm_buf_reserve((buf), sizeof(type)))) \
				goto nomem;				\
		*(type *)(buf)->data = cvt(val);			\
		(buf)->data += sizeof(type);				\
	} while (0)

#define WSM_PUT8(buf, val)  __WSM_PUT(buf, val, u8, (u8))
#define WSM_PUT16(buf, val) __WSM_PUT(buf, val, u16, __cpu_to_le16)
#define WSM_PUT32(buf, val) __WSM_PUT(buf, val, u32, __cpu_to_le32)

static void wsm_buf_reset(struct wsm_buf *buf);
static int wsm_buf_reserve(struct wsm_buf *buf, size_t extra_size);
static int get_interface_id_scanning(struct bes2600_common *hw_priv);

static int wsm_cmd_send(struct bes2600_common *hw_priv,
			struct wsm_buf *buf,
			void *arg, u16 cmd, long tmo, int if_id);

static struct bes2600_vif
	*wsm_get_interface_for_tx(struct bes2600_common *hw_priv);

static inline void wsm_cmd_lock(struct bes2600_common *hw_priv)
{
	bes2600_pwr_set_busy_event(hw_priv, BES_PWR_LOCK_ON_WSM_TX);
	down(&hw_priv->wsm_cmd_sema);
}

static inline void wsm_cmd_unlock(struct bes2600_common *hw_priv)
{
	up(&hw_priv->wsm_cmd_sema);
	bes2600_pwr_clear_busy_event(hw_priv, BES_PWR_LOCK_ON_WSM_TX);
}

static inline void wsm_oper_lock(struct bes2600_common *hw_priv)
{
	bes2600_pwr_set_busy_event(hw_priv, BES_PWR_LOCK_ON_WSM_OPER);
	down(&hw_priv->wsm_oper_lock);
}

static inline void wsm_oper_unlock(struct bes2600_common *hw_priv)
{
	up(&hw_priv->wsm_oper_lock);
	bes2600_pwr_clear_busy_event(hw_priv, BES_PWR_LOCK_ON_WSM_OPER);
}

/* ******************************************************************** */
/* WSM API implementation						*/

static int wsm_generic_confirm(struct bes2600_common *hw_priv,
				 void *arg,
				 struct wsm_buf *buf)
{
	u32 status = WSM_GET32(buf);
	if (WARN(status != WSM_STATUS_SUCCESS, "wsm_generic_confirm ret %u", status))
		return -EINVAL;
	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

int wsm_configuration(struct bes2600_common *hw_priv,
			  struct wsm_configuration *arg,
			  int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, arg->dot11MaxTransmitMsduLifeTime);
	WSM_PUT32(buf, arg->dot11MaxReceiveLifeTime);
	WSM_PUT32(buf, arg->dot11RtsThreshold);

	/* DPD block. */
	WSM_PUT16(buf, arg->dpdData_size + 12);
	WSM_PUT16(buf, 1); /* DPD version */
	WSM_PUT(buf, arg->dot11StationId, ETH_ALEN);
	WSM_PUT16(buf, 5); /* DPD flags */
	WSM_PUT(buf, arg->dpdData, arg->dpdData_size);

	ret = wsm_cmd_send(hw_priv, buf, arg, 0x0009, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

static int wsm_configuration_confirm(struct bes2600_common *hw_priv,
					 struct wsm_configuration *arg,
					 struct wsm_buf *buf)
{
	int i;
	int status;

	status = WSM_GET32(buf);
	if (WARN_ON(status != WSM_STATUS_SUCCESS))
		return -EINVAL;

	if (bes2600_chrdev_is_signal_mode()) {
		WSM_GET(buf, arg->dot11StationId, ETH_ALEN);
		arg->dot11FrequencyBandsSupported = WSM_GET8(buf);
		WSM_SKIP(buf, 1);
		arg->supportedRateMask = WSM_GET32(buf);
		for (i = 0; i < 2; ++i) {
			arg->txPowerRange[i].min_power_level = WSM_GET32(buf);
			arg->txPowerRange[i].max_power_level = WSM_GET32(buf);
			arg->txPowerRange[i].stepping = WSM_GET32(buf);
		}
	}
	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

/* ******************************************************************** */

//rf nosignaling tset
#ifdef CONFIG_BES2600_TESTMODE

int wsm_vendor_rf_cmd_confirm(struct bes2600_common *hw_priv, void *arg, struct wsm_buf *buf)
{
	return 0;
}

int wsm_vendor_rf_test_indication(struct bes2600_common *hw_priv, struct wsm_buf *buf)
{
	int i;
	int16_t ret = 0;
	u16 wsm_len;
	u32 cmd_type;
	struct wifi_power_cali_save_t power_cali_save;
	struct wifi_freq_cali_t wifi_freq_cali;
	struct wifi_get_power_cali_t power_cali_get;
	struct wifi_power_cali_flag_t power_cali_flag;
	struct wsm_mcu_hdr *msg_hdr = (struct wsm_mcu_hdr *)(buf->begin);

	wsm_len = __le16_to_cpu(msg_hdr->hdr.len);
	cmd_type = __le32_to_cpu(msg_hdr->cmd_type);
	buf->data += sizeof(struct wsm_mcu_hdr) - sizeof(struct wsm_hdr);

	switch (cmd_type) {
	case VENDOR_RF_SAVE_FREQOFFSET_CMD:
	case VENDOR_RF_GET_SAVE_FREQOFFSET_CMD:
		wifi_freq_cali.save_type = WSM_GET16(buf);
		wifi_freq_cali.freq_cali = WSM_GET16(buf);
		wifi_freq_cali.status = -WSM_GET16(buf);
		wifi_freq_cali.cali_flag = WSM_GET16(buf);
		if (wifi_freq_cali.save_type == RF_CALIB_DATA_IN_LINUX) {
			if (cmd_type == VENDOR_RF_SAVE_FREQOFFSET_CMD) {
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
				ret = bes2600_wifi_cali_freq_write(&wifi_freq_cali);
#else
				ret = -FACTORY_SAVE_FREQ_ERR;
#endif
			}

			if (cmd_type == VENDOR_RF_GET_SAVE_FREQOFFSET_CMD) {
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
				ret = vendor_get_freq_cali(&wifi_freq_cali);
#else
				ret = -FACTORY_SAVE_FILE_NOT_EXIST;
#endif
			}
			wifi_freq_cali.status = ret;
		}
		bes2600_rf_cmd_msg_assembly(cmd_type, &wifi_freq_cali,
			sizeof(struct wifi_freq_cali_t));
		break;
	case VENDOR_RF_SAVE_POWERLEVEL_CMD:
		power_cali_save.save_type = WSM_GET16(buf);
		power_cali_save.mode = WSM_GET16(buf);
		power_cali_save.bandwidth = WSM_GET16(buf);
		power_cali_save.band = WSM_GET16(buf);
		power_cali_save.ch = WSM_GET16(buf);
		power_cali_save.power_cali = WSM_GET16(buf);
		power_cali_save.status = -WSM_GET16(buf);
		if (power_cali_save.save_type == RF_CALIB_DATA_IN_LINUX) {
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
			ret = bes2600_wifi_power_cali_table_write(&power_cali_save);
#else
			ret = -FACTORY_SAVE_POWER_ERR;
#endif
			power_cali_save.status = ret;
		}
		bes2600_rf_cmd_msg_assembly(cmd_type, &power_cali_save,
			sizeof(struct wifi_power_cali_save_t));
		break;
	case VENDOR_RF_GET_SAVE_POWERLEVEL_CMD:
		power_cali_get.save_type = WSM_GET16(buf);
		if (power_cali_get.save_type == RF_CALIB_DATA_IN_LINUX) {
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
			ret = vendor_get_power_cali(&power_cali_get);
#else
			ret = -FACTORY_SAVE_FILE_NOT_EXIST;
#endif
			power_cali_get.status = ret;
		} else {
			/* 2.4G have 3 cali ch */
			for (i = 0; i < 3; i++)
				power_cali_get.tx_power_ch[i] = WSM_GET16(buf);
			/* 5G have 13 cali ch */
			for (i = 0; i < 13; i++)
				power_cali_get.tx_power_ch_5G[i] = WSM_GET16(buf);
			power_cali_get.status = -WSM_GET16(buf);
		}
		bes2600_rf_cmd_msg_assembly(cmd_type, &power_cali_get,
			sizeof(struct wifi_get_power_cali_t));

		break;
	case VENDOR_RF_POWER_CALIB_FINISH:
		power_cali_flag.save_type = WSM_GET16(buf);
		power_cali_flag.band = WSM_GET16(buf);
		power_cali_flag.status = -WSM_GET16(buf);
		if (power_cali_flag.save_type == RF_CALIB_DATA_IN_LINUX) {
#ifdef CONFIG_BES2600_CALIB_FROM_LINUX
			ret = vendor_set_power_cali_flag(&power_cali_flag);
#else
			ret = -FACTORY_SET_POWER_CALI_FLAG_ERR;
#endif
			power_cali_flag.status = ret;
		}
		bes2600_rf_cmd_msg_assembly(cmd_type, &power_cali_flag,
			sizeof(struct wifi_power_cali_flag_t));
		break;
	case VENDOR_RF_SIGNALING_CMD:
	case VENDOR_RF_NOSIGNALING_CMD:
	case VENDOR_RF_GET_CALI_FROM_EFUSE:
		bes2600_rf_cmd_msg_assembly(cmd_type, buf->data, wsm_len - sizeof(struct wsm_mcu_hdr));
		break;
	default:
		break;
	}

	up(&hw_priv->vendor_rf_cmd_replay_sema);

	bes2600_pwr_clear_busy_event(hw_priv, BES_PWR_LOCK_ON_TEST_CMD);

	return 0;

underflow:
	return -EINVAL;
}

int wsm_vendor_rf_cmd(struct bes2600_common *hw_priv, int if_id,
					  const struct vendor_rf_cmd_t *vendor_rf_cmd)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* the command need to wait complete indication */
	bes2600_pwr_set_busy_event(hw_priv, BES_PWR_LOCK_ON_TEST_CMD);

	WSM_PUT32(buf, vendor_rf_cmd->cmd_type);
	WSM_PUT32(buf, vendor_rf_cmd->cmd_argc);
	WSM_PUT32(buf, vendor_rf_cmd->cmd_len);
	WSM_PUT(buf, vendor_rf_cmd->cmd, vendor_rf_cmd->cmd_len);

	/**
	 * vendor signaling and nosignaling use id 0x0C25.
	 */
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0C25, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}
#endif /* CONFIG_BES2600_TESTMODE */

/* ******************************************************************** */
 // wifi cpu sleep control
 #ifdef BES_UNIFIED_PM
struct wsm_sleep_ctrl {
	u16 msgid;
	u16 msglen;
	u32 disable;
};

int wsm_sleep_ctrl(struct bes2600_common *hw_priv, u32 disable, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	if (if_id != 0) {
		WARN_ON(1);
		return -EBUSY;
	}

	wsm_cmd_lock(hw_priv);
	WSM_PUT32(buf, disable);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0024, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}
#endif

/* ******************************************************************** */

int wsm_reset(struct bes2600_common *hw_priv, const struct wsm_reset *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	u16 cmd = 0x000A | WSM_TX_LINK_ID(arg->link_id);

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, arg->reset_statistics ? 0 : 1);
	ret = wsm_cmd_send(hw_priv, buf, NULL, cmd, WSM_CMD_RESET_TIMEOUT,
				if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_read_mib(struct bes2600_common *hw_priv, u16 mibId, void *_buf,
			size_t buf_size)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mibId = mibId,
		.buf = _buf,
		.buf_size = buf_size,
	};

	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, mibId);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(hw_priv, buf, &mib_buf, 0x0005, WSM_CMD_TIMEOUT, -1);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

static int wsm_read_mib_confirm(struct bes2600_common *hw_priv,
				struct wsm_mib *arg,
				struct wsm_buf *buf)
{
	u16 size;
	if (WARN_ON(WSM_GET32(buf) != WSM_STATUS_SUCCESS))
		return -EINVAL;

	if (WARN_ON(WSM_GET16(buf) != arg->mibId))
		return -EINVAL;

	size = WSM_GET16(buf);
	if (size > arg->buf_size)
		size = arg->buf_size;

	WSM_GET(buf, arg->buf, size);
	arg->buf_size = size;
	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

/* ******************************************************************** */

int wsm_write_mib(struct bes2600_common *hw_priv, u16 mibId, void *_buf,
			size_t buf_size, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	struct wsm_mib mib_buf = {
		.mibId = mibId,
		.buf = _buf,
		.buf_size = buf_size,
	};

	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, mibId);
	WSM_PUT16(buf, buf_size);
	WSM_PUT(buf, _buf, buf_size);

	ret = wsm_cmd_send(hw_priv, buf, &mib_buf, 0x0006, WSM_CMD_TIMEOUT,
			if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

static int wsm_write_mib_confirm(struct bes2600_common *hw_priv,
				struct wsm_mib *arg,
				struct wsm_buf *buf,
				int interface_link_id)
{
	int ret;
	struct bes2600_vif *priv;

	if (!is_hardware_cw1250(hw_priv) || is_hardware_cw1260(hw_priv))
		interface_link_id = 0;

	ret = wsm_generic_confirm(hw_priv, arg, buf);
	if (ret)
		return ret;

	if (arg->mibId == 0x1006) {
		const char *p = arg->buf;

		/* Power save is enabled before add_interface is called */
		if (!hw_priv->vif_list[interface_link_id])
			return 0;
		/* OperationalMode: update PM status. */
		priv = cw12xx_hwpriv_to_vifpriv(hw_priv,
					interface_link_id);
		if (!priv)
			return 0;
		bes2600_enable_powersave(priv,
				(p[0] & 0x0F) ? true : false);
		spin_unlock(&priv->vif_lock);
	}
	return 0;
}

/* ******************************************************************** */

int wsm_scan(struct bes2600_common *hw_priv, const struct wsm_scan *arg,
		int if_id)
{
	int i;
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	if (unlikely(arg->numOfChannels > 48))
		return -EINVAL;

	if (unlikely(arg->numOfSSIDs > WSM_SCAN_MAX_NUM_OF_SSIDS))
		return -EINVAL;

	if (unlikely(arg->band > 1))
		return -EINVAL;

	wsm_oper_lock(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->band);
	WSM_PUT8(buf, arg->scanType);
	WSM_PUT8(buf, arg->scanFlags);
	WSM_PUT8(buf, arg->maxTransmitRate);
	WSM_PUT32(buf, arg->autoScanInterval);
	WSM_PUT8(buf, arg->numOfProbeRequests);
	WSM_PUT8(buf, arg->numOfChannels);
	WSM_PUT8(buf, arg->numOfSSIDs);
	WSM_PUT8(buf, arg->probeDelay);

	for (i = 0; i < arg->numOfChannels; ++i) {
		WSM_PUT16(buf, arg->ch[i].number);
		WSM_PUT16(buf, 0);
		WSM_PUT32(buf, arg->ch[i].minChannelTime);
		WSM_PUT32(buf, arg->ch[i].maxChannelTime);
		WSM_PUT32(buf, 0);
	}

	for (i = 0; i < arg->numOfSSIDs; ++i) {
		WSM_PUT32(buf, arg->ssids[i].length);
		WSM_PUT(buf, &arg->ssids[i].ssid[0],
				sizeof(arg->ssids[i].ssid));
	}

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0007, WSM_CMD_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	if (ret)
		wsm_oper_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_oper_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_stop_scan(struct bes2600_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0008, WSM_CMD_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}


static int wsm_tx_confirm(struct bes2600_common *hw_priv,
			  struct wsm_buf *buf,
			  int interface_link_id)
{
	struct wsm_tx_confirm tx_confirm;

	tx_confirm.packetID = WSM_GET32(buf);
	tx_confirm.status = WSM_GET32(buf);
	tx_confirm.txedRate = WSM_GET8(buf);
	tx_confirm.ackFailures = WSM_GET8(buf);
	tx_confirm.flags = WSM_GET16(buf);
	tx_confirm.mediaDelay = WSM_GET32(buf);
	tx_confirm.txQueueDelay = WSM_GET32(buf);

	if (is_hardware_cw1250(hw_priv) || is_hardware_cw1260(hw_priv)) {
		/* TODO:COMBO:linkID will be stored in packetID*/
		/* TODO:COMBO: Extract traffic resumption map */
		tx_confirm.if_id = bes2600_queue_get_if_id(tx_confirm.packetID);
		tx_confirm.link_id = bes2600_queue_get_link_id(
				tx_confirm.packetID);
	} else {
		tx_confirm.link_id = interface_link_id;
		tx_confirm.if_id = 0;
	}

	wsm_release_vif_tx_buffer(hw_priv, tx_confirm.if_id, 1);

	if (hw_priv->wsm_cbc.tx_confirm)
		hw_priv->wsm_cbc.tx_confirm(hw_priv, &tx_confirm);
	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

static int wsm_multi_tx_confirm(struct bes2600_common *hw_priv,
				struct wsm_buf *buf, int interface_link_id)
{
	struct bes2600_vif *priv;
	int ret;
	int count;
	int i;

	count = WSM_GET32(buf);
	if (WARN_ON(count <= 0))
		return -EINVAL;
	else if (count > 1) {
		ret = wsm_release_tx_buffer(hw_priv, count - 1);
		if (ret < 0)
			return ret;
		else if (ret > 0)
			bes2600_bh_wakeup(hw_priv);
	}
	priv = cw12xx_hwpriv_to_vifpriv(hw_priv, interface_link_id);
	if (priv) {
		bes2600_debug_txed_multi(priv, count);
		spin_unlock(&priv->vif_lock);
	}
	for (i = 0; i < count; ++i) {
		if(i < count - 1)
			bes2600_bh_dec_pending_count(hw_priv, 0);

		ret = wsm_tx_confirm(hw_priv, buf, interface_link_id);
		if (ret)
			return ret;
	}
	return ret;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

/* ******************************************************************** */

static int wsm_join_confirm(struct bes2600_common *hw_priv,
				struct wsm_join *arg,
				struct wsm_buf *buf)
{
	u32 status = WSM_GET32(buf);

	wsm_oper_unlock(hw_priv);

	if (status != WSM_STATUS_SUCCESS) {
		bes2600_warn(BES2600_DBG_WSM, "wsm_join_confirm ret %u\n", status);
		return -EINVAL;
	}

	arg->minPowerLevel = WSM_GET32(buf);
	arg->maxPowerLevel = WSM_GET32(buf);

	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

int wsm_join(struct bes2600_common *hw_priv, struct wsm_join *arg,
		 int if_id)
/*TODO: combo: make it work per vif.*/
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_oper_lock(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->mode);
	WSM_PUT8(buf, arg->band);
	WSM_PUT16(buf, arg->channelNumber);
	WSM_PUT(buf, &arg->bssid[0], sizeof(arg->bssid));
	WSM_PUT16(buf, arg->atimWindow);
	WSM_PUT8(buf, arg->preambleType);
	WSM_PUT8(buf, arg->probeForJoin);
	WSM_PUT8(buf, arg->dtimPeriod);
	WSM_PUT8(buf, arg->flags);
	WSM_PUT32(buf, arg->ssidLength);
	WSM_PUT(buf, &arg->ssid[0], sizeof(arg->ssid));
	WSM_PUT32(buf, arg->beaconInterval);
	WSM_PUT32(buf, arg->basicRateSet);

	hw_priv->tx_burst_idx = -1;
	ret = wsm_cmd_send(hw_priv, buf, arg, 0x000B, WSM_CMD_JOIN_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_oper_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_set_bss_params(struct bes2600_common *hw_priv,
			const struct wsm_set_bss_params *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, 0);
	WSM_PUT8(buf, arg->beaconLostCount);
	WSM_PUT16(buf, arg->aid);
	WSM_PUT32(buf, arg->operationalRateSet);
	WSM_PUT32(buf, hw_priv->ht_info.ht_cap.mcs.rx_mask[0] << 14);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0011, WSM_CMD_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_add_key(struct bes2600_common *hw_priv, const struct wsm_add_key *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT(buf, arg, sizeof(*arg));

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x000C, WSM_CMD_TIMEOUT,
				if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_remove_key(struct bes2600_common *hw_priv,
		   const struct wsm_remove_key *arg, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->entryIndex);
	WSM_PUT8(buf, 0);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x000D, WSM_CMD_TIMEOUT,
			   if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_set_tx_queue_params(struct bes2600_common *hw_priv,
				const struct wsm_set_tx_queue_params *arg,
				u8 id, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	u8 queue_id_to_wmm_aci[] = {3, 2, 0, 1};

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, queue_id_to_wmm_aci[id]);
	WSM_PUT8(buf, 0);
	WSM_PUT8(buf, arg->ackPolicy);
	WSM_PUT8(buf, 0);
	WSM_PUT32(buf, arg->maxTransmitLifetime);
	WSM_PUT16(buf, arg->allowedMediumTime);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0012, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_set_edca_params(struct bes2600_common *hw_priv,
				const struct wsm_edca_params *arg,
				int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* Implemented according to specification. */

	WSM_PUT16(buf, arg->params[3].cwMin);
	WSM_PUT16(buf, arg->params[2].cwMin);
	WSM_PUT16(buf, arg->params[1].cwMin);
	WSM_PUT16(buf, arg->params[0].cwMin);

	WSM_PUT16(buf, arg->params[3].cwMax);
	WSM_PUT16(buf, arg->params[2].cwMax);
	WSM_PUT16(buf, arg->params[1].cwMax);
	WSM_PUT16(buf, arg->params[0].cwMax);

	WSM_PUT8(buf, arg->params[3].aifns);
	WSM_PUT8(buf, arg->params[2].aifns);
	WSM_PUT8(buf, arg->params[1].aifns);
	WSM_PUT8(buf, arg->params[0].aifns);

	WSM_PUT16(buf, arg->params[3].txOpLimit);
	WSM_PUT16(buf, arg->params[2].txOpLimit);
	WSM_PUT16(buf, arg->params[1].txOpLimit);
	WSM_PUT16(buf, arg->params[0].txOpLimit);

	WSM_PUT32(buf, arg->params[3].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[2].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[1].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[0].maxReceiveLifetime);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0013, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_switch_channel(struct bes2600_common *hw_priv,
			   const struct wsm_switch_channel *arg,
			   int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	wsm_lock_tx(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->channelMode | 0x80);
	WSM_PUT8(buf, arg->channelSwitchCount);
	WSM_PUT16(buf, arg->newChannelNumber);

	hw_priv->channel_switch_in_progress = 1;

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0016, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	if (ret) {
		wsm_unlock_tx(hw_priv);
		hw_priv->channel_switch_in_progress = 0;
	}
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_unlock_tx(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_set_pm(struct bes2600_common *hw_priv, const struct wsm_set_pm *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->pmMode);
	WSM_PUT8(buf, arg->fastPsmIdlePeriod);
	WSM_PUT8(buf, arg->apPsmChangePeriod);
	WSM_PUT8(buf, arg->minAutoPsPollPeriod);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0010, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_start(struct bes2600_common *hw_priv, const struct wsm_start *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->mode);
	WSM_PUT8(buf, arg->band);
	WSM_PUT16(buf, arg->channelNumber);
	WSM_PUT32(buf, arg->CTWindow);
	WSM_PUT32(buf, arg->beaconInterval);
	WSM_PUT8(buf, arg->DTIMPeriod);
	WSM_PUT8(buf, arg->preambleType);
	WSM_PUT8(buf, arg->probeDelay);
	WSM_PUT8(buf, arg->ssidLength);
	WSM_PUT(buf, arg->ssid, sizeof(arg->ssid));
	WSM_PUT32(buf, arg->basicRateSet);

	hw_priv->tx_burst_idx = -1;
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0017, WSM_CMD_START_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

#if 0
/* This API is no longer present in WSC */
/* ******************************************************************** */

int wsm_beacon_transmit(struct bes2600_common *hw_priv,
			const struct wsm_beacon_transmit *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, arg->enableBeaconing ? 1 : 0);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0018, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}
#endif

/* ******************************************************************** */

int wsm_start_find(struct bes2600_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0019, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}

/* ******************************************************************** */

int wsm_stop_find(struct bes2600_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x001A, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}

/* ******************************************************************** */

int wsm_map_link(struct bes2600_common *hw_priv, const struct wsm_map_link *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	u16 cmd = 0x001C;

	wsm_cmd_lock(hw_priv);

	WSM_PUT(buf, &arg->mac_addr[0], sizeof(arg->mac_addr));

	if (is_hardware_cw1250(hw_priv) || is_hardware_cw1260(hw_priv)) {
		WSM_PUT8(buf, arg->unmap);
		WSM_PUT8(buf, arg->link_id);
	} else {
		cmd |= WSM_TX_LINK_ID(arg->link_id);
		WSM_PUT16(buf, 0);
	}

	ret = wsm_cmd_send(hw_priv, buf, NULL, cmd, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

/* ******************************************************************** */

int wsm_update_ie(struct bes2600_common *hw_priv,
		  const struct wsm_update_ie *arg, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, arg->what);
	WSM_PUT16(buf, arg->count);
	WSM_PUT(buf, arg->ies, arg->length);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x001B, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;

}

int wsm_epta_cmd(struct bes2600_common *hw_priv, struct wsm_epta_msg *arg)
{
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	static bool epta_lock_tx = false;

	if (arg->hw_epta_enable & (1 << 11))
		arg->hw_epta_enable &= ~(3 << 10); // force TDD
	else if (coex_is_fdd_mode())
		arg->hw_epta_enable |= (1 << 10); //LMAC_COEX_MODE_FDD

	if (arg->hw_epta_enable != 3 || arg->hw_epta_enable != 4) { //use for wifi connect
		///TODO: remove this hack. use hardware in disconnect mode
		if (coex_is_wifi_inactive()) {
			arg->wlan_duration = 20000;
			arg->bt_duration = 80000;
			arg->hw_epta_enable &= ~(0x3);
		}
		// if (coex_is_fdd_mode()) {
		// 	arg->wlan_duration = 100000;
		// 	arg->bt_duration = 0;
		// 	arg->hw_epta_enable |= (1 << 10);
		// } else {
		// 	if (coex_is_bt_inactive()) {
		// 		arg->wlan_duration = 100000;
		// 		arg->bt_duration = 0;
		// 		arg->hw_epta_enable = 0;
		// 	}
		// }
	}

	bes2600_info(BES2600_DBG_WSM, "epta cmd: wlan:%d bt:%d enable:%x",
		arg->wlan_duration, arg->bt_duration, arg->hw_epta_enable);

	/*
	Should lock tx queue to avoid frame stuck in firmware if wlan_duration is zero.
	There is no need to distinguish epta mode as the duration reflects requirements of scenarios
	*/
	if (arg->wlan_duration == 0 && !epta_lock_tx) {
		wsm_lock_tx(hw_priv);
		epta_lock_tx = true;
	} else if (epta_lock_tx && arg->wlan_duration != 0) {
		wsm_unlock_tx(hw_priv);
		epta_lock_tx = false;
	}

	wsm_cmd_lock(hw_priv);
	WSM_PUT32(buf, arg->wlan_duration);
	WSM_PUT32(buf, arg->bt_duration);
	WSM_PUT32(buf, arg->hw_epta_enable);
	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0029, WSM_CMD_TIMEOUT, 0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
#else
	return 0;
#endif
}

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
int wsm_epta_wifi_chan_cmd(struct bes2600_common *hw_priv, uint32_t channel, uint32_t type)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* cmd type */
	WSM_PUT32(buf, BES2600_RF_CMD_CH_INFO);

	WSM_PUT32(buf, channel);
	WSM_PUT16(buf, type);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0C27, WSM_CMD_TIMEOUT, 0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}
#endif

int wsm_wifi_status_cmd(struct bes2600_common *hw_priv, uint32_t status)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* cmd type */
	WSM_PUT32(buf, BES2600_RF_CMD_WIFI_STATUS);
	WSM_PUT32(buf, status);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0C27, WSM_CMD_TIMEOUT, 0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

int wsm_cpu_usage_cmd(struct bes2600_common *hw_priv)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* cmd type */
	WSM_PUT32(buf, BES2600_RF_CMD_CPU_USAGE);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0C27, WSM_CMD_TIMEOUT, 0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}

int wsm_save_factory_txt_to_mcu(struct bes2600_common *hw_priv, const u8 *data, int if_id, enum bes2600_rf_cmd_type cmd_type)
{
	int ret, i;
	const struct factory_t *factory_cali = (const struct factory_t *)data;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* cmd type */
	WSM_PUT32(buf, cmd_type);
	WSM_PUT32(buf, factory_cali->data.iQ_offset);
	WSM_PUT16(buf, factory_cali->data.freq_cal);

	for (i = 0; i < 3; i++)
		WSM_PUT16(buf, factory_cali->data.tx_power_ch[i]);

	WSM_PUT8(buf, factory_cali->data.freq_cal_flags);
	WSM_PUT8(buf, factory_cali->data.tx_power_type);
	WSM_PUT16(buf, factory_cali->data.temperature);

	for (i = 0; i < 13; i++)
		WSM_PUT16(buf, factory_cali->data.tx_power_ch_5G[i]);

	WSM_PUT16(buf, factory_cali->data.tx_power_flags_5G);

	for (i = 0; i < 4; i++)
		WSM_PUT32(buf, factory_cali->data.bt_tx_power[i]);

	WSM_PUT16(buf, factory_cali->data.temperature_5G);

	ret = wsm_cmd_send(hw_priv, buf, NULL, 0x0C27, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ENOMEM;
}
/* ******************************************************************** */
#ifdef MCAST_FWDING
/* 3.66 */
static int wsm_give_buffer_confirm(struct bes2600_common *hw_priv,
							struct wsm_buf *buf)
{
	bes2600_dbg(BES2600_DBG_WSM, "[WSM] HW Buf count %d\n", hw_priv->hw_bufs_used);
	if (!hw_priv->hw_bufs_used)
		wake_up(&hw_priv->bh_evt_wq);

	return 0;
}

/* 3.65 */
int wsm_init_release_buffer_request(struct bes2600_common *hw_priv, u8 index)
{
	struct wsm_buf *buf = &hw_priv->wsm_release_buf[index];
	u16 cmd = 0x0022; /* Buffer Request */
	u8 flags;
	size_t buf_len;

	wsm_buf_init(buf);

	flags = index ? 0: 0x1;

	WSM_PUT8(buf, flags);
	WSM_PUT8(buf, 0);
	WSM_PUT16(buf, 0);

	buf_len = buf->data - buf->begin;

	/* Fill HI message header */
	((__le16 *)buf->begin)[0] = __cpu_to_le16(buf_len);
	((__le16 *)buf->begin)[1] = __cpu_to_le16(cmd);

	return 0;
nomem:
	return -ENOMEM;
}

/* 3.68 */
static int wsm_request_buffer_confirm(struct bes2600_vif *priv,
							u8 *arg,
							struct wsm_buf *buf)
{
	u8 count;
	u32 sta_asleep_mask = 0;
	int i;
	u32 mask = 0;
	u32 change_mask = 0;
	struct bes2600_common *hw_priv = priv->hw_priv;

	/* There is no status field in this message */
	sta_asleep_mask = WSM_GET32(buf);
	count = WSM_GET8(buf);
	count -= 1; /* Current workaround for FW issue */

	spin_lock_bh(&priv->ps_state_lock);
	change_mask = (priv->sta_asleep_mask ^ sta_asleep_mask);
	bes2600_dbg(BES2600_DBG_WSM, "CM %x, HM %x, FWM %x\n", change_mask,priv->sta_asleep_mask, sta_asleep_mask);
	spin_unlock_bh(&priv->ps_state_lock);

	if (change_mask) {
		struct ieee80211_sta *sta;
		int ret = 0;


		for (i = 0; i < CW1250_MAX_STA_IN_AP_MODE ; ++i) {

			if(BES2600_LINK_HARD != priv->link_id_db[i].status)
				continue;

			mask = BIT(i + 1);

			/* If FW state and host state for this link are different then notify OMAC */
			if(change_mask & mask) {

				bes2600_dbg(BES2600_DBG_WSM, "PS State Changed %d for sta %pM\n", (sta_asleep_mask & mask) ? 1:0, priv->link_id_db[i].mac);


				rcu_read_lock();
				sta = ieee80211_find_sta(priv->vif, priv->link_id_db[i].mac);
				if (!sta) {
					bes2600_err(BES2600_DBG_WSM, "[WSM] WRBC - could not find sta %pM\n",
							priv->link_id_db[i].mac);
				} else {
					ret = ieee80211_sta_ps_transition_ni(sta, (sta_asleep_mask & mask) ? true: false);
					bes2600_dbg(BES2600_DBG_WSM, "PS State NOTIFIED %d\n", ret);
					WARN_ON(ret);
				}
				rcu_read_unlock();
			}
		}
		/* Replace STA mask with one reported by FW */
		spin_lock_bh(&priv->ps_state_lock);
		priv->sta_asleep_mask = sta_asleep_mask;
		spin_unlock_bh(&priv->ps_state_lock);
	}

	bes2600_dbg(BES2600_DBG_WSM, "[WSM] WRBC - HW Buf count %d SleepMask %d\n",
					hw_priv->hw_bufs_used, sta_asleep_mask);
	hw_priv->buf_released = 0;
	WARN_ON(count != (hw_priv->wsm_caps.numInpChBufs - 1));

	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

/* 3.67 */
int wsm_request_buffer_request(struct bes2600_vif *priv,
				u8 *arg)
{
	int ret;
	struct wsm_buf *buf = &priv->hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(priv->hw_priv);

	WSM_PUT8(buf, (*arg));
	WSM_PUT8(buf, 0);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(priv->hw_priv, buf, arg, 0x0023, WSM_CMD_JOIN_TIMEOUT,priv->if_id);

	wsm_cmd_unlock(priv->hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(priv->hw_priv);
	return -ENOMEM;
}

#endif


int wsm_set_keepalive_filter(struct bes2600_vif *priv, bool enable)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	priv->rx_filter.keepalive = enable;
	return wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
}

int wsm_set_probe_responder(struct bes2600_vif *priv, bool enable)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);

	priv->rx_filter.probeResponder = enable;
	return wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
}
/* ******************************************************************** */
/* WSM indication events implementation					*/

static int wsm_startup_indication(struct bes2600_common *hw_priv,
					struct wsm_buf *buf)
{
	u16 status;
	char fw_label[129];
	static const char * const fw_types[] = {
		"ETF",
		"WFM",
		"WSM",
		"HI test",
		"Platform test"
	};

	hw_priv->wsm_caps.numInpChBufs	= WSM_GET16(buf);
	hw_priv->wsm_caps.sizeInpChBuf	= WSM_GET16(buf);
	hw_priv->wsm_caps.hardwareId	= WSM_GET16(buf);
	hw_priv->wsm_caps.hardwareSubId	= WSM_GET16(buf);
	status				= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareCap	= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareType	= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareApiVer	= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareBuildNumber = WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareVersion	= WSM_GET16(buf);
	WSM_GET(buf, &fw_label[0], sizeof(fw_label) - 1);
	fw_label[sizeof(fw_label) - 1] = 0; /* Do not trust FW too much. */

	if (WARN_ON(status))
		return -EINVAL;

	if (WARN_ON(hw_priv->wsm_caps.firmwareType > 4))
		return -EINVAL;

	bes2600_dbg(BES2600_DBG_INIT, "BES2600 WSM init done.\n"
		"   Input buffers: %d x %d bytes\n"
		"   Hardware: %d.%d\n"
		"   %s firmware [%s], ver: %d, build: %d,"
			" api: %d, cap: 0x%.4X\n",
		hw_priv->wsm_caps.numInpChBufs,
		hw_priv->wsm_caps.sizeInpChBuf,
		hw_priv->wsm_caps.hardwareId,
		hw_priv->wsm_caps.hardwareSubId,
		fw_types[hw_priv->wsm_caps.firmwareType],
		&fw_label[0],
		hw_priv->wsm_caps.firmwareVersion,
		hw_priv->wsm_caps.firmwareBuildNumber,
		hw_priv->wsm_caps.firmwareApiVer,
		hw_priv->wsm_caps.firmwareCap);

	hw_priv->wsm_caps.firmwareReady = 1;

	wake_up(&hw_priv->wsm_startup_done);

	return 0;

underflow:
	WARN_ON(1);
	return -EINVAL;
}

static int wsm_receive_indication(struct bes2600_common *hw_priv,
					int interface_link_id,
					struct wsm_buf *buf,
					struct sk_buff **skb_p)
{
	struct bes2600_vif *priv;
	s8 pkt_signal = 0;

	hw_priv->rx_timestamp = jiffies;
	if (hw_priv->wsm_cbc.rx) {
		struct wsm_rx rx;
		struct ieee80211_hdr *hdr;
		size_t hdr_len;
		__le16 fctl;

		rx.status = WSM_GET32(buf);
		rx.channelNumber = WSM_GET16(buf);
		rx.rxedRate = WSM_GET8(buf);
		rx.rcpiRssi = WSM_GET8(buf);
		rx.flags = WSM_GET32(buf);
		buf->data+=16; // 2019-10-25, for lmac wsm data ind struct update

		/* TODO:COMBO: Frames received from scanning are received
		* with interface ID == 2 */
		if (is_hardware_cw1250(hw_priv) || is_hardware_cw1260(hw_priv)) {
			if (interface_link_id == CW12XX_GENERIC_IF_ID) {
				/* Frames received in response to SCAN
				 * Request */
				interface_link_id =
					get_interface_id_scanning(hw_priv);
				if (interface_link_id == -1) {
					interface_link_id = hw_priv->roc_if_id;
				}
#ifdef ROAM_OFFLOAD
				if (hw_priv->auto_scanning) {
					interface_link_id = hw_priv->scan.if_id;
				}
#endif/*ROAM_OFFLOAD*/
			}
			/* linkid (peer sta id is encoded in bit 25-28 of
			   flags field */
			rx.link_id = ((rx.flags & (0xf << 25)) >> 25);
			rx.if_id = interface_link_id;
		} else {
			rx.link_id = interface_link_id;
			rx.if_id = 0;
		}

		if(rx.if_id == -1) {
			bes2600_info(BES2600_DBG_WSM, "%s: intf is not match\n", __func__);
			return 0;
		}

		priv = cw12xx_hwpriv_to_vifpriv(hw_priv, rx.if_id);
		if (!priv) {
			bes2600_info(BES2600_DBG_WSM, "%s: NULL priv drop frame\n", __func__);
			return 0;
		}

		/* FW Workaround: Drop probe resp or
		beacon when RSSI is 0 */
		hdr = (struct ieee80211_hdr *) buf->data;

		if (!rx.rcpiRssi &&
			(ieee80211_is_probe_resp(hdr->frame_control) ||
			ieee80211_is_beacon(hdr->frame_control))) {
			spin_unlock(&priv->vif_lock);
			return 0;
		}

		/* If no RSSI subscription has been made,
		* convert RCPI to RSSI here */
		if (!priv->cqm_use_rssi) {
			pkt_signal = rx.rcpiRssi / 2 - 110;
			rx.rcpiRssi = rx.rcpiRssi / 2 - 110;
		}

		if(ieee80211_is_data(hdr->frame_control)) {
			if (priv->signal == 0) {
				priv->signal = pkt_signal;
				priv->signal_mul = pkt_signal * 100;
			} else {
				priv->signal_mul = priv->signal_mul * 80 / 100 + pkt_signal * 20;
				priv->signal = priv->signal_mul / 100;
			}

			bes2600_dbg(BES2600_DBG_TXRX, "pkt signal:%d\n", priv->signal);
		}


		fctl = *(__le16 *)buf->data;
		hdr_len = buf->data - buf->begin;
		skb_pull(*skb_p, hdr_len);

		if (!rx.status &&
			unlikely(ieee80211_is_deauth(fctl) || ieee80211_is_disassoc(fctl))) {
			bes2600_dbg(BES2600_DBG_WSM, "rx deauth or disassoc, priv->join_status:%u", priv->join_status);
			if (priv->join_status == BES2600_JOIN_STATUS_STA &&
				(ether_addr_equal(hdr->addr3, priv->join_bssid) ||
				 ether_addr_equal(hdr->addr3, priv->bssid))) {
				bool ignore = false;

				if (is_multicast_ether_addr(hdr->addr1)) {
					struct ieee80211_mmie *mmie;
					bool has_mmie = false;
					/*
					 * We may receive broadcast/multicast robust management frame
					 * when PMF is enabled, in that case, FW has checked the MMIE
					 * and verified IPN and MIC.
					 * However, some buggy AP, e.g. Tenda AC6, send broadcast deauth
					 * with MMIE even when no management frame protection,
					 * this frame should be ignored and dropped by mac80211.
					 */
					if ((*skb_p)->len >= 24 + sizeof(*mmie)) {
						mmie = (struct ieee80211_mmie *)
							   ((*skb_p)->data + (*skb_p)->len - sizeof(*mmie));
						if (mmie->element_id == WLAN_EID_MMIE &&
							mmie->length == sizeof(*mmie) - 2)
							has_mmie = true;
					}
					bes2600_info(BES2600_DBG_WSM, "[WSM] RX broadcast/multicast deauth: len=%d, has_mmie:%u, pmf=%d\n",
							(*skb_p)->len, has_mmie, priv->pmf);
					if (has_mmie ^ priv->pmf)
						ignore = true;
				} else if (ether_addr_equal(hdr->addr1, priv->vif->addr)) {
					bool has_protected = ieee80211_has_protected(fctl);
					bes2600_info(BES2600_DBG_WSM, "[WSM] RX unicast deauth: protected=%d, pmf=%d, connect_in_process=%d\n",
							has_protected, priv->pmf, atomic_read(&priv->connect_in_process));
					/*
					 * We should report unprotected deauth to mac80211 for
					 * SA query when PMF is enabled, so cannot unjoin here.
					 * If PMF is disabled, it is unexpected to receive
					 * a protected unicast deauth.
					 */
					if ((has_protected ^ priv->pmf) || atomic_read(&priv->connect_in_process))
						ignore = true;
				} else {
					ignore = true;
				}

				if (!ignore) {
					/* Schedule unjoin work */
					bes2600_info(BES2600_DBG_WSM, "[WSM] Issue unjoin command (RX).\n");
					wsm_lock_tx_async(hw_priv);
					if (queue_work(hw_priv->workqueue,
								   &priv->unjoin_work) <= 0) {
						wsm_unlock_tx(hw_priv);
					}
#ifdef CONFIG_PM
					else if(bes2600_suspend_status_get(hw_priv)) {
						bes2600_pending_unjoin_set(hw_priv, priv->if_id);
					}
#endif
					if (bes2600_chrdev_wakeup_by_event_get() == WAKEUP_EVENT_PEER_DETACH)
						bes2600_chrdev_wifi_update_wakeup_reason(WAKEUP_REASON_WIFI_DEAUTH_DISASSOC, 0);
				}
			}
			bes2600_chrdev_wakeup_by_event_set(WAKEUP_EVENT_NONE);
		}
		hw_priv->wsm_cbc.rx(priv, &rx, skb_p);
		if (*skb_p)
			skb_push(*skb_p, hdr_len);
		spin_unlock(&priv->vif_lock);
	}
	return 0;

underflow:
	return -EINVAL;
}

static int wsm_event_indication(struct bes2600_common *hw_priv,
				struct wsm_buf *buf,
				int interface_link_id)
{
	int first;
	struct bes2600_wsm_event *event;
	struct bes2600_vif *priv;

	if (!is_hardware_cw1250(hw_priv) && !is_hardware_cw1260(hw_priv))
		interface_link_id = 0;

	priv = cw12xx_hwpriv_to_vifpriv(hw_priv, interface_link_id);

	if (unlikely(!priv)) {
		bes2600_info(BES2600_DBG_WSM, "[WSM] Not find corresponding interface\n");
		return 0;
	}

	if (unlikely(priv->mode == NL80211_IFTYPE_UNSPECIFIED)) {
		/* STA is stopped. */
		spin_unlock(&priv->vif_lock);
		return 0;
	}
	spin_unlock(&priv->vif_lock);

	event = kzalloc(sizeof(struct bes2600_wsm_event), GFP_KERNEL);

	event->evt.eventId = __le32_to_cpu(WSM_GET32(buf));
	event->evt.eventData = __le32_to_cpu(WSM_GET32(buf));
	event->if_id = interface_link_id;

	bes2600_dbg(BES2600_DBG_WSM, "[WSM] Event: %d(%d)\n",
		event->evt.eventId, event->evt.eventData);

	spin_lock(&hw_priv->event_queue_lock);
	first = list_empty(&hw_priv->event_queue);
	list_add_tail(&event->link, &hw_priv->event_queue);
	spin_unlock(&hw_priv->event_queue_lock);

	if (first)
		queue_work(hw_priv->workqueue, &hw_priv->event_handler);

	return 0;

underflow:
	kfree(event);
	return -EINVAL;
}

/* TODO:COMBO:Make this perVIFF once mac80211 support is available */
static int wsm_channel_switch_indication(struct bes2600_common *hw_priv,
						struct wsm_buf *buf)
{
	wsm_unlock_tx(hw_priv); /* Re-enable datapath */
	WARN_ON(WSM_GET32(buf));

	hw_priv->channel_switch_in_progress = 0;
	wake_up(&hw_priv->channel_switch_done);

	if (hw_priv->wsm_cbc.channel_switch)
		hw_priv->wsm_cbc.channel_switch(hw_priv);
	return 0;

underflow:
	return -EINVAL;
}

static int wsm_set_pm_indication(struct bes2600_common *hw_priv,
					struct wsm_buf *buf)
{
	struct wsm_set_pm_complete arg;

	arg.status = WSM_GET32(buf);
	arg.psm = WSM_GET8(buf);

	if(arg.status == WSM_STATUS_SUCCESS) {
		bes2600_pwr_notify_ps_changed(hw_priv, arg.psm);
	} else {
		bes2600_err(BES2600_DBG_WSM, "[WSM] PM Ind status:%d psm:%d\n", arg.status, arg.psm);
	}

	return 0;

underflow:
	return -EINVAL;
}

static int wsm_scan_complete_indication(struct bes2600_common *hw_priv,
					struct wsm_buf *buf)
{
#ifdef ROAM_OFFLOAD
	if(hw_priv->auto_scanning == 0)
		wsm_oper_unlock(hw_priv);
#else
	wsm_oper_unlock(hw_priv);
#endif /*ROAM_OFFLOAD*/

	if (hw_priv->wsm_cbc.scan_complete) {
		struct wsm_scan_complete arg;
		arg.status = WSM_GET32(buf);
		arg.psm = WSM_GET8(buf);
		arg.numChannels = WSM_GET8(buf);
		hw_priv->wsm_cbc.scan_complete(hw_priv, &arg);
	}
	return 0;

underflow:
	return -EINVAL;
}

static int wsm_find_complete_indication(struct bes2600_common *hw_priv,
					struct wsm_buf *buf)
{
	/* TODO: Implement me. */
	//STUB();
	return 0;
}

static int wsm_suspend_resume_indication(struct bes2600_common *hw_priv,
					 int interface_link_id,
					 struct wsm_buf *buf)
{
	if (hw_priv->wsm_cbc.suspend_resume) {
		u32 flags;
		struct wsm_suspend_resume arg;
		struct bes2600_vif *priv;

		if (is_hardware_cw1250(hw_priv) ||
				is_hardware_cw1260(hw_priv)) {
			int i;
			arg.if_id = interface_link_id;
			/* TODO:COMBO: Extract bitmap from suspend-resume
			* TX indication */
			bes2600_for_each_vif(hw_priv, priv, i) {
				if (!priv)
					continue;
				if (priv->join_status ==
						BES2600_JOIN_STATUS_AP) {
					 arg.if_id = priv->if_id;
					 break;
				}
				arg.link_id = 0;
			}
		} else {
			arg.if_id = 0;
			arg.link_id = interface_link_id;
		}

		flags = WSM_GET32(buf);
		arg.stop = !(flags & 1);
		arg.multicast = !!(flags & 8);
		arg.queue = (flags >> 1) & 3;

		priv = cw12xx_hwpriv_to_vifpriv(hw_priv, arg.if_id);
		if (unlikely(!priv)) {
			bes2600_dbg(BES2600_DBG_WSM, "[WSM] suspend-resume indication"
				   " for removed interface!\n");
			return 0;
		}
		hw_priv->wsm_cbc.suspend_resume(priv, &arg);
		spin_unlock(&priv->vif_lock);
	}
	return 0;

underflow:
	return -EINVAL;
}

/**
 * signaling cmd confirm.
 */

int wsm_driver_rf_cmd_confirm(struct bes2600_common *hw_priv, void *arg, struct wsm_buf *buf)
{
	int ret = 0;
	u32 cmd_type;
	struct wsm_mcu_hdr *msg_hdr = (struct wsm_mcu_hdr *)(buf->begin);

	cmd_type = __le32_to_cpu(msg_hdr->cmd_type);
	buf->data += sizeof(struct wsm_mcu_hdr) - sizeof(struct wsm_hdr);

	switch (cmd_type) {
	case BES2600_RF_CMD_CALI_TXT_TO_FLASH:
		ret = WSM_GET32(buf);
		break;
	default:
		break;
	}

	return ret;

underflow:
	return -EINVAL;
}

/* ******************************************************************** */
/* WSM TX								*/

int wsm_cmd_send(struct bes2600_common *hw_priv,
		 struct wsm_buf *buf,
		 void *arg, u16 cmd, long tmo, int if_id)
{
	size_t buf_len = buf->data - buf->begin;
	int ret;

	if (cmd == 0x0006) /* Write MIB */
		bes2600_dbg(BES2600_DBG_WSM, "[WSM] >>> 0x%.4X [MIB: 0x%.4X] (%lu)\n",
			cmd, __le16_to_cpu(((__le16 *)buf->begin)[2]),
			(long unsigned)buf_len);
	else
		bes2600_dbg(BES2600_DBG_WSM, "[WSM] >>> 0x%.4X (%lu)\n", cmd, (long unsigned)buf_len);

	/* Fill HI message header */
	/* BH will add sequence number */

	/* TODO:COMBO: Add if_id from  to the WSM header */
	/* if_id == -1 indicates that command is HW specific,
	 * eg. wsm_configuration which is called during driver initialzation
	 *  (mac80211 .start callback called when first ifce is created. )*/

	/* send hw specific commands on if 0 */
	if (if_id == -1)
		if_id = 0;

	((__le16 *)buf->begin)[0] = __cpu_to_le16(buf_len);
	if (IS_DRIVER_TO_MCU_CMD(cmd))
		((__le16 *)buf->begin)[1] = __cpu_to_le16(cmd);
	else
		((__le16 *)buf->begin)[1] = __cpu_to_le16(cmd |
					((is_hardware_cw1250(hw_priv)|| is_hardware_cw1260(hw_priv)) ?
						(if_id << 6) : 0));

#ifdef BES2600_HOST_TIMESTAMP_DEBUG
	if (buf->end >= buf->data + 4)
		*(u32 *)buf->data = (u32)jiffies_to_msecs(jiffies);
#endif

	spin_lock(&hw_priv->wsm_cmd.lock);
	BUG_ON(hw_priv->wsm_cmd.ptr);
	hw_priv->wsm_cmd.done = 0;
	hw_priv->wsm_cmd.ptr = buf->begin;
	hw_priv->wsm_cmd.len = buf_len;
	hw_priv->wsm_cmd.arg = arg;
	hw_priv->wsm_cmd.cmd = cmd;
	spin_unlock(&hw_priv->wsm_cmd.lock);
	bes2600_tx_loop_record_wsm_cmd(hw_priv, hw_priv->wsm_cmd.ptr);

	bes2600_bh_wakeup(hw_priv);

	if (unlikely(hw_priv->bh_error)) {
		/* Do not wait for timeout if BH is dead. Exit immediately. */
		ret = 0;
	} else {
		long rx_timestamp;
		long wsm_cmd_starttime = jiffies;
		long wsm_cmd_runtime;
		long wsm_cmd_max_tmo = WSM_CMD_DEFAULT_TIMEOUT;

		/* Give start cmd a little more time */
		if (tmo == WSM_CMD_START_TIMEOUT)
			wsm_cmd_max_tmo = WSM_CMD_START_TIMEOUT;
		/* Firmware prioritizes data traffic over control confirm.
		 * Loop below checks if data was RXed and increases timeout
		 * accordingly. */
		do {
			/* It's safe to use unprotected access to
			 * wsm_cmd.done here */
			ret = wait_event_timeout(
					hw_priv->wsm_cmd_wq,
					hw_priv->wsm_cmd.done, tmo);
			rx_timestamp = jiffies - hw_priv->rx_timestamp;
			wsm_cmd_runtime = jiffies - wsm_cmd_starttime;
			if (unlikely(rx_timestamp < 0) || wsm_cmd_runtime < 0)
				rx_timestamp = tmo + 1;
		} while (!ret && rx_timestamp <= tmo &&
					wsm_cmd_runtime < wsm_cmd_max_tmo);
	}

	if (unlikely(ret == 0)) {
		u16 raceCheck;

		spin_lock(&hw_priv->wsm_cmd.lock);
		raceCheck = hw_priv->wsm_cmd.cmd;
		hw_priv->wsm_cmd.arg = NULL;
		hw_priv->wsm_cmd.ptr = NULL;
		spin_unlock(&hw_priv->wsm_cmd.lock);

		/* Race condition check to make sure _confirm is not called
		 * after exit of _send */
		if (raceCheck == 0xFFFF) {
			/* If wsm_handle_rx got stuck in _confirm we will hang
			 * system there. It's better than silently currupt
			 * stack or heap, isn't it? */
			BUG_ON(wait_event_timeout(
					hw_priv->wsm_cmd_wq,
					hw_priv->wsm_cmd.done,
					WSM_CMD_LAST_CHANCE_TIMEOUT) <= 0);
		}

		/* Kill BH thread to report the error to the top layer. */
		//hw_priv->bh_error = 1;
		wake_up(&hw_priv->bh_wq);
		ret = -ETIMEDOUT;
	} else {
		spin_lock(&hw_priv->wsm_cmd.lock);
		hw_priv->wsm_cmd.arg = NULL;
		hw_priv->wsm_cmd.ptr = NULL;
		BUG_ON(!hw_priv->wsm_cmd.done);
		ret = hw_priv->wsm_cmd.ret;
		spin_unlock(&hw_priv->wsm_cmd.lock);
	}
	bes2600_tx_loop_clear_wsm_cmd(hw_priv);
	wsm_buf_reset(buf);
	return ret;
}

/* ******************************************************************** */
/* WSM TX port control							*/

void wsm_lock_tx(struct bes2600_common *hw_priv)
{
	wsm_cmd_lock(hw_priv);
	if (atomic_add_return(1, &hw_priv->tx_lock) == 1) {
		if (wsm_flush_tx(hw_priv))
			bes2600_dbg(BES2600_DBG_WSM, "[WSM] TX is locked.\n");
	}
	wsm_cmd_unlock(hw_priv);
}

void wsm_vif_lock_tx(struct bes2600_vif *priv)
{
	struct bes2600_common *hw_priv = priv->hw_priv;

	wsm_cmd_lock(hw_priv);
	if (atomic_add_return(1, &hw_priv->tx_lock) == 1) {
		if (wsm_vif_flush_tx(priv))
			bes2600_dbg(BES2600_DBG_WSM, "[WSM] TX is locked for"
					" if_id %d.\n", priv->if_id);
	}
	wsm_cmd_unlock(hw_priv);
}

void wsm_lock_tx_async(struct bes2600_common *hw_priv)
{
	if (atomic_add_return(1, &hw_priv->tx_lock) == 1)
		bes2600_dbg(BES2600_DBG_WSM, "[WSM] TX is locked (async).\n");
}

bool wsm_flush_tx(struct bes2600_common *hw_priv)
{
	unsigned long timestamp = jiffies;
	bool pending = false;
	long timeout;
	int i;

	/* Flush must be called with TX lock held. */
	BUG_ON(!atomic_read(&hw_priv->tx_lock));

	/* First check if we really need to do something.
	 * It is safe to use unprotected access, as hw_bufs_used
	 * can only decrements. */

	if (!hw_priv->hw_bufs_used)
		return true;

	if (hw_priv->bh_error) {
		/* In case of failure do not wait for magic. */
		bes2600_err(BES2600_DBG_WSM, "[WSM] Fatal error occured, "
				"will not flush TX.\n");
		return false;
	} else {
		/* Get a timestamp of "oldest" frame */
		for (i = 0; i < 4; ++i)
			pending |= bes2600_queue_get_xmit_timestamp(
					&hw_priv->tx_queue[i],
					&timestamp, CW12XX_ALL_IFS,
					0xffffffff);
		/* It is allowed to lock TX with only a command in the pipe. */
		if (!pending)
			return true;

		timeout = timestamp + WSM_CMD_LAST_CHANCE_TIMEOUT - jiffies;
		if (timeout < 0 || wait_event_timeout(hw_priv->bh_evt_wq,
				!hw_priv->hw_bufs_used,
				timeout) <= 0) {
			/* Hmmm... Not good. Frame had stuck in firmware. */
			bes2600_chrdev_wifi_force_close(hw_priv, true);
		}

		/* Ok, everything is flushed. */
		return true;
	}
}

bool wsm_vif_flush_tx(struct bes2600_vif *priv)
{
	struct bes2600_common *hw_priv = priv->hw_priv;
	unsigned long timestamp = jiffies;
	unsigned long timeout;
	int i;
	int if_id = priv->if_id;


	/* Flush must be called with TX lock held. */
	BUG_ON(!atomic_read(&hw_priv->tx_lock));

	/* First check if we really need to do something.
	 * It is safe to use unprotected access, as hw_bufs_used
	 * can only decrements. */

	if (!hw_priv->hw_bufs_used_vif[priv->if_id])
		return true;

	if (hw_priv->bh_error) {
		/* In case of failure do not wait for magic. */
		bes2600_err(BES2600_DBG_WSM,  "[WSM] Fatal error occured, "
				"will not flush TX.\n");
		return false;
	} else {
		/* Get a timestamp of "oldest" frame */
		for (i = 0; i < 4; ++i)
			bes2600_queue_get_xmit_timestamp(
					&hw_priv->tx_queue[i],
					&timestamp, if_id,
					0xffffffff);
		/* It is allowed to lock TX with only a command in the pipe. */
		if (!hw_priv->hw_bufs_used_vif[if_id])
			return true;

		/* calculate wait time */
		timeout = timestamp + WSM_CMD_LAST_CHANCE_TIMEOUT;
		if (timeout >= jiffies)
			timeout -= jiffies;
		else
			timeout += (ULONG_MAX - jiffies);

		/* wait packets on vif to be flushed */
		if (wait_event_timeout(hw_priv->bh_evt_wq,
				!hw_priv->hw_bufs_used_vif[if_id],
				timeout) <= 0) {
			/* Hmmm... Not good. Frame had stuck in firmware. */
			bes2600_chrdev_wifi_force_close(hw_priv, true);
		}

		/* Ok, everything is flushed. */
		return true;
	}
}


void wsm_unlock_tx(struct bes2600_common *hw_priv)
{
	int tx_lock;
	if (hw_priv->bh_error)
		bes2600_err(BES2600_DBG_WSM, "fatal error occured, unlock is unsafe\n");
	else {
		tx_lock = atomic_sub_return(1, &hw_priv->tx_lock);
		if (tx_lock < 0) {
			BUG_ON(1);
		} else if (tx_lock == 0) {
			bes2600_bh_wakeup(hw_priv);
			bes2600_dbg(BES2600_DBG_WSM, "[WSM] TX is unlocked.\n");
		}
	}
}

/* ******************************************************************** */
/* WSM RX								*/

int wsm_handle_exception(struct bes2600_common *hw_priv, u8 *data, size_t len)
{
#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	struct bes2600_vif *priv = NULL;
	int if_id = 0;
#endif
	struct wsm_buf buf;
	u32 reason;
	u32 reg[18];
	char fname[48];
	size_t i;

	static const char * const reason_str[] = {
		"undefined instruction",
		"prefetch abort",
		"data abort",
		"unknown error",
	};

#if defined(CONFIG_BES2600_USE_STE_EXTENSIONS)
	/* Send the event upwards on the FW exception */
	bes2600_pm_stay_awake(&hw_priv->pm_state, 3*HZ);

	spin_lock(&hw_priv->vif_list_lock);
	bes2600_for_each_vif(hw_priv, priv, if_id) {
		if (!priv)
			continue;
		ieee80211_driver_hang_notify(priv->vif, GFP_KERNEL);
	}
	spin_unlock(&hw_priv->vif_list_lock);
#endif

	buf.begin = buf.data = data;
	buf.end = &buf.begin[len];

	reason = WSM_GET32(&buf);
	for (i = 0; i < ARRAY_SIZE(reg); ++i)
		reg[i] = WSM_GET32(&buf);
	WSM_GET(&buf, fname, sizeof(fname));

	if (reason < 4)
		wiphy_err(hw_priv->hw->wiphy,
			"Firmware exception: %s.\n",
			reason_str[reason]);
	else
		wiphy_err(hw_priv->hw->wiphy,
			"Firmware assert at %.*s, line %d\n",
			(int)sizeof(fname), fname, (int)reg[1]);

	for (i = 0; i < 12; i += 4)
		wiphy_err(hw_priv->hw->wiphy,
			"R%d: 0x%.8X, R%d: 0x%.8X, R%d: 0x%.8X, R%d: 0x%.8X,\n",
			(int)i + 0, reg[i + 0], (int)i + 1, reg[i + 1],
			(int)i + 2, reg[i + 2], (int)i + 3, reg[i + 3]);
	wiphy_err(hw_priv->hw->wiphy,
		"R12: 0x%.8X, SP: 0x%.8X, LR: 0x%.8X, PC: 0x%.8X,\n",
		reg[i + 0], reg[i + 1], reg[i + 2], reg[i + 3]);
	i += 4;
	wiphy_err(hw_priv->hw->wiphy,
		"CPSR: 0x%.8X, SPSR: 0x%.8X\n",
		reg[i + 0], reg[i + 1]);

	print_hex_dump_bytes("R1: ", DUMP_PREFIX_NONE,
		fname, sizeof(fname));
	return 0;

underflow:
	wiphy_err(hw_priv->hw->wiphy,
		"Firmware exception.\n");
	print_hex_dump_bytes("Exception: ", DUMP_PREFIX_NONE,
		data, len);
	return -EINVAL;
}
EXPORT_SYMBOL(wsm_handle_exception);

int wsm_bt_ts_request(struct bes2600_common *hw_priv, struct wsm_buf *buf)
{
#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
	uint32_t type;

	type = __le32_to_cpu(((struct wsm_mcu_hdr *)(buf->begin))->cmd_type);
	bbt_change_current_status(hw_priv, type);
	return 0;
#else
	return 0;
#endif
}

int wsm_handle_rx(struct bes2600_common *hw_priv, int id,
		  struct wsm_hdr *wsm, struct sk_buff **skb_p)
{
	int ret = 0;
	struct wsm_buf wsm_buf;
//	struct bes2600_vif *priv = NULL;
//	int i = 0;
	int interface_link_id = (id >> 6) & 0x0F;
	u32 ind_confirm_label = 0x0;  /* wsm to mcu cmd ind & cnfirm label */

#ifdef ROAM_OFFLOAD
#if 0
	struct bes2600_vif *priv;
	priv = cw12xx_hwpriv_to_vifpriv(hw_priv, interface_link_id);
	if (unlikely(!priv)) {
		WARN_ON(1);
		return 0;
	}
	spin_unlock(&priv->vif_lock);
#endif
#endif/*ROAM_OFFLOAD*/

	/* Strip link id. */
	id &= ~WSM_TX_LINK_ID(WSM_TX_LINK_ID_MAX);

	wsm_buf.begin = (u8 *)&wsm[0];
	wsm_buf.data = (u8 *)&wsm[1];
	wsm_buf.end = &wsm_buf.begin[__le32_to_cpu(wsm->len)];

	bes2600_dbg(BES2600_DBG_WSM, "[WSM] <<< 0x%.4X (%ld)\n", id,
			(long)(wsm_buf.end - wsm_buf.begin));

	if (IS_DRIVER_TO_MCU_CMD(id))
		ind_confirm_label = __le32_to_cpu(((struct wsm_mcu_hdr *)wsm)->handle_label);

	if (id == 0x404) {
		ret = wsm_tx_confirm(hw_priv, &wsm_buf, interface_link_id);
#ifdef MCAST_FWDING
#if 1
	} else if (id == 0x422) {
		ret = wsm_give_buffer_confirm(hw_priv, &wsm_buf);
#endif
#endif

	} else if (id == 0x41E) {
		ret = wsm_multi_tx_confirm(hw_priv, &wsm_buf,
					   interface_link_id);
	} else if (WSM_CONFIRM_CONDITION(id, ind_confirm_label)) {
		void *wsm_arg;
		u16 wsm_cmd;

		/* Do not trust FW too much. Protection against repeated
		 * response and race condition removal (see above). */
		spin_lock(&hw_priv->wsm_cmd.lock);
		wsm_arg = hw_priv->wsm_cmd.arg;
		wsm_cmd = hw_priv->wsm_cmd.cmd &
				~WSM_TX_LINK_ID(WSM_TX_LINK_ID_MAX);
		hw_priv->wsm_cmd.cmd = 0xFFFF;
		spin_unlock(&hw_priv->wsm_cmd.lock);

		if (((id & 0x0f00) == 0x0400) && WARN_ON((id & ~0x0400) != wsm_cmd)) {
			/* Note that any non-zero is a fatal retcode. */
			ret = -EINVAL;
			goto out;
		}

		switch (id) {
		case 0x0409:
			/* Note that wsm_arg can be NULL in case of timeout in
			 * wsm_cmd_send(). */
			if (likely(wsm_arg))
				ret = wsm_configuration_confirm(hw_priv,
								wsm_arg,
								&wsm_buf);
			break;
		case 0x0405:
			if (likely(wsm_arg))
				ret = wsm_read_mib_confirm(hw_priv, wsm_arg,
								&wsm_buf);
			break;
		case 0x0406:
			if (likely(wsm_arg))
				ret = wsm_write_mib_confirm(hw_priv, wsm_arg,
								&wsm_buf,
								interface_link_id);
			break;
		case 0x040B:
			if (likely(wsm_arg))
				ret = wsm_join_confirm(hw_priv, wsm_arg,
							   &wsm_buf);
			break;

#ifdef MCAST_FWDING
		case 0x0423: /* req buffer cfm*/
			if (likely(wsm_arg)){
				bes2600_for_each_vif(hw_priv, priv, i) {
					if (priv && (priv->join_status == BES2600_JOIN_STATUS_AP))
						ret = wsm_request_buffer_confirm(priv,
								wsm_arg, &wsm_buf);
				}
			}
			break;
#endif
		case 0x0407: /* start-scan */
#ifdef ROAM_OFFLOAD
			if (hw_priv->auto_scanning) {
				if (atomic_read(&hw_priv->scan.in_progress)) {
					hw_priv->auto_scanning = 0;
				}
				else {
					wsm_oper_unlock(hw_priv);
					up(&hw_priv->scan.lock);
				}
			}
#endif /*ROAM_OFFLOAD*/
		case 0x0408: /* stop-scan */
		case 0x040A: /* wsm_reset */
		case 0x040C: /* add_key */
		case 0x040D: /* remove_key */
		case 0x0410: /* wsm_set_pm */
		case 0x0411: /* set_bss_params */
		case 0x0412: /* set_tx_queue_params */
		case 0x0413: /* set_edca_params */
		case 0x0416: /* switch_channel */
		case 0x0417: /* start */
		case 0x0418: /* beacon_transmit */
		case 0x0419: /* start_find */
		case 0x041A: /* stop_find */
		case 0x041B: /* update_ie */
		case 0x041C: /* map_link */
		case 0x0429: /* epta */
			WARN_ON(wsm_arg != NULL);
			ret = wsm_generic_confirm(hw_priv, wsm_arg, &wsm_buf);
			if (ret)
				wiphy_warn(hw_priv->hw->wiphy,
					"wsm_generic_confirm "
					"failed for request 0x%.4X.\n",
					id & ~0x0400);
			break;
#ifdef CONFIG_BES2600_TESTMODE
		case 0x0C25:
			ret = wsm_vendor_rf_cmd_confirm(hw_priv, wsm_arg, &wsm_buf);
			break;
#endif /* CONFIG_BES2600_TESTMODE */
		case 0x0C27:
			ret = wsm_driver_rf_cmd_confirm(hw_priv, wsm_arg, &wsm_buf);
			break;
#ifdef BES_UNIFIED_PM
		case 0x0424: /* wifi sleep disable */
			break;
#endif
		default:
			BUG_ON(1);
		}

		spin_lock(&hw_priv->wsm_cmd.lock);
		hw_priv->wsm_cmd.ret = ret;
		hw_priv->wsm_cmd.done = 1;
		spin_unlock(&hw_priv->wsm_cmd.lock);
		ret = 0; /* Error response from device should ne stop BH. */

		wake_up(&hw_priv->wsm_cmd_wq);
	} else if ((id & 0x0f00) == 0x0800) {
		switch (id) {
		case 0x0801:
			ret = wsm_startup_indication(hw_priv, &wsm_buf);
			break;
		case 0x0804:
			ret = wsm_receive_indication(hw_priv, interface_link_id,
					&wsm_buf, skb_p);
			break;
		case 0x0805:
			ret = wsm_event_indication(hw_priv, &wsm_buf,
					interface_link_id);
			break;
		case 0x080A:
			ret = wsm_channel_switch_indication(hw_priv, &wsm_buf);
			break;
		case 0x0809:
			ret = wsm_set_pm_indication(hw_priv, &wsm_buf);
			break;
		case 0x0806:
#ifdef ROAM_OFFLOAD
			if(hw_priv->auto_scanning && hw_priv->frame_rcvd) {
				struct bes2600_vif *priv;
				hw_priv->frame_rcvd = 0;
				priv = cw12xx_hwpriv_to_vifpriv(hw_priv, hw_priv->scan.if_id);
				if (unlikely(!priv)) {
					WARN_ON(1);
					return 0;
				}
					spin_unlock(&priv->vif_lock);
				if (hw_priv->beacon) {
					struct wsm_scan_complete *scan_cmpl = \
						(struct wsm_scan_complete *) \
						((u8 *)wsm + sizeof(struct wsm_hdr));
					struct ieee80211_rx_status *rhdr = \
						IEEE80211_SKB_RXCB(hw_priv->beacon);
					rhdr->signal = (s8)scan_cmpl->reserved;
					if (!priv->cqm_use_rssi) {
						rhdr->signal = rhdr->signal / 2 - 110;
					}
					if (!hw_priv->beacon_bkp)
						hw_priv->beacon_bkp = \
						skb_copy(hw_priv->beacon, GFP_ATOMIC);
					ieee80211_rx_irqsafe(hw_priv->hw, hw_priv->beacon);
					hw_priv->beacon = hw_priv->beacon_bkp;

					hw_priv->beacon_bkp = NULL;
				}
				bes2600_dbg(BES2600_DBG_WSM, "[WSM] Send Testmode Event.\n");
#ifdef CONFIG_BES2600_TESTMODE
				bes2600_testmode_event(priv->hw->wiphy,
					BES_MSG_NEW_SCAN_RESULTS, 0,
					0, GFP_KERNEL);
#endif

			}
#endif /*ROAM_OFFLOAD*/
			ret = wsm_scan_complete_indication(hw_priv, &wsm_buf);
			break;
		case 0x080B:
			ret = wsm_find_complete_indication(hw_priv, &wsm_buf);
			break;
		case 0x080C:
			ret = wsm_suspend_resume_indication(hw_priv,
					interface_link_id, &wsm_buf);
			break;
		default:
			//STUB();
			break;
		}
	} else if (WSM_TO_MCU_CMD_IND_CONDITION(id, ind_confirm_label)) {
		switch (id) {
#ifdef CONFIG_BES2600_TESTMODE
		case 0x0C25:
			ret = wsm_vendor_rf_test_indication(hw_priv, &wsm_buf);
			break;
#endif /* CONFIG_BES2600_TESTMODE */
		case 0x0C30:
			ret = wsm_bt_ts_request(hw_priv, &wsm_buf);
			break;
		default:
			break;
		}
	} else {
		WARN_ON(1);
		ret = -EINVAL;
	}
out:
	return ret;
}
EXPORT_SYMBOL(wsm_handle_rx);

static bool wsm_handle_tx_data(struct bes2600_vif *priv,
				   const struct wsm_tx *wsm,
				   const struct ieee80211_tx_info *tx_info,
				   struct bes2600_txpriv *txpriv,
				   struct bes2600_queue *queue)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
#ifdef P2P_MULTIVIF
	struct bes2600_vif *p2p_if_vif = NULL;
#endif
	bool handled = false;
	const struct ieee80211_hdr *frame =
		(struct ieee80211_hdr *) &((u8 *)wsm)[txpriv->offset];
	__le16 fctl = frame->frame_control;
	enum {
		doProbe,
		doDrop,
		doJoin,
		doOffchannel,
		doWep,
		doTx,
	} action = doTx;

	hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
#ifdef P2P_MULTIVIF
	if (priv->if_id == CW12XX_GENERIC_IF_ID)
		p2p_if_vif = __cw12xx_hwpriv_to_vifpriv(hw_priv, 2);
#endif
	frame =  (struct ieee80211_hdr *) &((u8 *)wsm)[txpriv->offset];
	fctl  = frame->frame_control;

	switch (priv->mode) {
	case NL80211_IFTYPE_P2P_DEVICE:
	case NL80211_IFTYPE_STATION:
		if (unlikely((priv->join_status == BES2600_JOIN_STATUS_STA) &&
			ieee80211_is_nullfunc(fctl))) {
			spin_lock(&priv->bss_loss_lock);
			if (priv->bss_loss_status == BES2600_BSS_LOSS_CHECKING) {
				priv->bss_loss_status = BES2600_BSS_LOSS_CONFIRMING;
				priv->bss_loss_confirm_id = wsm->packetID;
			}
			spin_unlock(&priv->bss_loss_lock);
		} else if (unlikely(
			(priv->join_status <= BES2600_JOIN_STATUS_MONITOR) ||
			memcmp(frame->addr1, priv->join_bssid,
				sizeof(priv->join_bssid)))) {
#ifdef P2P_MULTIVIF
			if (p2p_if_vif && (p2p_if_vif->join_status >
				BES2600_JOIN_STATUS_MONITOR)
					&& (priv->join_status
						< BES2600_JOIN_STATUS_MONITOR)) {
				/*
					* Post group formation, frame transmission on p2p0
					* interafce should not use offchannel/generic channel.
					* Instead, the frame should be transmitted on interafce
					* 1. This is needed by wsc fw.
					*/
				action = doTx;
				txpriv->raw_if_id = 0;
			} else
#endif
			if (ieee80211_is_auth(fctl))
				action = doJoin;
			else if (ieee80211_is_probe_req(fctl))
				action = doTx;
			else if (memcmp(frame->addr1, priv->join_bssid,
					sizeof(priv->join_bssid)) &&
					(priv->join_status ==
					BES2600_JOIN_STATUS_STA) &&
					(ieee80211_is_data(fctl))) {
				action = doDrop;
			}
			else if (priv->join_status >=
					BES2600_JOIN_STATUS_MONITOR)
				action = doTx;
			else if (get_interface_id_scanning(hw_priv) != -1) {
				wiphy_warn(priv->hw->wiphy,
					"Scan ONGOING dropping offchannel"
					" eligible frame.\n");
				action = doDrop;
			}
			else
				action = doTx;
		}
		break;
	case NL80211_IFTYPE_AP:
		if (unlikely(!priv->join_status))
			action = doDrop;
		else if (unlikely(!(BIT(txpriv->raw_link_id) &
				(BIT(0) | priv->link_id_map)))) {
			wiphy_warn(priv->hw->wiphy,
					"A frame with expired link id "
					"is dropped.\n");
			action = doDrop;
		}
		if (bes2600_queue_get_generation(wsm->packetID) >
				BES2600_MAX_REQUEUE_ATTEMPTS) {
			/* HACK!!! WSM324 firmware has tendency to requeue
				* multicast frames in a loop, causing performance
				* drop and high power consumption of the driver.
				* In this situation it is better just to drop
				* the problematic frame. */
			wiphy_warn(priv->hw->wiphy,
					"Too many attempts "
					"to requeue a frame. "
					"Frame is dropped.\n");
			action = doDrop;
		}
		break;
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_MESH_POINT:
		//STUB();
	case NL80211_IFTYPE_MONITOR:
	default:
		action = doDrop;
		break;
	}

	if (action == doTx) {
		if (unlikely(ieee80211_is_probe_req(fctl))) {
#ifdef CONFIG_BES2600_TESTMODE
			if (hw_priv->enable_advance_scan &&
				(priv->join_status == BES2600_JOIN_STATUS_STA) &&
				(hw_priv->advanceScanElems.scanMode ==
					BES2600_SCAN_MEASUREMENT_ACTIVE))
				/* If Advance Scan is Requested on Active Scan
				 * then transmit the Probe Request */
				action = doTx;
			else
#endif
			action = doProbe;
		} else if ((fctl & __cpu_to_le32(IEEE80211_FCTL_PROTECTED)) &&
			tx_info->control.hw_key &&
			unlikely(tx_info->control.hw_key->keyidx !=
					priv->wep_default_key_id) &&
			(tx_info->control.hw_key->cipher ==
					WLAN_CIPHER_SUITE_WEP40 ||
			 tx_info->control.hw_key->cipher ==
					WLAN_CIPHER_SUITE_WEP104))
			action = doWep;
	}

	switch (action) {
	case doProbe:
	{
		/* An interesting FW "feature". Device filters
		 * probe responses.
		 * The easiest way to get it back is to convert
		 * probe request into WSM start_scan command. */
		bes2600_dbg(BES2600_DBG_WSM,
			"[WSM] Convert probe request to scan.\n");
		wsm_lock_tx_async(hw_priv);
		hw_priv->pending_frame_id = __le32_to_cpu(wsm->packetID);
		queue_delayed_work(hw_priv->workqueue,
				&hw_priv->scan.probe_work, 0);
		handled = true;
	}
	break;
	case doDrop:
	{
		/* See detailed description of "join" below.
		 * We are dropping everything except AUTH in non-joined mode. */
		bes2600_err(BES2600_DBG_WSM, "[WSM] Drop frame (0x%.4X).\n", fctl);
#ifdef CONFIG_BES2600_TESTMODE
		BUG_ON(bes2600_queue_remove(hw_priv, queue,
			__le32_to_cpu(wsm->packetID)));
#else
		BUG_ON(bes2600_queue_remove(queue,
			__le32_to_cpu(wsm->packetID)));
#endif /*CONFIG_BES2600_TESTMODE*/
		handled = true;
	}
	break;
	case doJoin:
	{
		/* There is one more interesting "feature"
		 * in FW: it can't do RX/TX before "join".
		 * "Join" here is not an association,
		 * but just a syncronization between AP and STA.
		 * priv->join_status is used only in bh thread and does
		 * not require protection */
		bes2600_info(BES2600_DBG_WSM, "[WSM] Issue join command.\n");
		wsm_lock_tx_async(hw_priv);
		hw_priv->pending_frame_id = __le32_to_cpu(wsm->packetID);

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
		if (hw_priv->channel->band != NL80211_BAND_2GHZ)
			bwifi_change_current_status(hw_priv, BWIFI_STATUS_CONNECTING_5G);
		else
			bwifi_change_current_status(hw_priv, BWIFI_STATUS_CONNECTING);
#endif
		if (queue_work(hw_priv->workqueue, &priv->join_work) <= 0)
			wsm_unlock_tx(hw_priv);
		handled = true;
	}
	break;
	case doOffchannel:
	{
		bes2600_info(BES2600_DBG_WSM, "[WSM] Offchannel TX request.\n");
		wsm_lock_tx_async(hw_priv);
		hw_priv->pending_frame_id = __le32_to_cpu(wsm->packetID);
		if (queue_work(hw_priv->workqueue, &priv->offchannel_work) <= 0)
			wsm_unlock_tx(hw_priv);
		handled = true;
	}
	break;
	case doWep:
	{
		bes2600_info(BES2600_DBG_WSM,  "[WSM] Issue set_default_wep_key.\n");
		wsm_lock_tx_async(hw_priv);
		priv->wep_default_key_id = tx_info->control.hw_key->keyidx;
		hw_priv->pending_frame_id = __le32_to_cpu(wsm->packetID);
		if (queue_work(hw_priv->workqueue, &priv->wep_key_work) <= 0)
			wsm_unlock_tx(hw_priv);
		handled = true;
	}
	break;
	case doTx:
	{
#if 0
		/* Kept for history. If you want to implement wsm->more,
		 * make sure you are able to send a frame after that. */
		wsm->more = (count > 1) ? 1 : 0;
		if (wsm->more) {
			/* HACK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			 * It's undocumented in WSM spec, but BES2600 hangs
			 * if 'more' is set and no TX is performed due to TX
			 * buffers limitation. */
			if (priv->hw_bufs_used + 1 ==
					priv->wsm_caps.numInpChBufs)
				wsm->more = 0;
		}

		/* BUG!!! FIXME: we can't use 'more' at all: we don't know
		 * future. It could be a request from upper layer with TX lock
		 * requirements (scan, for example). If "more" is set device
		 * will not send data and wsm_tx_lock() will fail...
		 * It's not obvious how to fix this deadlock. Any ideas?
		 * As a workaround more is set to 0. */
		wsm->more = 0;
#endif /* 0 */

		if (ieee80211_is_deauth(fctl) &&
				priv->mode != NL80211_IFTYPE_AP) {
			/* Shedule unjoin work */
			bes2600_info(BES2600_DBG_WSM, "[WSM] Issue unjoin command (TX).\n");
			atomic_set(&priv->connect_in_process, 0);
#if 0
			wsm->more = 0;
#endif /* 0 */

#ifdef WIFI_BT_COEXIST_EPTA_ENABLE
			bwifi_change_current_status(hw_priv, BWIFI_STATUS_DISCONNECTING);
#endif
			wsm_lock_tx_async(hw_priv);
			if (queue_work(hw_priv->workqueue,
					&priv->unjoin_work) <= 0)
				wsm_unlock_tx(hw_priv);
		}
	}
	break;
	}
	return handled;
}

static int bes2600_get_prio_queue(struct bes2600_vif *priv,
				 u32 link_id_map, int *total)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	static u32 urgent;
	struct wsm_edca_queue_params *edca;
	unsigned score, best = -1;
	int winner = -1;
	int queued;
	int i;
	urgent = BIT(priv->link_id_after_dtim) | BIT(priv->link_id_uapsd);

	/* search for a winner using edca params */
	for (i = 0; i < 4; ++i) {
		queued = bes2600_queue_get_num_queued(priv,
				&hw_priv->tx_queue[i],
				link_id_map);
		if (!queued)
			continue;
		*total += queued;
		edca = &priv->edca.params[i];
		score = ((edca->aifns + edca->cwMin) << 16) +
				(edca->cwMax - edca->cwMin) *
				(get_random_u32() & 0xFFFF);
		if (score < best && (winner < 0 || i != 3)) {
			best = score;
			winner = i;
		}
	}

	/* override winner if bursting */
	if (winner >= 0 && hw_priv->tx_burst_idx >= 0 &&
			winner != hw_priv->tx_burst_idx &&
			!bes2600_queue_get_num_queued(priv,
				&hw_priv->tx_queue[winner],
				link_id_map & urgent) &&
			bes2600_queue_get_num_queued(priv,
				&hw_priv->tx_queue[hw_priv->tx_burst_idx],
				link_id_map))
		winner = hw_priv->tx_burst_idx;

	return winner;
}

static int wsm_get_tx_queue_and_mask(struct bes2600_vif *priv,
					 struct bes2600_queue **queue_p,
					 u32 *tx_allowed_mask_p,
					 bool *more)
{
	struct bes2600_common *hw_priv = cw12xx_vifpriv_to_hwpriv(priv);
	int idx;
	u32 tx_allowed_mask;
	int total = 0;

	/* Search for a queue with multicast frames buffered */
	if (priv->tx_multicast) {
		tx_allowed_mask = BIT(priv->link_id_after_dtim);
		idx = bes2600_get_prio_queue(priv,
				tx_allowed_mask, &total);
		if (idx >= 0) {
			*more = total > 1;
			goto found;
		}
	}

	/* Search for unicast traffic */
	tx_allowed_mask = ~priv->sta_asleep_mask;
	tx_allowed_mask |= BIT(priv->link_id_uapsd);
	if (priv->sta_asleep_mask) {
		tx_allowed_mask |= priv->pspoll_mask;
		tx_allowed_mask &= ~BIT(priv->link_id_after_dtim);
	} else {
		tx_allowed_mask |= BIT(priv->link_id_after_dtim);
	}
	idx = bes2600_get_prio_queue(priv,
			tx_allowed_mask, &total);
	if (idx < 0)
		return -ENOENT;

found:
	*queue_p = &hw_priv->tx_queue[idx];
	*tx_allowed_mask_p = tx_allowed_mask;
	return 0;
}

int wsm_get_tx(struct bes2600_common *hw_priv, u8 **data,
		   size_t *tx_len, int *burst, int *vif_selected)
{
	struct wsm_tx *wsm = NULL;
	struct ieee80211_tx_info *tx_info;
	struct bes2600_queue *queue = NULL;
	int queue_num;
	u32 tx_allowed_mask = 0;
	struct bes2600_txpriv *txpriv = NULL;
#ifdef P2P_MULTIVIF
	int first = 1;
#endif
	/*
	 * Count was intended as an input for wsm->more flag.
	 * During implementation it was found that wsm->more
	 * is not usable, see details above. It is kept just
	 * in case you would like to try to implement it again.
	 */
	int count = 0;
#ifdef P2P_MULTIVIF
	int if_pending = CW12XX_MAX_VIFS - 1;
#else
	int if_pending = 1;
#endif

	/* More is used only for broadcasts. */
	bool more = false;

	count = bes2600_itp_get_tx(hw_priv, data, tx_len, burst);
	if (count)
		return count;

	if (hw_priv->wsm_cmd.ptr) {
		++count;
		spin_lock(&hw_priv->wsm_cmd.lock);
		BUG_ON(!hw_priv->wsm_cmd.ptr);
		*data = hw_priv->wsm_cmd.ptr;
		*tx_len = hw_priv->wsm_cmd.len;
		*burst = 1;
		*vif_selected = -1;
		spin_unlock(&hw_priv->wsm_cmd.lock);
	} else {
		for (;;) {
			int ret;
			struct bes2600_vif *priv;
#if 0
			int num_pending_vif0, num_pending_vif1;
#endif
			if (atomic_add_return(0, &hw_priv->tx_lock))
				break;
			/* Keep one buffer reserved for commands. Note
			   that, hw_bufs_used has already been incremented
			   before reaching here. */
			if (hw_priv->hw_bufs_used >=
					hw_priv->wsm_caps.numInpChBufs)
				break;
#ifdef P2P_MULTIVIF
			if (first) {
				first = 0;
				hw_priv->if_id_selected = 0;
			}
#endif
			priv = wsm_get_interface_for_tx(hw_priv);
			/* go to next interface ID to select next packet */
#ifdef P2P_MULTIVIF
			hw_priv->if_id_selected++;
			if(hw_priv->if_id_selected > 2)
				hw_priv->if_id_selected = 0;
#else
				hw_priv->if_id_selected ^= 1;
#endif

			/* There might be no interface before add_interface
			 * call */
			if (!priv) {
				if (if_pending) {
#ifdef P2P_MULTIVIF
					if_pending--;
#else
					if_pending = 0;
#endif
					continue;
				}
				break;
			}

#if 0
			if (((priv->if_id == 0) &&
			(hw_priv->hw_bufs_used_vif[0] >=
						CW12XX_FW_VIF0_THROTTLE)) ||
			((priv->if_id == 1) &&
			(hw_priv->hw_bufs_used_vif[1] >=
						CW12XX_FW_VIF1_THROTTLE))) {
				spin_unlock(&priv->vif_lock);
				if (if_pending) {
					if_pending = 0;
					continue;
				}
				break;
			}
#endif

			/* This can be removed probably: bes2600_vif will not
			 * be in hw_priv->vif_list (as returned from
			 * wsm_get_interface_for_tx) until it's fully
			 * enabled, so statement above will take case of that*/
			if (!atomic_read(&priv->enabled)) {
				spin_unlock(&priv->vif_lock);
				break;
			}

			/* TODO:COMBO: Find the next interface for which
			* packet needs to be found */
			spin_lock_bh(&priv->ps_state_lock);
			ret = wsm_get_tx_queue_and_mask(priv, &queue,
					&tx_allowed_mask, &more);
			queue_num = queue - hw_priv->tx_queue;

			if (priv->buffered_multicasts &&
					(ret || !more) &&
					(priv->tx_multicast ||
					 !priv->sta_asleep_mask)) {
				priv->buffered_multicasts = false;
				if (priv->tx_multicast) {
					priv->tx_multicast = false;
					queue_work(hw_priv->workqueue,
						&priv->multicast_stop_work);
				}
			}

			spin_unlock_bh(&priv->ps_state_lock);

			if (ret) {
				spin_unlock(&priv->vif_lock);
#ifdef P2P_MULTIVIF
				if (if_pending) {
#else
				if (if_pending == 1) {
#endif
#ifdef P2P_MULTIVIF
					if_pending--;
#else
					if_pending = 0;
#endif
					continue;
				}
				break;
			}

			if (bes2600_queue_get(queue,
					priv->if_id,
					tx_allowed_mask,
					&wsm, &tx_info, &txpriv)) {
				spin_unlock(&priv->vif_lock);
				if_pending = 0;
				continue;
			}
#ifndef P2P_MULTIVIF
			{
				struct ieee80211_hdr *hdr =
				(struct ieee80211_hdr *)
					&((u8 *)wsm)[txpriv->offset];

				bes2600_dbg(BES2600_DBG_WSM, "QGET-1 %x, off_id %d,"
						   " if_id %d\n",
						hdr->frame_control,
						txpriv->offchannel_if_id,
						priv->if_id);
			}
#endif
			if (wsm_handle_tx_data(priv, wsm,
					tx_info, txpriv, queue)) {
				spin_unlock(&priv->vif_lock);
				if_pending = 0;
				continue;  /* Handled by WSM */
			}

			wsm->hdr.id &= __cpu_to_le16(
					~WSM_TX_IF_ID(WSM_TX_IF_ID_MAX));
#ifdef P2P_MULTIVIF
			if (txpriv->raw_if_id)
				wsm->hdr.id |= cpu_to_le16(
					WSM_TX_IF_ID(txpriv->raw_if_id));
#else
			if (txpriv->offchannel_if_id)
				wsm->hdr.id |= cpu_to_le16(
					WSM_TX_IF_ID(txpriv->offchannel_if_id));
#endif
			else
				wsm->hdr.id |= cpu_to_le16(
					WSM_TX_IF_ID(priv->if_id));

			*vif_selected = priv->if_id;
#ifdef ROC_DEBUG
			{
				struct ieee80211_hdr *hdr =
				(struct ieee80211_hdr *)
					&((u8 *)wsm)[txpriv->offset];

				bes2600_dbg(BES2600_DBG_WSM, "QGET-2 %x, off_id %d,"
						   " if_id %d\n",
						hdr->frame_control,
						txpriv->offchannel_if_id,
						priv->if_id);
			}
#endif

			priv->pspoll_mask &= ~BIT(txpriv->raw_link_id);

			*data = (u8 *)wsm;
			*tx_len = __le16_to_cpu(wsm->hdr.len);

			/* allow bursting if txop is set */
			if (priv->edca.params[queue_num].txOpLimit)
				*burst = min(*burst,
					(int)bes2600_queue_get_num_queued(priv,
						queue, tx_allowed_mask) + 1);
			else
				*burst = 1;

			/* store index of bursting queue */
			if (*burst > 1)
				hw_priv->tx_burst_idx = queue_num;
			else
				hw_priv->tx_burst_idx = -1;

			if (more) {
				struct ieee80211_hdr *hdr =
					(struct ieee80211_hdr *)
					&((u8 *)wsm)[txpriv->offset];
				if(strstr(&priv->ssid[0], "6.1.12")) {
					if(hdr->addr1[0] & 0x01 ) {
						hdr->frame_control |=
						cpu_to_le16(IEEE80211_FCTL_MOREDATA);
					}
				}
				else {
					/* more buffered multicast/broadcast frames
					*  ==> set MoreData flag in IEEE 802.11 header
					*  to inform PS STAs */
					hdr->frame_control |=
					cpu_to_le16(IEEE80211_FCTL_MOREDATA);
				}
			}
			bes2600_dbg(BES2600_DBG_WSM, "[WSM] >>> 0x%.4X (%lu) %p %c\n",
				0x0004, (long unsigned)*tx_len, *data,
				wsm->more ? 'M' : ' ');
			++count;
			spin_unlock(&priv->vif_lock);
			break;
		}
	}

	return count;
}

void wsm_txed(struct bes2600_common *hw_priv, u8 *data)
{
	if (data == hw_priv->wsm_cmd.ptr) {
		spin_lock(&hw_priv->wsm_cmd.lock);
		hw_priv->wsm_cmd.ptr = NULL;
		spin_unlock(&hw_priv->wsm_cmd.lock);
	} else {
		bes2600_pwr_set_busy_event_async(hw_priv, BES_PWR_LOCK_ON_LMAC_RSP);
	}
}

/* ******************************************************************** */
/* WSM buffer								*/

void wsm_buf_init(struct wsm_buf *buf)
{
	BUG_ON(buf->begin);
	buf->begin = kmalloc(SDIO_BLOCK_SIZE, GFP_KERNEL | GFP_DMA);
	buf->end = buf->begin ? &buf->begin[SDIO_BLOCK_SIZE] : buf->begin;
	wsm_buf_reset(buf);
}

void wsm_buf_deinit(struct wsm_buf *buf)
{
	kfree(buf->begin);
	buf->begin = buf->data = buf->end = NULL;
}

static void wsm_buf_reset(struct wsm_buf *buf)
{
	if (buf->begin) {
		buf->data = &buf->begin[4];
		*(u32 *)buf->begin = 0;
	} else
		buf->data = buf->begin;
}

static int wsm_buf_reserve(struct wsm_buf *buf, size_t extra_size)
{
	size_t pos = buf->data - buf->begin;
	size_t size = pos + extra_size;


	if (size & (SDIO_BLOCK_SIZE - 1)) {
		size &= SDIO_BLOCK_SIZE;
		size += SDIO_BLOCK_SIZE;
	}

	buf->begin = krealloc(buf->begin, size, GFP_KERNEL | GFP_DMA);
	if (buf->begin) {
		buf->data = &buf->begin[pos];
		buf->end = &buf->begin[size];
		return 0;
	} else {
		buf->end = buf->data = buf->begin;
		return -ENOMEM;
	}
}

static struct bes2600_vif
	*wsm_get_interface_for_tx(struct bes2600_common *hw_priv)
{
	struct bes2600_vif *priv = NULL, *i_priv;
	int i = hw_priv->if_id_selected;

	if (is_hardware_cw1250(hw_priv) || 1 /*TODO:COMBO*/) {
		spin_lock(&hw_priv->vif_list_lock);
#if 0
		bes2600_for_each_vif(hw_priv, i_priv, i) {
			if (i_priv) {
				priv = i_priv;
				spin_lock(&priv->vif_lock);
				break;
			}
		}
#endif
		i_priv = hw_priv->vif_list[i] ?
			cw12xx_get_vif_from_ieee80211(hw_priv->vif_list[i]) : NULL;
		if (i_priv) {
			priv = i_priv;
			spin_lock(&priv->vif_lock);
		}
		/* TODO:COMBO:
		* Find next interface based on TX bitmap announced by the FW
		* Find next interface based on load balancing */
		spin_unlock(&hw_priv->vif_list_lock);
	} else {
		priv = cw12xx_hwpriv_to_vifpriv(hw_priv, 0);
	}

	return priv;
}

static inline int get_interface_id_scanning(struct bes2600_common *hw_priv)
{
	if (hw_priv->scan.req)
		return hw_priv->scan.if_id;
	else if (hw_priv->scan.direct_probe == 1)
		return hw_priv->scan.if_id;
	else
		return -1;
}
