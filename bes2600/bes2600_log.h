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
#ifndef __BES2600_LOG_H__
#define __BES2600_LOG_H__

/* Log Level Control */
#define BES2600_LOG_NONE		0
#define BES2600_LOG_ERROR		1
#define BES2600_LOG_WARN		2
#define BES2600_LOG_INFO		3
#define BES2600_LOG_DBG			4

/* Module Log Level Control */
enum BES2600_DBG {
	BES2600_DBG_DOWNLOAD = 0,
	BES2600_DBG_NIY,
	BES2600_DBG_SBUS,
	BES2600_DBG_INIT,
	BES2600_DBG_TXRX_OPT,
	BES2600_DBG_TXRX,
	BES2600_DBG_QUEUE,
	BES2600_DBG_SPI,
	BES2600_DBG_SDIO,
	BES2600_DBG_USB,
	BES2600_DBG_PM,
	BES2600_DBG_SYS,
	BES2600_DBG_BT,
	BES2600_DBG_ANDROID,
	BES2600_DBG_BH,
	BES2600_DBG_AP,
	BES2600_DBG_STA,
	BES2600_DBG_SCAN,
	BES2600_DBG_ITP,
	BES2600_DBG_TEST_MODE,
	BES2600_DBG_TX_POLICY,
	BES2600_DBG_WSM,
	BES2600_DBG_ROC,
	BES2600_DBG_CHARDEV,
	BES2600_DBG_FACTORY,
	BES2600_DBG_EPTA,
	BES2600_DBG_PWR,
	BES2600_DBG_TXLOOP,

	BES2600_DBG_MAX,
};

int bes2600_get_dbg_lvl(int module);

int bes2600_log_control_open(struct inode *inode, struct file *file);

ssize_t bes2600_log_control_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos);

ssize_t bes2600_log_control_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos);

#define GET_LOG_LVL(module)		bes2600_get_dbg_lvl(module)

#define bes2600_dbg(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)

#define bes2600_dbg_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			printk(KERN_DEBUG __VA_ARGS__);		\
	} while (0)

#define bes2600_dbg_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_DBG)	\
			print_hex_dump(KERN_DEBUG, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)

#define bes2600_info(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)

#define bes2600_info_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			printk(KERN_INFO __VA_ARGS__);		\
	} while (0)

#define bes2600_info_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_INFO)	\
			print_hex_dump(KERN_INFO, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)


#define bes2600_warn(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			printk(KERN_WARNING __VA_ARGS__);	\
	} while (0)

#define bes2600_warn_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			printk(KERN_WARNING __VA_ARGS__);	\
	} while (0)

#define bes2600_warn_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_WARN)	\
			print_hex_dump(KERN_WARNING, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)

#define bes2600_err(module, ...)				\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			printk(KERN_ERR __VA_ARGS__);		\
	} while (0)

#define bes2600_err_with_cond(cond, module, ...)		\
	do {							\
		if ((0 != (cond)) && 				\
		    GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			printk(KERN_ERR __VA_ARGS__);		\
	} while (0)

#define bes2600_err_dump(module, desc, array, len)		\
	do {							\
		if (GET_LOG_LVL(module) >= BES2600_LOG_ERROR)	\
			print_hex_dump(KERN_ERR, 		\
				desc, DUMP_PREFIX_NONE,		\
				16, 1, array, 			\
				len, false);			\
	} while(0)

#define STUB()							\
	do {							\
		bes2600_dbg(BES2600_DBG_NIY,			\
			   "%s: STUB at line %d.\n",		\
			   __func__, __LINE__);			\
	} while (0)

#endif
