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
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "bes2600_log.h"
#include "bes2600.h"

struct bes2600_dbg_info {
	int dbg_lvl;
	char *module_name;
};

struct bes2600_dbg_info bes2600_dbg_tbl[BES2600_DBG_MAX] = {
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "download"},       /* BES2600_DBG_DOWNLOAD */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "niy"},            /* BES2600_DBG_NIY */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "sbus"},           /* BES2600_DBG_SBUS */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "init"},           /* BES2600_DBG_INIT */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "txrx_opt"},       /* BES2600_DBG_TXRX_OPT */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "txrx"},           /* BES2600_DBG_TXRX */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "queue"},          /* BES2600_DBG_QUEUE */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "spi"},            /* BES2600_DBG_SPI */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "sdio"},           /* BES2600_DBG_SDIO */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "usb"},            /* BES2600_DBG_USB */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "pm"},             /* BES2600_DBG_PM */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "sys"},            /* BES2600_DBG_SYS */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "bt"},             /* BES2600_DBG_BT */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "android"},        /* BES2600_DBG_ANDROID */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "bh"},             /* BES2600_DBG_BH */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "ap"},             /* BES2600_DBG_AP */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "sta"},            /* BES2600_DBG_STA */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "scan"},           /* BES2600_DBG_SCAN */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "itp"},            /* BES2600_DBG_ITP */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "test_mode"},      /* BES2600_DBG_TEST_MODE */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "tx_policy"},      /* BES2600_DBG_TX_POLICY */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "wsm"},            /* BES2600_DBG_WSM */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "roc"},            /* BES2600_DBG_ROC */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "chardev"},        /* BES2600_DBG_CHARDEV */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "factory"},        /* BES2600_DBG_FACTORY */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "epta"},           /* BES2600_DBG_EPTA */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "bes_pwr"},        /* BES2600_DBG_PWR */
	{.dbg_lvl = BES2600_LOG_INFO, .module_name = "tx_loop"},        /* BES2600_DBG_TXLOOP */
};

int bes2600_get_dbg_lvl(int module)
{
	if(module >= ARRAY_SIZE(bes2600_dbg_tbl))
		return BES2600_LOG_NONE;

	return bes2600_dbg_tbl[module].dbg_lvl;
}

int bes2600_log_control_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

ssize_t bes2600_log_control_write(struct file *file,const char __user *user_buf, size_t count, loff_t *ppos)
{
	u32 i;
	char *buf = NULL;
	char *module, *level;
	unsigned long log_level;
	char *str_none = "NONE";
	char *str_err = "ERR";
	char *str_warn = "WARN";
	char *str_info = "INFO";
	char *str_dbg = "DBG";

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;
	buf[count] = '\0';

	module = strstr(buf, "module:");
	level = strstr(buf, "level:");
	if (module == NULL || level == NULL) {
		bes2600_err(BES2600_DBG_CHARDEV, "module or level error. %s\n", buf);
		goto out;
	}
	module += 7;
	level += 6;
	if (strncasecmp(str_none, level, strlen(str_none)) == 0)
		log_level = BES2600_LOG_NONE;
	else if(strncasecmp(str_err, level, strlen(str_err)) == 0)
		log_level = BES2600_LOG_ERROR;
	else if(strncasecmp(str_warn, level, strlen(str_warn)) == 0)
		log_level = BES2600_LOG_WARN;
	else if(strncasecmp(str_info, level, strlen(str_info)) == 0)
		log_level = BES2600_LOG_INFO;
	else if(strncasecmp(str_dbg, level, strlen(str_dbg)) == 0)
		log_level = BES2600_LOG_DBG;
	else {
		bes2600_err(BES2600_DBG_CHARDEV, "module level error. %s\n", __func__);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(bes2600_dbg_tbl); ++i) {
		if (strncasecmp(bes2600_dbg_tbl[i].module_name, module, strlen(bes2600_dbg_tbl[i].module_name)) == 0) {
			bes2600_dbg_tbl[i].dbg_lvl = log_level;
			break;
		}
	}

out:
	kfree(buf);
	return count;
}

ssize_t bes2600_log_control_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	char *buf = NULL;
	int i,ret;
	int used_len = 0;
	char str[10];

	if (!count)
		return -EINVAL;
	buf = kmalloc(1024, GFP_KERNEL);
	if(!buf) {
		bes2600_err(BES2600_DBG_CHARDEV, "kmalloc error. %s\n", __func__);
		return -ENOMEM;
	}
	for (i = 0; i < ARRAY_SIZE(bes2600_dbg_tbl); ++i) {
		if(bes2600_dbg_tbl[i].dbg_lvl == BES2600_LOG_NONE) 
			strcpy(str, "NONE");
		else if (bes2600_dbg_tbl[i].dbg_lvl == BES2600_LOG_ERROR)
			strcpy(str, "ERR");
		else if (bes2600_dbg_tbl[i].dbg_lvl == BES2600_LOG_WARN)
			strcpy(str, "WARN");
		else if (bes2600_dbg_tbl[i].dbg_lvl == BES2600_LOG_INFO)
			strcpy(str, "INFO");
		else if (bes2600_dbg_tbl[i].dbg_lvl == BES2600_LOG_DBG)
			strcpy(str, "DBG");
		else
			return -ENOMEM;
		used_len += snprintf(buf + used_len, (1024 - used_len), "%-16s%s\n", bes2600_dbg_tbl[i].module_name, str);
	}
	ret = simple_read_from_buffer(user_buf, count, ppos, buf, used_len);
	kfree(buf);
	return ret;
}
