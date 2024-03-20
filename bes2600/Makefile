KERN_DIR = /lib/modules/$(shell uname -r)/build
# feature option
BES2600                                 ?= m

CONFIG_BES2600_WLAN_SDIO                ?= y
CONFIG_BES2600_WLAN_SPI                 ?= n
CONFIG_BES2600_WLAN_USB                 ?= n

CONFIG_BES2600_VENDOR_CMD               ?= y
CONFIG_BES2600_TESTMODE                 ?= n

CONFIG_BES2600_WAPI_SUPPORT             ?= n
CONFIG_BES2600_STA_DEBUG                ?= y
CONFIG_BES2600_STATIC_SDD               ?= y
P2P_MULTIVIF                            ?= y
AP_AGGREGATE_FW_FIX                     ?= y
CONFIG_BES2600_BT                       ?= n
WIFI_BT_COEXIST_EPTA_ENABLE             ?= y
WIFI_BT_COEXIST_EPTA_FDD                ?= n
CONFIG_BES2600_WOWLAN                   ?= y
CONFIG_BES2600_LISTEN_INTERVAL          ?= 3
BSS_LOSS_CHECK                          ?= y

CONFIG_BES2600_DEBUGFS                  ?= y
CONFIG_BES2600_ITP                      ?= n

CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES ?= n
CONFIG_BES2600_CALIB_FROM_LINUX         ?= y

CONFIG_BES2600_WIFI_BOOT_ON             ?= y
CONFIG_BES2600_BT_BOOT_ON               ?= n

PLAT_ALLWINNER_T507                     ?= n
PLAT_ALLWINNER_R329                     ?= n
PLAT_ROCKCHIP                           ?= n
PLAT_UBUNTU_VUB300                      ?= n
PLAT_QCOM_QM215                         ?= n
PLAT_CVITEK_182X                        ?= n
PLAT_PINETAB                            ?= y

BES2600_GPIO_WAKEUP_AP                  ?= n
BES2600_WRITE_DPD_TO_FILE               ?= n
BES2600_TX_MORE_RETRY                   ?= n

# bes evb
BES2600_INDEPENDENT_EVB                 ?= n
# wifi module for allwinner made by bes
BES2600_INTEGRATED_MODULE_V1            ?= n
# xiaomi R329 wifi module
BES2600_INTEGRATED_MODULE_V2            ?= n
# sicun QM215 wifi module
BES2600_INTEGRATED_MODULE_V3            ?= n

# 0: use dynamic_ps_timeout value
# other: override dynamic_ps_timeout value
BES2600_FASTPS_IDLE_TIME		?= 8

#1.rock api(fixed macaddr)
#2.read from file(macaddr of customers)
#3.read from file(macaddr template)
#4.random macaddr
GET_MAC_ADDR_METHOD                     ?= 4

ifeq ($(CONFIG_BES2600_DEBUGFS),y)
BES2600_DUMP_FW_DPD_LOG                 ?= n
endif

ifeq ($(CONFIG_BES2600_TESTMODE),y)
CONFIG_BES2600_KEEP_ALIVE               ?= n
ifeq ($(CONFIG_BES2600_KEEP_ALIVE)_$(PLAT_ALLWINNER_R329),y_y)
ccflags-y += -DVENDOR_XM_KEEPALIVE
endif
endif

BES2600_DRV_VERSION := bes2600_0.3.5_2024.0116

ifeq ($(GET_MAC_ADDR_METHOD)_$(PLAT_ROCKCHIP),1_n)
 $(error Parameter setting error, GET_MAC_ADDR_METHOD can only be set to 1 on rockchip platform)
endif

ifeq ($(BES2600_GPIO_WAKEUP_AP)_$(CONFIG_BES2600_WLAN_SDIO),y_n)
 $(error Parameter setting error, BES2600_GPIO_WAKEUP_AP can only be set to y when CONFIG_BES2600_WLAN_SDIO set to y)
endif

ifeq ($(GET_MAC_ADDR_METHOD)_$(PLAT_ALLWINNER_R329),2_y)
PATH_WIFI_MACADDR ?= /data/wifi/wifimac.txt
endif

ifeq ($(CONFIG_BES2600_CALIB_FROM_LINUX),y)
FACTORY_CRC_CHECK                    ?= n
FACTORY_SAVE_MULTI_PATH              ?= y
STANDARD_FACTORY_EFUSE_FLAG          ?= y
ifeq ($(FACTORY_SAVE_MULTI_PATH),y)
FACTORY_PATH                         ?= /data/cfg/bes2600_factory.txt
FACTORY_DEFAULT_PATH                 ?= /lib/firmware/bes2600_factory.txt
else ifneq ($(filter y,$(PLAT_ALLWINNER_R329) $(PLAT_QCOM_QM215)),)
FACTORY_PATH ?= /data/wifi/bes2600_factory.txt
else ifneq ($(filter y,$(PLAT_ALLWINNER_T507) $(PLAT_ROCKCHIP)),)
FACTORY_PATH ?= /vendor/firmware/bes2600_factory.txt
endif
endif

FACTORY_PATH ?= /lib/firmware/bes2600_factory.txt

# basic function
define boolen_flag
$(strip $(if $(findstring $($(1)),$(2)),-D$(1)))
endef

define string_flag
$(strip $(if $($(1)),-D$(1)=\"$($(1))\"))
endef

define value_flag
$(strip $(if $($(1)),-D$(1)=$($(1))))
endef

ccflags-y += -Werror

ifneq ($(filter y,$(PLAT_ALLWINNER_R329) $(PLAT_ALLWINNER_T507)),)
ccflags-y += -DPLAT_ALLWINNER
endif

ifeq ($(CONFIG_BES2600_WLAN_SDIO),y)
FW_DOWNLOAD_BY_SDIO                     ?= y
SDIO_HOST_ADMA_SUPPORT                  ?= y
ccflags-y += -DCONFIG_BES2600_WLAN_BES
ccflags-y += -DBES_SDIO_RXTX_TOGGLE
ccflags-y += -DBES_SDIO_TX_MULTIPLE_ENABLE
ccflags-y += -DBES_SDIO_RX_MULTIPLE_ENABLE
ccflags-y += -DBES_UNIFIED_PM
ccflags-y += -DBES_SDIO_OPTIMIZED_LEN
ccflags-y += -DBES2600_HOST_TIMESTAMP_DEBUG
#specific for xiaomi R329
#ccflags-y += -DBES2600_BOOT_UART_TO_SDIO
endif # CONFIG_BES2600_WLAN_SDIO

ifeq ($(CONFIG_BES2600_WLAN_SPI),y)
FW_DOWNLOAD_BY_UART                     ?= y
ccflags-y += -DCONFIG_BES2600_WLAN_BES
#ccflags-y += -DCONFIG_BES2600_SPI_THROUGHPUT_TEST
#ccflags-y += -DFW_DOWNLOAD_MANULLY
ccflags-y += -DBES_UNIFIED_PM
endif # CONFIG_BES2600_WLAN_SPI

ifeq ($(CONFIG_BES2600_WLAN_USB),y)
FW_DOWNLOAD_BY_USB                     ?= y
ccflags-y += -DCONFIG_BES2600_WLAN_BES
endif # CONFIG_BES2600_WLAN_USB

ifeq ($(FW_DOWNLOAD_BY_UART)_$(PLAT_ALLWINNER_T507),y_y)
BES2600_LOAD_FW_TOOL_PATH   ?= /system/bin/bes_fw_download
BES2600_LOAD_FW_TOOL_DEVICE ?= /dev/ttyS2
endif

ifeq ($(FW_DOWNLOAD_BY_UART)_$(PLAT_QCOM_QM215),y_y)
FW_DOWNLOAD_UART_DAEMON         ?= y
BES2600_LOAD_FW_TOOL_PATH   ?= /system/bin/bes_fw_download
BES2600_LOAD_FW_TOOL_DEVICE ?= /dev/ttyHS0
endif

ifeq ($(BES2600_WRITE_DPD_TO_FILE),y)
BES2600_DPD_PATH ?= /data/cfg/bes2600_dpd.bin
BES2600_DEFAULT_DPD_PATH ?= /lib/firmware/bes2600_dpd.bin
BES2600_DPD_GOLDEN_PATH ?= /data/cfg/bes2600_dpd_golden.bin
endif

ifeq ($(BES2600_DUMP_FW_DPD_LOG),y)
BES2600_DPD_LOG_PATH ?= /data/applog/bes2600_dpd_log.log
endif

# compilation macros setting
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WLAN_SDIO,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WLAN_SPI,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WLAN_USB,y)

ccflags-y += $(call boolen_flag,PLAT_ALLWINNER_R329,y)
ccflags-y += $(call boolen_flag,PLAT_ALLWINNER_T507,y)
ccflags-y += $(call boolen_flag,PLAT_UBUNTU_VUB300,y)
ccflags-y += $(call boolen_flag,PLAT_ROCKCHIP,y)
ccflags-y += $(call boolen_flag,PLAT_QCOM_QM215,y)
ccflags-y += $(call boolen_flag,PLAT_CVITEK_182X,y)
ccflags-y += $(call boolen_flag,PLAT_PINETAB,y)

ccflags-y += $(call boolen_flag,CONFIG_BES2600_VENDOR_CMD,y)

ccflags-y += $(call boolen_flag,CONFIG_BES2600_STATIC_SDD,y)
ccflags-y += $(call boolen_flag,P2P_MULTIVIF,y)
ccflags-y += $(call boolen_flag,AP_AGGREGATE_FW_FIX,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_BT,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WAPI_SUPPORT,y)
ccflags-y += $(call boolen_flag,WIFI_BT_COEXIST_EPTA_ENABLE,y)
ccflags-y += $(call boolen_flag,WIFI_BT_COEXIST_EPTA_FDD,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_DISABLE_BEACON_HINTS,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_NON_POWER_OF_TWO_BLOCKSIZES,y)
ccflags-y += $(call boolen_flag,BES2600_TX_MORE_RETRY,y)

ccflags-y += $(call boolen_flag,CONFIG_BES2600_ITP,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_DEBUGFS,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_BH_DEBUG,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WSM_DEBUG,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WSM_DUMPS,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WSM_DUMPS_SHORT,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_TXRX_DEBUG,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_TX_POLICY_DEBUG,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_STA_DEBUG,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_DUMP_ON_ERROR,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_WOWLAN,y)
ccflags-y += $(call value_flag,CONFIG_BES2600_LISTEN_INTERVAL)
ccflags-y += $(call value_flag,BES2600_FASTPS_IDLE_TIME)
ccflags-y += $(call boolen_flag,BSS_LOSS_CHECK,y)

ccflags-y += $(call string_flag,BES2600_LOAD_FW_TOOL_PATH)
ccflags-y += $(call string_flag,BES2600_LOAD_FW_TOOL_DEVICE)
ccflags-y += $(call string_flag,BES2600_DRV_VERSION)
ccflags-y += $(call string_flag,BES2600_DPD_PATH)
ccflags-y += $(call string_flag,BES2600_DEFAULT_DPD_PATH)
ccflags-y += $(call string_flag,BES2600_DPD_GOLDEN_PATH)
ccflags-y += $(call boolen_flag,FW_DOWNLOAD_UART_DAEMON,y)

ccflags-y += $(call boolen_flag,BES2600_INDEPENDENT_EVB,y)
ccflags-y += $(call boolen_flag,BES2600_INTEGRATED_MODULE_V1,y)
ccflags-y += $(call boolen_flag,BES2600_INTEGRATED_MODULE_V2,y)
ccflags-y += $(call boolen_flag,BES2600_INTEGRATED_MODULE_V3,y)
ccflags-y += $(call boolen_flag,FW_DOWNLOAD_BY_SDIO,y)
ccflags-y += $(call boolen_flag,SDIO_HOST_ADMA_SUPPORT,y)
ccflags-y += $(call boolen_flag,FW_DOWNLOAD_BY_UART,y)
ccflags-y += $(call boolen_flag,FW_DOWNLOAD_BY_USB,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_TESTMODE,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_KEEP_ALIVE,y)

ccflags-y += $(call boolen_flag,CONFIG_BES2600_WIFI_BOOT_ON,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_BT_BOOT_ON,y)
ccflags-y += $(call boolen_flag,CONFIG_BES2600_CALIB_FROM_LINUX,y)

ccflags-y += $(call value_flag,GET_MAC_ADDR_METHOD)
ccflags-y += $(call string_flag,PATH_WIFI_MACADDR)
ccflags-y += $(call string_flag,FACTORY_PATH)
ccflags-y += $(call string_flag,FACTORY_DEFAULT_PATH)
ccflags-y += $(call boolen_flag,FACTORY_SAVE_MULTI_PATH,y)
ccflags-y += $(call boolen_flag,FACTORY_CRC_CHECK,y)

ccflags-y += $(call boolen_flag,BES2600_GPIO_WAKEUP_AP,y)
ccflags-y += $(call boolen_flag,BES2600_WRITE_DPD_TO_FILE,y)

ccflags-y += $(call boolen_flag,BES2600_DUMP_FW_DPD_LOG,y)
ccflags-y += $(call string_flag,BES2600_DPD_LOG_PATH)

ccflags-y += $(call boolen_flag,STANDARD_FACTORY_EFUSE_FLAG,y)

# internal feature options
ccflags-y += -DAP_HT_CAP_UPDATE
ccflags-y += -DBES2600_RX_IN_BH
ccflags-y += -DDCW1260_DETECTION_LOGIC

# sdd options
ccflags-y += -DTEST_11B=0
ccflags-y += -DDPD_CALI=0
ccflags-y += -DDPD_CALI=0
ccflags-y += -DALI_CONFG=0
ccflags-y += -DCHIP_WIFI_ROM_VER=1
ccflags-y += -DWIFI_OUT_FEM=0
ccflags-y += -DRF_TX_CONTROL_IO=16

# stbc rx option
ccflags-y += -DSTBC_RX_24G=0
ccflags-y += -DSTBC_RX_5G=0

#ccflags-y += -DP2P_STA_COEX
#ccflags-y += -DCUSTOM_FEATURE
#ccflags-y += -DMCAST_FWDING
#ccflags-y += -DAP_AGGREGATE_FW_FIX
# Extra IE for probe response from upper layer is needed in P2P GO
# For offloading probe response to FW, the extra IE must be included
# in the probe response template
#ccflags-y += -DPROBE_RESP_EXTRA_IE
ccflags-y += -DIPV6_FILTERING

# basic files for building module
bes2600-y := \
	fwio.o \
	txrx.o \
	main.o \
	queue.o \
	hwio.o \
	bh.o \
	wsm.o \
	sta.o \
	ap.o \
	scan.o \
	txrx_opt.o \
	bes_chardev.o \
	tx_loop.o \
	bes2600_log.o

# compilation files select
bes2600-$(CONFIG_BES2600_DEBUGFS)       += debug.o
bes2600-$(CONFIG_BES2600_ITP)           += itp.o
bes2600-$(CONFIG_PM)                    += pm.o
bes2600-$(CONFIG_BES2600_BT)            += bes2600_btusb.o
bes2600-$(CONFIG_BES2600_TESTMODE)      += wifi_testmode_cmd.o
bes2600-$(CONFIG_BES2600_WLAN_SDIO)     += bes2600_sdio.o
bes2600-$(CONFIG_BES2600_WLAN_SPI)      += bes2600_spi.o
bes2600-$(CONFIG_BES2600_WLAN_USB)      += bes2600_usb.o
bes2600-$(CONFIG_BES2600_VENDOR_CMD)    += bes2600_cfgvendor.o

bes2600-$(FW_DOWNLOAD_BY_SDIO)          += bes_fw.o bes_fw_common.o
bes2600-$(FW_DOWNLOAD_BY_UART)          += bes_fw.o bes_fw_common.o
bes2600-$(FW_DOWNLOAD_BY_USB)           += bes_fw_usb.o bes_fw_common.o
bes2600-$(WIFI_BT_COEXIST_EPTA_ENABLE)  += epta_coex.o epta_request.o
bes2600-$(CONFIG_BES2600_WOWLAN)        += bes_pwr.o

ifneq ($(CONFIG_BES2600_CALIB_FROM_LINUX)_$(PLAT_ALLWINNER_R329),n_n)
bes2600-y += bes2600_factory.o
endif

obj-$(BES2600) += bes2600.o

all: modules

modules clean:
	$(MAKE) -C $(KERN_DIR) M=$(shell pwd) $@
