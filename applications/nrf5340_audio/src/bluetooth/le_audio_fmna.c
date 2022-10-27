/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-4-Clause
 */

#include <zephyr.h>
#include <sys/printk.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>

#include <fmna.h>

#include <settings/settings.h>

#include "button_assignments.h"

#define HS_BT_ID BT_ID_DEFAULT
#define FMNA_BT_ID      1
#define BT_ID_COUNT     2

BUILD_ASSERT(BT_ID_COUNT == CONFIG_BT_ID_MAX, "BT identities misconfigured");

#define FMNA_PEER_SOUND_DURATION K_SECONDS(5)

#define FMNA_SOUND_LED DK_LED1

#define FMNA_ADV_RESUME_BUTTON             BUTTON_MUTE
#define FMNA_FACTORY_SETTINGS_RESET_BUTTON BUTTON_TEST_TONE

#define FMNA_DEVICE_NAME_SUFFIX " - Find My"

#define HS_PAIRING_BUTTON      BUTTON_TEST_TONE

#define HS_DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define HS_FMNA_DEVICE_NAME \
	HS_DEVICE_NAME FMNA_DEVICE_NAME_SUFFIX

#define BATTERY_LEVEL_CHANGE_BUTTON   BUTTON_TEST_TONE

bool fmna_location_available;
bool fmna_pairing_mode_exit;

static bool hs_pairing_mode;
static uint8_t battery_level = 100;
static struct bt_le_ext_adv *hs_adv_set;

static const struct bt_data hs_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL,
		      BT_UUID_16_ENCODE(BT_UUID_HRS_VAL),
		      BT_UUID_16_ENCODE(BT_UUID_BAS_VAL),
		      BT_UUID_16_ENCODE(BT_UUID_DIS_VAL))
};

static void fmna_sound_timeout_work_handle(struct k_work *item);

static K_WORK_DELAYABLE_DEFINE(fmna_sound_timeout_work, fmna_sound_timeout_work_handle);

static void hs_device_name_set(bool force)
{
	static bool suffix_present = false;
	bool use_suffix;

	/* Suffix should be present when the HR sensor is in the pairing
	 * mode and when the Find My Network is enabled.
	 */
	use_suffix = (hs_pairing_mode && fmna_location_available);

	if ((force) || (use_suffix != suffix_present)) {
		int err;
		const char* device_name = use_suffix ?
			HS_FMNA_DEVICE_NAME : HS_DEVICE_NAME;

		err = bt_set_name(device_name);
		if (err) {
			printk("bt_set_name failed (err %d)\n", err);
			return;
		} else {
			printk("HR Sensor device name set to: %s\n", device_name);
		}

		suffix_present = use_suffix;

		if (hs_adv_set) {
			err = bt_le_ext_adv_set_data(
				hs_adv_set, hs_ad,
				ARRAY_SIZE(hs_ad), NULL, 0);
			if (err) {
				printk("bt_le_ext_adv_set_data failed (err %d)\n", err);
				return;
			}
		}
	}
}

static void fmna_sound_stop_indicate(void)
{
	printk("Stopping the sound from being played\n");

	//dk_set_led(FMNA_SOUND_LED, 0);
}

static void fmna_sound_timeout_work_handle(struct k_work *item)
{
	int err;

	err = fmna_sound_completed_indicate();
	if (err) {
		printk("fmna_sound_completed_indicate failed (err %d)\n", err);
		return;
	}

	printk("Sound playing timed out\n");

	fmna_sound_stop_indicate();
}

static void fmna_sound_start(enum fmna_sound_trigger sound_trigger)
{
	k_work_reschedule(&fmna_sound_timeout_work, FMNA_PEER_SOUND_DURATION);

	//dk_set_led(FMNA_SOUND_LED, 1);

	printk("Starting to play sound...\n");
}

static void fmna_sound_stop(void)
{
	printk("Received a request from FMN to stop playing sound\n");

	k_work_cancel_delayable(&fmna_sound_timeout_work);

	fmna_sound_stop_indicate();
}

static const struct fmna_sound_cb fmna_sound_callbacks = {
	.sound_start = fmna_sound_start,
	.sound_stop = fmna_sound_stop,
};

static void fmna_location_availability_changed(bool available)
{
	printk("Find My location %s\n", available ? "enabled" : "disabled");

	fmna_location_available = available;

	hs_device_name_set(false);
}

static void fmna_pairing_mode_exited(void)
{
	printk("Exited the FMN pairing mode\n");

	fmna_pairing_mode_exit = true;
}

static const struct fmna_enable_cb fmna_enable_callbacks = {
	.location_availability_changed = fmna_location_availability_changed,
	.pairing_mode_exited = fmna_pairing_mode_exited,
};

static int fmna_id_create(uint8_t id)
{
	int ret;
	bt_addr_le_t addrs[CONFIG_BT_ID_MAX];
	size_t count = ARRAY_SIZE(addrs);

	bt_id_get(addrs, &count);
	if (id < count) {
		return 0;
	}

	do {
		ret = bt_id_create(NULL, NULL);
		if (ret < 0) {
			return ret;
		}
	} while (ret != id);

	return 0;
}
static bool factory_settings_restore_check(void)
{
	bool pressed;

	(void)button_pressed(FMNA_FACTORY_SETTINGS_RESET_BUTTON, &pressed);

	return (pressed);
}

static int fmna_initialize(void)
{
	int err;
	struct fmna_enable_param enable_param = {0};

	err = fmna_sound_cb_register(&fmna_sound_callbacks);
	if (err) {
		printk("fmna_sound_cb_register failed (err %d)\n", err);
		return err;
	}

	err = fmna_id_create(FMNA_BT_ID);
	if (err) {
		printk("fmna_id_create failed (err %d)\n", err);
		return err;
	}

	enable_param.bt_id = FMNA_BT_ID;
	enable_param.init_battery_level = battery_level;
	enable_param.use_default_factory_settings = factory_settings_restore_check();

	err = fmna_enable(&enable_param, &fmna_enable_callbacks);
	if (err) {
		printk("fmna_enable failed (err %d)\n", err);
		return err;
	}

	return 0;
}


static void identities_print(void)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	bt_addr_le_t addrs[BT_ID_COUNT];
	size_t count = ARRAY_SIZE(addrs);

	bt_id_get(addrs, &count);

	if (count != BT_ID_COUNT) {
		printk("Wrong number of identities\n");
		k_oops();
	}

	bt_addr_le_to_str(&addrs[HS_BT_ID], addr_str, sizeof(addr_str));
	printk("HS sensor identity %d: %s\n", HS_BT_ID, addr_str);

	bt_addr_le_to_str(&addrs[FMNA_BT_ID], addr_str, sizeof(addr_str));
	printk("Find My identity %d: %s\n", FMNA_BT_ID, addr_str);
}



void fmna_init(void)
{
	int err;

	printk("Starting the FMN coexistence application\n");


	err = fmna_initialize();
	if (err) {
		printk("FMNA init failed (err %d)\n", err);
		return;
	}

	printk("FMNA initialized\n");

	identities_print();
}
