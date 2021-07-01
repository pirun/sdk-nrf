/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef SLM_STATS_
#define SLM_STATS_

/**@file slm_stats.h
 *
 * @brief functions to collect SLM statistics
 * @{
 */

/**
 * @brief Initialize SLM stats collector.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_stats_init(void);

/**
 * @brief Uninitialize SLM stats collector.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_stats_uninit(void);

/**
 * @brief read network and registration stats from modem
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_stats_read(void);

#if defined(CONFIG_SLM_DIAG)
/**
 * @brief get network and registration stats
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int slm_stats_get_nw_reg_status(void);
#endif


/** @} */

#endif /* SLM_STATS_ */
