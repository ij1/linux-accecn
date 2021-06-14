#ifndef _TCP_PACED_CHIRPING_PARAM_H
#define _TCP_PACED_CHIRPING_PARAM_H

#include <linux/module.h>

#if IS_ENABLED(CONFIG_PACED_CHIRPING)

/* Paced Chirping parameters */
static unsigned int paced_chirping_enabled __read_mostly = 0;
module_param(paced_chirping_enabled, uint, 0644);
MODULE_PARM_DESC(paced_chirping_enabled, "Enable paced chirping (Default: 0)");
#endif

#endif
