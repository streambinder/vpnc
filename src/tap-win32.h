/*
 *  This file has been borrowed from the Win32 OpenVPN Tap driver
 *  (common.h is the original file name).
 *
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Originally derived from the CIPE-Win32
 *               project by Damion K. Wilson, with extensive modifications by
 *               James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) 2002-2005 OpenVPN Solutions LLC,
 *  and is released under the GPL version 2 (see below).
 *
 *  SPDX-FileCopyrightText: James Yonan
 *  SPDX-FileCopyrightText: 2002-2005 OpenVPN Solutions LLC
 *  SPDX-FileCopyrightText: 2003 Damion K. Wilson CIPE-Win32 Project
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
*/

/* ===============================================
    This file is included both by OpenVPN and
    the TAP-Win32 driver and contains definitions
    common to both.
   =============================================== */

/* =============
    TAP IOCTLs
   ============= */

#define TAP_CONTROL_CODE(request,method) \
	CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

/* Present in 8.1 */

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)

/* Added in 8.2 */

/* obsoletes TAP_IOCTL_CONFIG_POINT_TO_POINT */
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE (10, METHOD_BUFFERED)

/* =================
    Registry keys
   ================= */

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

/* ======================
    Filesystem prefixes
   ====================== */

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define SYSDEVICEDIR      "\\Device\\"
#define USERDEVICEDIR     "\\DosDevices\\Global\\"
#define TAPSUFFIX         ".tap"

/* =========================================================
    TAP_COMPONENT_ID -- These strings defines the TAP driver
    types -- different component IDs can reside in the system
    simultaneously.
   ========================================================= */

static const char* TAP_COMPONENT_ID[] = { "tap0901", "tap0801", NULL };
