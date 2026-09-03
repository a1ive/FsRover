// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef FSROVER_BUILD_CONFIG_H
#define FSROVER_BUILD_CONFIG_H	1

/* Shared by C++ and the resource compiler. MSBuild exposes properties
   with the same names; use 0 to omit a feature, or 1 to include it. */
#ifndef FSROVER_EMBED_DOKAN
#define FSROVER_EMBED_DOKAN	1
#endif

/* Controls the in-app elevation command and the S.M.A.R.T. viewer.
   Existing mount backends and physical-disk access are independent. */
#ifndef FSROVER_ENABLE_ADMIN_FEATURES
#define FSROVER_ENABLE_ADMIN_FEATURES	1
#endif

#endif
