/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* String IDs shared by FsRover.rc and main.cpp.  Every user-visible
   string lives in the stringtable (en-US, zh-CN, zh-TW, ja-JP); the
   IDS_FMT_* entries are printf format strings and must keep the same
   specifiers in the same order in every language.  */

#ifndef FSROVER_RESOURCE_H
#define FSROVER_RESOURCE_H	1

#define IDI_APP			1

/* Embedded Dokan runtime for the build architecture: user-mode library
   and kernel driver.
   Only the matching architecture is bundled.
   See FsRover.rc and dokanfs.cpp.  */
#define IDR_DOKAN_DLL		210
#define IDR_DOKAN_SYS		211

/* Bundled help page (FsRover\help.md), UTF-8 markdown shown by the
   markdown viewer.  See mdview.cpp: a help.md next to the executable
   overrides it.  */
#define IDR_HELP_MD		212

#define IDC_STATIC		-1

/* File properties dialog  */
#define IDD_PROPS		101

/* Hex viewer: offset navigation plus one virtual list view, resizable.  */
#define IDD_HEX			102

/* Cryptodisk unlock (LUKS/LUKS2): passphrase or key file.  */
#define IDD_CRYPTO		103

/* Text viewer: encoding/wrap/line-number/font bar + RichEdit body.  */
#define IDD_TEXT		104

/* Image viewer: empty template, the client area is drawn with D2D.  */
#define IDD_IMAGE		105

/* About box: logo, version/copyright, third-party credits.  */
#define IDD_ABOUT		106

/* Supported features: one read-only edit filled at runtime.  */
#define IDD_SUPPORT		107

/* Dokan mount options: drive-letter picker + open-in-Explorer switch.  */
#define IDD_DOKANMOUNT		108

/* Disk/partition properties: buttons only, the sheet itself is painted.  */
#define IDD_DISKPROPS		109

/* Markdown preview: one read-only RichEdit filling the client area.  */
#define IDD_MD			110

/* VeraCrypt/TrueCrypt unlock: passphrase plus the parameters such a
   volume does not store (PIM, PRF, TrueCrypt mode, hidden/backup header).  */
#define IDD_VERACRYPT		111

/* Plain dm-crypt mount: cipher spec, hash, key size, sector size, secret.  */
#define IDD_PLAINMOUNT		112

#define IDC_TEXT_EDIT		1301
#define IDC_TEXT_ENC_LABEL	1302
#define IDC_TEXT_ENCODING	1303
#define IDC_TEXT_WRAP		1304
#define IDC_TEXT_LINENUM	1305
#define IDC_TEXT_FONT		1306
#define IDC_TEXT_INFO		1307

#define IDC_MD_EDIT		1801

#define IDC_HEX_LIST		1101
#define IDC_HEX_OFFSET_LABEL	1102
#define IDC_HEX_OFFSET_EDIT	1103
#define IDC_HEX_GO		1104
#define IDC_HEX_PREV		1105
#define IDC_HEX_NEXT		1106

#define IDC_CRYPTO_INFO		1201
#define IDC_CRYPTO_PASS		1202
#define IDC_CRYPTO_USEKEYFILE	1203
#define IDC_CRYPTO_KEYFILE	1204
#define IDC_CRYPTO_BROWSE	1205
#define IDC_CRYPTO_PROGRESS	1206

#define IDC_VC_INFO		1221
#define IDC_VC_PASS		1222
#define IDC_VC_KEYFILES		1223
#define IDC_VC_BROWSE		1224
#define IDC_VC_CLEARKEYS	1225
#define IDC_VC_PIM		1226
#define IDC_VC_PRF		1227
#define IDC_VC_TRUECRYPT	1228
#define IDC_VC_HIDDEN		1229
#define IDC_VC_BACKUP		1230
#define IDC_VC_PROGRESS		1231

#define IDC_PM_INFO		1241
#define IDC_PM_CIPHER		1242
#define IDC_PM_HASH		1243
#define IDC_PM_KEYBITS		1244
#define IDC_PM_SECTOR		1245
#define IDC_PM_PASS		1246
#define IDC_PM_USEKEYFILE	1247
#define IDC_PM_KEYFILE		1248
#define IDC_PM_BROWSE		1249
#define IDC_PM_KEYOFFSET	1250
#define IDC_PM_OFFSET		1251
#define IDC_PM_SKIP		1252

#define IDC_ABOUT_ICON		1401
#define IDC_ABOUT_NAME		1402
#define IDC_ABOUT_CREDITS_LABEL	1403
#define IDC_ABOUT_CREDITS	1404
#define IDC_ABOUT_URL		1405

#define IDC_SUPPORT_TEXT	1501

#define IDC_DOKAN_INFO		1601
#define IDC_DOKAN_LETTER_LABEL	1602
#define IDC_DOKAN_LETTER	1603
#define IDC_DOKAN_EXPLORER	1604

#define IDC_DISKPROPS_COPY	1702

#define IDC_PROPS_TYPE		1001
#define IDC_PROPS_MD5		1002
#define IDC_PROPS_SHA1		1003
#define IDC_PROPS_CRC32		1004
#define IDC_PROPS_CRC64		1005
#define IDC_PROPS_SHA256	1006
#define IDC_PROPS_SHA512	1007
#define IDC_PROPS_CALC		1008
#define IDC_PROPS_COPY		1009
#define IDC_PROPS_PROGRESS	1010
#define IDC_PROPS_STATUS	1011
#define IDC_PROPS_RESULT	1012
#define IDC_PROPS_INODE		1013

#define IDS_APP_TITLE		1
#define IDS_BTN_REFRESH		2
#define IDS_BTN_EXTRACT		3
#define IDS_BTN_UP		4
#define IDS_BTN_CANCEL		5
#define IDS_COL_NAME		6
#define IDS_COL_SIZE		7
#define IDS_COL_MODIFIED	8
#define IDS_MENU_EXTRACT	9
#define IDS_MENU_MOUNT		10
#define IDS_MENU_UNMOUNT	11
#define IDS_STATUS_STARTING	12
#define IDS_STATUS_LISTING	13
#define IDS_STATUS_ENUM		14
#define IDS_STATUS_EXTRACTING	15
#define IDS_STATUS_CANCELLING	16
#define IDS_STATUS_NOTHING	17
#define IDS_STATUS_MOUNTING	18
#define IDS_STATUS_UNMOUNTING	19
#define IDS_FMT_DEVICES		20
#define IDS_FMT_ITEMS		21
#define IDS_FMT_EXTRACT_DONE	22
#define IDS_FMT_EXTRACT_PROG	23
#define IDS_FMT_MOUNTED		24
#define IDS_FMT_UNMOUNTED	25
#define IDS_PICK_FOLDER		26
#define IDS_MENU_DOKAN_MOUNT	27
#define IDS_MENU_DOKAN_UNMOUNT	28
#define IDS_FMT_DOKAN_MOUNTED	29
#define IDS_FMT_TRAY_UNMOUNT	30
#define IDS_ASK_UNMOUNT_ALL	31
#define IDS_TRAY_OPEN		32
#define IDS_TRAY_EXIT		33
#define IDS_MENU_PROPS		34
#define IDS_PROPS_CALCULATING	35
#define IDS_PROPS_COMPLETE	36
#define IDS_PROPS_SELECT_ONE	37
#define IDS_MENU_HEX		38
#define IDS_HEX_TITLE		39
#define IDS_HEX_OFFSET		40
#define IDS_HEX_TEXT		41
#define IDS_SIZE_SYMLINK	42
#define IDS_FMT_CRYPTO_TITLE	43
#define IDS_CRYPTO_BADKEY	44
#define IDS_CRYPTO_KEYFILE	45
#define IDS_MENU_COPY_NAME	46
#define IDS_MENU_COPY_PATH	47
#define IDS_HEX_GO		48
#define IDS_MENU_MOUNT_DECOMP	49
#define IDS_MENU_TEXT		50
#define IDS_TEXT_TITLE		51
#define IDS_TEXT_ENCODING	52
#define IDS_TEXT_WRAP		53
#define IDS_TEXT_LINENUM	54
#define IDS_TEXT_FONT		55
#define IDS_TEXT_AUTO		56
#define IDS_TEXT_LOADING	57
#define IDS_FMT_TEXT_INFO	58
#define IDS_FMT_TEXT_TRUNC	59
#define IDS_ASK_TEXT_BIG	60
#define IDS_ASK_TEXT_BIN	61
#define IDS_MENU_IMAGE		62
#define IDS_IMAGE_TITLE		63
#define IDS_IMAGE_BAD		64
#define IDS_IMAGE_TOOBIG	65
#define IDS_IMAGE_NO_D2D	66
#define IDS_MENU_FILE		67
#define IDS_MENU_SELECTION	68
#define IDS_MENU_DOKAN		69
#define IDS_MENU_HELP		70
#define IDS_MENU_SEL_ALL	71
#define IDS_MENU_SEL_INVERT	72
#define IDS_DOKAN_NONE		73
#define IDS_DOKAN_UNAVAILABLE	74
#define IDS_MENU_SUPPORT	75
#define IDS_MENU_ABOUT		76
#define IDS_ABOUT_CREDITS	77
#define IDS_SUPPORT_FS		78
#define IDS_SUPPORT_PARTMAP	79
#define IDS_SUPPORT_DISKFILTER	80
#define IDS_SUPPORT_CRYPTODISK	81
#define IDS_SUPPORT_IOFILTER	82
#define IDS_DOKAN_INSTALL	83
#define IDS_DOKAN_INSTALLING	84
#define IDS_DOKAN_INSTALL_OK	85
#define IDS_FMT_DOKAN_INSTALL_FAIL	86
#define IDS_DOKAN_LETTER	87
#define IDS_DOKAN_OPEN_EXPLORER	88
#define IDS_DP_DEVICE		89
#define IDS_DP_FS		90
#define IDS_DP_UUID		91
#define IDS_DP_LABEL		92
#define IDS_DP_SIZE		93
#define IDS_DP_LBA		94
#define IDS_DP_SECTOR		95
#define IDS_DP_PARENT_FILE	96
#define IDS_DP_PARENTS		97
#define IDS_DP_UNKNOWN		98
#define IDS_DP_COPY		99
#define IDS_DP_PARENT_DEV	100
#define IDS_FMT_EXTRACT_LINKS	101
#define IDS_MENU_TIMESTAMPS	102
#define IDS_BTN_BACK		103
#define IDS_BTN_FWD		104
#define IDS_MENU_SHORTCUTS	105
#define IDS_KEY_LIST		106
#define IDS_DP_TYPE		107
#define IDS_DP_COLON		108
#define IDS_DP_FREE		109
#define IDS_DP_T_DISK		110
#define IDS_DP_T_PART		111
#define IDS_DP_T_IMAGE		112
#define IDS_DP_T_VOLUME		113
#define IDS_DP_T_CRYPTO		114
#define IDS_DP_T_PSEUDO		115
#define IDS_MENU_EXPORT		116
#define IDS_PICK_IMAGE		117
#define IDS_FILTER_IMAGE	118
#define IDS_STATUS_EXPORTING	119
#define IDS_FMT_EXPORT_PROG	120
#define IDS_FMT_EXPORT_DONE	121
#define IDS_MENU_OPEN_IMAGE	122
#define IDS_MENU_OPEN_IMAGE_DECOMP	123
#define IDS_PICK_OPEN_IMAGE	124
#define IDS_FILTER_OPEN_IMAGE	125
#define IDS_FILTER_ALL		126
#define IDS_MENU_RUNAS		127
#define IDS_ELEVATE_FAILED	128
#define IDS_DOKAN_NEED_ADMIN	129
#define IDS_DOKAN_WOW64		130
#define IDS_MENU_MARKDOWN	131
#define IDS_MD_TITLE		132
#define IDS_MD_ASK_LINK		133
#define IDS_FMT_MD_TRUNC	134
#define IDS_CMDLINE_USAGE	135
#define IDS_FMT_CMDLINE_ARG	136
#define IDS_MENU_HELPDOC	137
#define IDS_MENU_VERACRYPT	138
#define IDS_FMT_VC_TITLE	139
#define IDS_VC_BADKEY		140
#define IDS_VC_KEYFILES		141
#define IDS_VC_PRF_AUTO		142
#define IDS_VC_BADPIM		143
#define IDS_MENU_PLAINMOUNT	150
#define IDS_FMT_PM_TITLE	151
#define IDS_PM_FAILED		152
#define IDS_PM_KEYFILE		153
#define IDS_PM_BADPARAM		154
#define IDS_PM_HASH_NONE	155
#define IDS_PROPS_NO_INODE	144

#endif /* ! FSROVER_RESOURCE_H */
