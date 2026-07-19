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

#define IDC_TEXT_EDIT		1301
#define IDC_TEXT_ENC_LABEL	1302
#define IDC_TEXT_ENCODING	1303
#define IDC_TEXT_WRAP		1304
#define IDC_TEXT_LINENUM	1305
#define IDC_TEXT_FONT		1306
#define IDC_TEXT_INFO		1307

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

#define IDC_ABOUT_ICON		1401
#define IDC_ABOUT_NAME		1402
#define IDC_ABOUT_CREDITS_LABEL	1403
#define IDC_ABOUT_CREDITS	1404

#define IDC_SUPPORT_TEXT	1501

#define IDC_DOKAN_INFO		1601
#define IDC_DOKAN_LETTER_LABEL	1602
#define IDC_DOKAN_LETTER	1603
#define IDC_DOKAN_EXPLORER	1604

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
#define IDS_SUPPORT_IOFILTER	81
#define IDS_DOKAN_INSTALL	82
#define IDS_DOKAN_INSTALLING	83
#define IDS_DOKAN_INSTALL_OK	84
#define IDS_FMT_DOKAN_INSTALL_FAIL	85
#define IDS_DOKAN_LETTER	86
#define IDS_DOKAN_OPEN_EXPLORER	87

#endif /* ! FSROVER_RESOURCE_H */
