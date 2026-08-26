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

#include <grub/charset.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/file.h>
#include <grub/fs.h>
#include <grub/fshelp.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define ADFS_DISCRECORD_OFFSET	0xc00U
#define ADFS_DR_OFFSET		0x1c0U
#define ADFS_DR_SIZE		60U
#define ADFS_DR_SIZE_BITS	(ADFS_DR_SIZE * 8U)
#define ADFS_BOOT_BLOCK_SIZE	512U
#define ADFS_F_DIR_SIZE		2048U
#define ADFS_F_ENTRIES		77U
#define ADFS_F_NAME_LEN		10U
#define ADFS_FPLUS_NAME_LEN	255U
#define ADFS_FPLUS_MAX_SIZE	(4U * 1024U * 1024U)
#define ADFS_ROOT_FRAG		2U

#define ADFS_ATTR_DIRECTORY	(1U << 3)
#define ADFS_FILETYPE_LINKFS	0xfc0U
#define ADFS_BIGDIRSTARTNAME	0x72504253U /* "SBPr" */
#define ADFS_BIGDIRENDNAME	0x6e65766fU /* "oven" */

PRAGMA_BEGIN_PACKED
struct grub_adfs_discrecord
{
	grub_uint8_t log2secsize;
	grub_uint8_t secspertrack;
	grub_uint8_t heads;
	grub_uint8_t density;
	grub_uint8_t idlen;
	grub_uint8_t log2bpmb;
	grub_uint8_t skew;
	grub_uint8_t bootoption;
	grub_uint8_t lowsector;
	grub_uint8_t nzones;
	grub_uint8_t zone_spare[2];
	grub_uint8_t root[4];
	grub_uint8_t disc_size[4];
	grub_uint8_t disc_id[2];
	grub_uint8_t disc_name[10];
	grub_uint8_t disc_type[4];
	grub_uint8_t disc_size_high[4];
	grub_uint8_t sharesize;
	grub_uint8_t big_flag;
	grub_uint8_t nzones_high;
	grub_uint8_t reserved43;
	grub_uint8_t format_version[4];
	grub_uint8_t root_size[4];
	grub_uint8_t unused52[8];
} GRUB_PACKED;
PRAGMA_END_PACKED

struct grub_adfs_data;

struct grub_fshelp_node
{
	struct grub_adfs_data *data;
	grub_uint32_t indaddr;
	grub_uint32_t loadaddr;
	grub_uint32_t execaddr;
	grub_uint32_t size;
	grub_uint32_t attr;
};

struct grub_adfs_data
{
	grub_disk_t disk;
	struct grub_adfs_discrecord dr;
	struct grub_fshelp_node root;
	grub_uint8_t *map;
	grub_uint32_t sector_size;
	grub_uint32_t zone_size;
	grub_uint32_t nzones;
	grub_uint32_t ids_per_zone;
	grub_uint32_t last_zone_endbit;
	grub_int32_t map2blk;
	grub_uint8_t log2sharesize;
};

static grub_dl_t my_mod;

static grub_uint32_t
adfs_get_le (const grub_uint8_t *p, unsigned int len)
{
	grub_uint32_t value = 0;
	unsigned int i;

	for (i = 0; i < len; i++)
		value |= (grub_uint32_t) p[i] << (i * 8);
	return value;
}

static grub_uint64_t
adfs_disc_size (const struct grub_adfs_discrecord *dr)
{
	return ((grub_uint64_t) adfs_get_le (dr->disc_size_high, 4) << 32) | adfs_get_le (dr->disc_size, 4);
}

static grub_err_t
adfs_disk_read (grub_disk_t disk, grub_uint64_t offset, grub_size_t len,
		void *buf)
{
	return grub_disk_read (disk, offset >> GRUB_DISK_SECTOR_BITS,
		(grub_off_t) (offset & (GRUB_DISK_SECTOR_SIZE - 1)), len, buf);
}

static int
adfs_check_boot_block (const grub_uint8_t *block)
{
	unsigned int result = 0;
	unsigned int i;

	for (i = 511; i != 0; i--)
	{
		result = (result & 0xff) + (result >> 8);
		result += block[i - 1];
	}
	return (result & 0xff) == block[511];
}

static int
adfs_check_discrecord (const struct grub_adfs_discrecord *dr)
{
	grub_uint32_t disc_size_high;
	grub_uint32_t format_version;
	grub_uint32_t max_idlen;
	grub_uint32_t nzones;
	grub_uint32_t sector_bits;
	grub_uint32_t zone_spare;
	unsigned int i;

	if (dr->log2secsize < 8 || dr->log2secsize > 10)
		return 0;
	if (dr->idlen < dr->log2secsize + 3)
		return 0;

	disc_size_high = adfs_get_le (dr->disc_size_high, 4);
	if ((disc_size_high >> dr->log2secsize) != 0 || adfs_disc_size (dr) == 0)
		return 0;

	format_version = adfs_get_le (dr->format_version, 4);
	max_idlen = format_version ? 19U : 16U;
	if (dr->idlen > max_idlen || dr->log2bpmb >= 32)
		return 0;

	nzones = dr->nzones | ((grub_uint32_t) dr->nzones_high << 8);
	sector_bits = 8U << dr->log2secsize;
	zone_spare = adfs_get_le (dr->zone_spare, 2);
	if (nzones == 0 || zone_spare < 32 || zone_spare >= sector_bits)
		return 0;

	for (i = 0; i < sizeof (dr->unused52); i++)
		if (dr->unused52[i] != 0)
			return 0;

	return 1;
}

static int
adfs_same_geometry (const struct grub_adfs_discrecord *a, const struct grub_adfs_discrecord *b)
{
	return a->log2secsize == b->log2secsize
		&& a->idlen == b->idlen
		&& a->log2bpmb == b->log2bpmb
		&& (a->sharesize & 0x0f) == (b->sharesize & 0x0f)
		&& a->nzones == b->nzones
		&& a->nzones_high == b->nzones_high
		&& grub_memcmp (a->zone_spare, b->zone_spare, sizeof (a->zone_spare)) == 0
		&& grub_memcmp (a->disc_size, b->disc_size, sizeof (a->disc_size)) == 0
		&& grub_memcmp (a->disc_size_high, b->disc_size_high, sizeof (a->disc_size_high)) == 0;
}

static int
adfs_read_discrecord (grub_disk_t disk, struct grub_adfs_discrecord *dr)
{
	grub_uint8_t block[ADFS_BOOT_BLOCK_SIZE];

	if (!adfs_disk_read (disk, ADFS_DISCRECORD_OFFSET, sizeof (block), block))
	{
		if (adfs_check_boot_block (block))
		{
			grub_memcpy (dr, block + ADFS_DR_OFFSET, sizeof (*dr));
			if (adfs_check_discrecord (dr))
				return 1;
		}
	}
	grub_errno = GRUB_ERR_NONE;

	if (adfs_disk_read (disk, 0, 4 + sizeof (*dr), block))
		return 0;
	grub_memcpy (dr, block + 4, sizeof (*dr));
	if (!adfs_check_discrecord (dr) || dr->nzones_high != 0 || dr->nzones != 1)
		return 0;
	return 1;
}

static grub_uint8_t
adfs_zone_check (const grub_uint8_t *map, grub_uint32_t sector_size)
{
	unsigned int v0 = 0, v1 = 0, v2 = 0, v3 = 0;
	grub_uint32_t i;

	for (i = sector_size - 4; i != 0; i -= 4)
	{
		v0 += map[i] + (v3 >> 8);
		v3 &= 0xff;
		v1 += map[i + 1] + (v0 >> 8);
		v0 &= 0xff;
		v2 += map[i + 2] + (v1 >> 8);
		v1 &= 0xff;
		v3 += map[i + 3] + (v2 >> 8);
		v2 &= 0xff;
	}
	v0 += v3 >> 8;
	v1 += map[1] + (v0 >> 8);
	v2 += map[2] + (v1 >> 8);
	v3 += map[3] + (v2 >> 8);
	return (grub_uint8_t) (v0 ^ v1 ^ v2 ^ v3);
}

static int
adfs_read_map (struct grub_adfs_data *data)
{
	grub_uint64_t disc_bits;
	grub_uint64_t map_addr;
	grub_uint64_t map_blocks;
	grub_uint64_t map_bytes;
	grub_uint64_t preceding;
	grub_uint32_t crosscheck = 0;
	grub_uint32_t zone;

	data->sector_size = 1U << data->dr.log2secsize;
	data->nzones = data->dr.nzones | ((grub_uint32_t) data->dr.nzones_high << 8);
	data->zone_size = data->sector_size * 8 - adfs_get_le (data->dr.zone_spare, 2);
	if (data->zone_size <= ADFS_DR_SIZE_BITS)
		return 0;
	data->map2blk = (grub_int32_t) data->dr.log2bpmb - data->dr.log2secsize;
	data->log2sharesize = data->dr.sharesize & 0x0f;
	data->ids_per_zone = data->zone_size / (data->dr.idlen + 1U);
	if (data->ids_per_zone == 0)
		return 0;

	map_addr = ((grub_uint64_t) (data->nzones >> 1)) * data->zone_size;
	if (data->nzones > 1)
	{
		if (map_addr < ADFS_DR_SIZE_BITS)
			return 0;
		map_addr -= ADFS_DR_SIZE_BITS;
	}
	if (data->map2blk >= 0)
		map_blocks = map_addr << data->map2blk;
	else
		map_blocks = map_addr >> -data->map2blk;

	if (data->nzones > GRUB_SIZE_MAX / data->sector_size)
		return 0;
	map_bytes = (grub_uint64_t) data->nzones * data->sector_size;
	if (map_blocks > adfs_disc_size (&data->dr) / data->sector_size
		|| map_bytes > adfs_disc_size (&data->dr)
		|| map_blocks * data->sector_size > adfs_disc_size (&data->dr) - map_bytes)
		return 0;

	data->map = grub_malloc ((grub_size_t) map_bytes);
	if (!data->map)
		return 0;
	if (adfs_disk_read (data->disk, map_blocks * data->sector_size, (grub_size_t) map_bytes, data->map))
		return 0;

	for (zone = 0; zone < data->nzones; zone++)
	{
		const grub_uint8_t *map = data->map + zone * data->sector_size;
		if (adfs_zone_check (map, data->sector_size) != map[0])
			return 0;
		crosscheck ^= map[3];
	}
	if (crosscheck != 0xff)
		return 0;

	disc_bits = adfs_disc_size (&data->dr) >> data->dr.log2bpmb;
	if (data->nzones == 1)
	{
		if (disc_bits > data->zone_size - ADFS_DR_SIZE_BITS)
			return 0;
		data->last_zone_endbit = 32U + ADFS_DR_SIZE_BITS + (grub_uint32_t) disc_bits;
	}
	else
	{
		preceding = (grub_uint64_t) (data->nzones - 1) * data->zone_size - ADFS_DR_SIZE_BITS;
		if (disc_bits <= preceding || disc_bits - preceding > data->zone_size)
			return 0;
		data->last_zone_endbit = 32U + (grub_uint32_t) (disc_bits - preceding);
	}
	if (data->last_zone_endbit > data->sector_size * 8)
		return 0;
	if (data->nzones == 1 && data->last_zone_endbit <= 32U + ADFS_DR_SIZE_BITS)
		return 0;

	return 1;
}

static grub_uint32_t
adfs_map_bits (const grub_uint8_t *map, grub_uint32_t start, grub_uint32_t count)
{
	grub_uint32_t value = 0;
	grub_uint32_t i;

	for (i = 0; i < count; i++)
		value |= ((map[(start + i) >> 3] >> ((start + i) & 7)) & 1U) << i;
	return value;
}

static grub_uint32_t
adfs_next_set_bit (const grub_uint8_t *map, grub_uint32_t start, grub_uint32_t end)
{
	while (start < end)
	{
		if ((map[start >> 3] >> (start & 7)) & 1U)
			break;
		start++;
	}
	return start;
}

static int
adfs_lookup_zone (const struct grub_adfs_data *data, grub_uint32_t zone,
	grub_uint32_t frag_id, grub_uint64_t *offset, grub_uint32_t *found)
{
	const grub_uint8_t *map = data->map + zone * data->sector_size;
	grub_uint32_t endbit = (zone + 1 == data->nzones) ? data->last_zone_endbit : 32U + data->zone_size;
	grub_uint32_t start = zone ? 32U : 32U + ADFS_DR_SIZE_BITS;
	grub_uint32_t idmask = (1U << data->dr.idlen) - 1U;
	grub_uint32_t freelink;

	freelink = adfs_map_bits (map, 8, data->dr.idlen <= 15 ? data->dr.idlen : 15) & 0x7fff;
	freelink = freelink ? 8U + freelink : 0;

	while (start < endbit)
	{
		grub_uint32_t fragend;
		grub_uint32_t frag;
		grub_uint32_t length;

		if (start + data->dr.idlen >= endbit)
			return 0;
		frag = adfs_map_bits (map, start, data->dr.idlen) & idmask;
		fragend = adfs_next_set_bit (map, start + data->dr.idlen, endbit);
		if (fragend >= endbit)
			return 0;
		length = fragend + 1U - start;

		if (start == freelink)
			freelink += frag & 0x7fff;
		else if (frag == frag_id)
		{
			if (*offset < length)
			{
				*found = start + (grub_uint32_t) *offset;
				return 1;
			}
			*offset -= length;
		}
		start = fragend + 1U;
	}
	return 0;
}

static grub_disk_addr_t
adfs_map_lookup (struct grub_adfs_data *data, grub_uint32_t frag_id, grub_uint64_t offset)
{
	grub_uint64_t mapoff;
	grub_uint32_t start_zone;
	grub_uint32_t pass;

	if (frag_id == ADFS_ROOT_FRAG)
		start_zone = data->nzones >> 1;
	else
		start_zone = frag_id / data->ids_per_zone;
	if (start_zone >= data->nzones)
		goto fail;

	if (data->map2blk >= 0)
		mapoff = offset >> data->map2blk;
	else
		mapoff = offset << -data->map2blk;

	for (pass = 0; pass < data->nzones; pass++)
	{
		grub_uint32_t zone = (start_zone + pass) % data->nzones;
		grub_uint64_t remaining = mapoff;
		grub_uint32_t found;

		if (adfs_lookup_zone (data, zone, frag_id, &remaining, &found))
		{
			grub_uint64_t startblk = (grub_uint64_t) zone * data->zone_size;
			grub_uint64_t bit;
			grub_uint64_t block;
			grub_uint64_t secoff;

			if (zone)
				startblk -= ADFS_DR_SIZE_BITS;
			bit = startblk + found - (zone ? 32U : 32U + ADFS_DR_SIZE_BITS);
			if (data->map2blk >= 0)
				block = bit << data->map2blk;
			else
				block = bit >> -data->map2blk;

			if (data->map2blk >= 0)
				secoff = offset - (mapoff << data->map2blk);
			else
				secoff = offset - (mapoff >> -data->map2blk);
			block += secoff;
			if (block != 0 && block < adfs_disc_size (&data->dr) / data->sector_size)
				return block;
			goto fail;
		}
		mapoff = remaining;
	}

fail:
	grub_error (GRUB_ERR_BAD_FS, "ADFS fragment 0x%x at offset %llu not found", frag_id, (unsigned long long) offset);
	return (grub_disk_addr_t) -1;
}

static grub_disk_addr_t
adfs_block_map (struct grub_adfs_data *data, grub_uint32_t indaddr,
		grub_uint64_t block)
{
	if (indaddr & 0xff)
		block += ((grub_uint64_t) ((indaddr & 0xff) - 1)) << data->log2sharesize;
	return adfs_map_lookup (data, indaddr >> 8, block);
}

static grub_ssize_t
adfs_read_object (struct grub_adfs_data *data, grub_uint32_t indaddr,
	grub_uint64_t pos, grub_size_t len, void *buf,
	grub_disk_read_hook_t read_hook, void *read_hook_data)
{
	grub_uint8_t *out = buf;
	grub_size_t done = 0;

	while (done < len)
	{
		grub_uint64_t cur = pos + done;
		grub_uint64_t fileblock = cur >> data->dr.log2secsize;
		grub_uint32_t blockoff = (grub_uint32_t) cur & (data->sector_size - 1);
		grub_size_t amount = data->sector_size - blockoff;
		grub_disk_addr_t block;

		if (amount > len - done)
			amount = len - done;
		block = adfs_block_map (data, indaddr, fileblock);
		if (block == (grub_disk_addr_t) -1)
			return -1;

		data->disk->read_hook = read_hook;
		data->disk->read_hook_data = read_hook_data;
		if (adfs_disk_read (data->disk, (grub_uint64_t) block * data->sector_size + blockoff, amount, out + done))
		{
			data->disk->read_hook = 0;
			return -1;
		}
		data->disk->read_hook = 0;
		done += amount;
	}
	return (grub_ssize_t) done;
}

static grub_uint32_t
adfs_ror13 (grub_uint32_t value)
{
	return (value >> 13) | (value << 19);
}

static grub_uint8_t
adfs_f_checkbyte (const grub_uint8_t *dir)
{
	grub_uint32_t check = 0;
	grub_uint32_t i = 0;
	grub_uint32_t last = 5;

	for (;;)
	{
		while (i < (last & ~3U))
		{
			check = adfs_get_le (dir + i, 4) ^ adfs_ror13 (check);
			i += 4;
		}
		if (dir[last] == 0)
			break;
		last += 26;
	}
	while (i < last)
		check = dir[i++] ^ adfs_ror13 (check);
	for (i = 2008; i < 2044; i += 4)
		check = adfs_get_le (dir + i, 4) ^ adfs_ror13 (check);
	return (grub_uint8_t) (check ^ (check >> 8) ^ (check >> 16) ^ (check >> 24));
}

static int
adfs_f_validate (const grub_uint8_t *dir)
{
	const grub_uint8_t *tail = dir + 2007;

	if (dir[0] != tail[35] || tail[0] != 0 || tail[1] != 0 || tail[2] != 0)
		return 0;
	if (grub_memcmp (dir + 1, "Nick", 4) != 0 && grub_memcmp (dir + 1, "Hugo", 4) != 0)
		return 0;
	if (grub_memcmp (dir + 1, tail + 36, 4) != 0)
		return 0;
	return adfs_f_checkbyte (dir) == tail[40];
}

static grub_uint32_t
adfs_fplus_entry_offset (const grub_uint8_t *dir, grub_uint32_t pos)
{
	grub_uint32_t name_len = adfs_get_le (dir + 8, 4);
	return 28U + ((name_len + 3U) & ~3U) + pos * 28U;
}

static int
adfs_fplus_validate_header (const grub_uint8_t *dir, grub_uint32_t *size_out)
{
	grub_uint32_t size = adfs_get_le (dir + 12, 4);
	grub_uint32_t dir_name_len = adfs_get_le (dir + 8, 4);
	grub_uint32_t entries = adfs_get_le (dir + 16, 4);
	grub_uint32_t names_size = adfs_get_le (dir + 20, 4);
	grub_uint64_t entries_end;

	if (dir[1] != 0 || dir[2] != 0 || dir[3] != 0
		|| adfs_get_le (dir + 4, 4) != ADFS_BIGDIRSTARTNAME
		|| size == 0 || (size & 2047) != 0 || size > ADFS_FPLUS_MAX_SIZE
		|| dir_name_len > ADFS_FPLUS_NAME_LEN)
		return 0;
	entries_end = (grub_uint64_t) 28 + ((dir_name_len + 3U) & ~3U) + (grub_uint64_t) entries * 28;
	if (entries > ADFS_FPLUS_MAX_SIZE / 28
		|| entries_end > size - 8U
		|| names_size > size - 8U - entries_end)
		return 0;
	*size_out = size;
	return 1;
}

static grub_uint8_t
adfs_fplus_checkbyte (const grub_uint8_t *dir)
{
	grub_uint32_t entries = adfs_get_le (dir + 16, 4);
	grub_uint32_t end = adfs_fplus_entry_offset (dir, entries) + adfs_get_le (dir + 20, 4);
	grub_uint32_t size = adfs_get_le (dir + 12, 4);
	const grub_uint8_t *tail = dir + size - 8;
	grub_uint32_t check = 0;
	grub_uint32_t i;

	for (i = 0; i < end; i += 4)
		check = adfs_ror13 (check) ^ adfs_get_le (dir + i, 4);
	check = adfs_ror13 (check) ^ adfs_get_le (tail, 4);
	check = adfs_ror13 (check) ^ tail[4];
	check = adfs_ror13 (check) ^ tail[5];
	check = adfs_ror13 (check) ^ tail[6];
	return (grub_uint8_t) (check ^ (check >> 8) ^ (check >> 16) ^ (check >> 24));
}

static int
adfs_fplus_validate (const grub_uint8_t *dir, grub_uint32_t size)
{
	const grub_uint8_t *tail = dir + size - 8;

	if (adfs_get_le (tail, 4) != ADFS_BIGDIRENDNAME
		|| tail[4] != dir[0] || tail[5] != 0 || tail[6] != 0)
		return 0;
	return adfs_fplus_checkbyte (dir) == tail[7];
}

static grub_uint32_t
adfs_filetype (grub_uint32_t loadaddr)
{
	if ((loadaddr & 0xfff00000U) != 0xfff00000U)
		return 0xffffffffU;
	return (loadaddr >> 8) & 0xfff;
}

static grub_int64_t
adfs_mtime (const struct grub_fshelp_node *node, int *valid)
{
	grub_uint64_t centiseconds;
	grub_uint64_t seconds;

	if ((node->loadaddr & 0xfff00000U) != 0xfff00000U)
	{
		*valid = 0;
		return 0;
	}
	centiseconds = ((grub_uint64_t) (node->loadaddr & 0xff) << 32) | node->execaddr;
	seconds = centiseconds / 100;
	*valid = 1;
	return seconds < 2208988800ULL ? 0 : (grub_int64_t) (seconds - 2208988800ULL);
}

static int
adfs_emit (struct grub_fshelp_node *dir, const grub_uint8_t *raw_name,
	grub_uint32_t name_len, grub_uint32_t indaddr, grub_uint32_t loadaddr,
	grub_uint32_t execaddr, grub_uint32_t size, grub_uint32_t attr,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_fshelp_node *node;
	grub_uint8_t name[ADFS_FPLUS_NAME_LEN];
	grub_uint8_t utf8[ADFS_FPLUS_NAME_LEN * GRUB_MAX_UTF8_PER_LATIN1 + 1];
	grub_uint32_t dots = 0;
	grub_uint32_t i;
	enum grub_fshelp_filetype type;

	if (name_len == 0 || name_len > sizeof (name))
		return 0;
	for (i = 0; i < name_len; i++)
	{
		name[i] = raw_name[i];
		if (name[i] == '/')
		{
			name[i] = '.';
			dots++;
		}
	}
	if (name_len <= 2 && dots == name_len)
		name[0] = '^';
	*grub_latin1_to_utf8 (utf8, name, name_len) = '\0';

	node = grub_malloc (sizeof (*node));
	if (!node)
		return 1;
	node->data = dir->data;
	node->indaddr = indaddr;
	node->loadaddr = loadaddr;
	node->execaddr = execaddr;
	node->size = size;
	node->attr = attr;

	if (attr & ADFS_ATTR_DIRECTORY)
		type = GRUB_FSHELP_DIR;
	else if (adfs_filetype (loadaddr) == ADFS_FILETYPE_LINKFS)
		type = GRUB_FSHELP_SYMLINK;
	else
		type = GRUB_FSHELP_REG;
	return hook ((char *) utf8, type | GRUB_FSHELP_CASE_INSENSITIVE, node, hook_data);
}

static int
adfs_iterate_f (struct grub_fshelp_node *dir, const grub_uint8_t *raw,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	grub_uint32_t entry;

	for (entry = 0; entry < ADFS_F_ENTRIES; entry++)
	{
		const grub_uint8_t *de = raw + 5 + entry * 26;
		grub_uint32_t name_len;

		if (de[0] == 0)
			break;
		for (name_len = 0; name_len < ADFS_F_NAME_LEN; name_len++)
			if (de[name_len] < ' ')
				break;
		if (adfs_emit (dir, de, name_len, adfs_get_le (de + 22, 3),
				adfs_get_le (de + 10, 4), adfs_get_le (de + 14, 4),
				adfs_get_le (de + 18, 4), de[25], hook, hook_data))
			return 1;
	}
	return 0;
}

static int
adfs_iterate_fplus (struct grub_fshelp_node *dir, const grub_uint8_t *raw,
	grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	grub_uint32_t entries = adfs_get_le (raw + 16, 4);
	grub_uint32_t names_size = adfs_get_le (raw + 20, 4);
	grub_uint32_t names_offset = adfs_fplus_entry_offset (raw, entries);
	grub_uint32_t entry;

	for (entry = 0; entry < entries; entry++)
	{
		const grub_uint8_t *de = raw + adfs_fplus_entry_offset (raw, entry);
		grub_uint32_t name_len = adfs_get_le (de + 20, 4);
		grub_uint32_t name_ptr = adfs_get_le (de + 24, 4);

		if (name_len == 0 || name_len > ADFS_FPLUS_NAME_LEN
			|| name_ptr > names_size || name_len > names_size - name_ptr)
		{
			grub_error (GRUB_ERR_BAD_FS, "malformed ADFS F+ directory entry");
			return 1;
		}
		if (adfs_emit (dir, raw + names_offset + name_ptr, name_len,
				adfs_get_le (de + 12, 4), adfs_get_le (de, 4),
				adfs_get_le (de + 4, 4), adfs_get_le (de + 8, 4),
				adfs_get_le (de + 16, 4), hook, hook_data))
			return 1;
	}
	return 0;
}

static int
adfs_iterate_dir (grub_fshelp_node_t dir, grub_fshelp_iterate_dir_hook_t hook, void *hook_data)
{
	struct grub_adfs_data *data = dir->data;
	grub_uint8_t header[28];
	grub_uint8_t *raw;
	grub_uint32_t size;
	int ret;

	if (adfs_get_le (data->dr.format_version, 4) == 0)
	{
		if (dir->size != 0 && dir->size != ADFS_F_DIR_SIZE)
		{
			grub_error (GRUB_ERR_BAD_FS, "invalid ADFS F directory size");
			return 0;
		}
		size = ADFS_F_DIR_SIZE;
	}
	else
	{
		if (adfs_read_object (data, dir->indaddr, 0, sizeof (header), header, 0, 0) != sizeof (header))
			return 0;
		if (!adfs_fplus_validate_header (header, &size))
		{
			grub_error (GRUB_ERR_BAD_FS, "malformed ADFS F+ directory header");
			return 0;
		}
	}

	raw = grub_malloc (size);
	if (!raw)
		return 0;
	if (adfs_read_object (data, dir->indaddr, 0, size, raw, 0, 0) != size)
		goto fail;

	if (adfs_get_le (data->dr.format_version, 4) == 0)
	{
		if (!adfs_f_validate (raw))
		{
			grub_error (GRUB_ERR_BAD_FS, "ADFS F directory checksum mismatch");
			goto fail;
		}
		ret = adfs_iterate_f (dir, raw, hook, hook_data);
	}
	else
	{
		if (!adfs_fplus_validate (raw, size))
		{
			grub_error (GRUB_ERR_BAD_FS, "ADFS F+ directory checksum mismatch");
			goto fail;
		}
		ret = adfs_iterate_fplus (dir, raw, hook, hook_data);
	}
	grub_free (raw);
	return ret;

fail:
	grub_free (raw);
	return 0;
}

static void
adfs_free_data (struct grub_adfs_data *data)
{
	if (!data)
		return;
	grub_free (data->map);
	grub_free (data);
}

static struct grub_adfs_data *
adfs_mount (grub_disk_t disk)
{
	struct grub_adfs_data *data;
	struct grub_adfs_discrecord map_dr;
	grub_uint32_t root_size;

	data = grub_zalloc (sizeof (*data));
	if (!data)
		return 0;
	data->disk = disk;
	if (!adfs_read_discrecord (disk, &data->dr))
		goto bad_fs;
	if (!adfs_read_map (data))
		goto bad_fs;
	grub_memcpy (&map_dr, data->map + 4, sizeof (map_dr));
	if (!adfs_check_discrecord (&map_dr)
		|| !adfs_same_geometry (&data->dr, &map_dr))
		goto bad_fs;
	data->dr = map_dr;

	root_size = adfs_get_le (data->dr.format_version, 4) ? adfs_get_le (data->dr.root_size, 4) : ADFS_F_DIR_SIZE;
	if (root_size == 0 || root_size > ADFS_FPLUS_MAX_SIZE)
		goto bad_fs;
	data->root.data = data;
	data->root.indaddr = adfs_get_le (data->dr.root, 4);
	data->root.loadaddr = 0xfff0003fU;
	data->root.execaddr = 0xec22c000U;
	data->root.size = root_size;
	data->root.attr = ADFS_ATTR_DIRECTORY;
	return data;

bad_fs:
	if (grub_errno == GRUB_ERR_NONE || grub_errno == GRUB_ERR_OUT_OF_RANGE)
		grub_error (GRUB_ERR_BAD_FS, "not an ADFS filesystem");
	else if (grub_errno != GRUB_ERR_OUT_OF_MEMORY)
		grub_error (GRUB_ERR_BAD_FS, "invalid or corrupted ADFS filesystem");
	adfs_free_data (data);
	return 0;
}

static grub_err_t
grub_adfs_open (grub_file_t file, const char *name)
{
	struct grub_adfs_data *data;
	struct grub_fshelp_node *node = 0;

	grub_dl_ref (my_mod);
	data = adfs_mount (file->device->disk);
	if (!data)
		goto fail;
	grub_fshelp_find_file (name, &data->root, &node, adfs_iterate_dir, 0, GRUB_FSHELP_REG);
	if (grub_errno)
		goto fail;

	file->size = node->size;
	data->root = *node;
	if (node != &data->root)
		grub_free (node);
	file->data = data;
	file->offset = 0;
	return GRUB_ERR_NONE;

fail:
	if (data && node && node != &data->root)
		grub_free (node);
	adfs_free_data (data);
	grub_dl_unref (my_mod);
	return grub_errno;
}

static grub_ssize_t
grub_adfs_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct grub_adfs_data *data = file->data;

	if (file->offset > file->size)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "attempt to read past end of ADFS file");
		return -1;
	}
	if ((grub_uint64_t) len > file->size - file->offset)
		len = (grub_size_t) (file->size - file->offset);
	return adfs_read_object (data, data->root.indaddr, file->offset, len, buf, file->read_hook, file->read_hook_data);
}

static grub_err_t
grub_adfs_close (grub_file_t file)
{
	adfs_free_data (file->data);
	grub_dl_unref (my_mod);
	return GRUB_ERR_NONE;
}

struct grub_adfs_dir_ctx
{
	grub_fs_dir_hook_t hook;
	void *hook_data;
};

static int
grub_adfs_dir_iter (const char *filename, enum grub_fshelp_filetype filetype,
	grub_fshelp_node_t node, void *hook_data)
{
	struct grub_adfs_dir_ctx *ctx = hook_data;
	struct grub_dirhook_info info;
	int mtime_valid;
	int ret;

	grub_memset (&info, 0, sizeof (info));
	info.dir = (filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_DIR;
	info.symlink = (filetype & GRUB_FSHELP_TYPE_MASK) == GRUB_FSHELP_SYMLINK;
	info.case_insensitive = 1;
	info.mtime = adfs_mtime (node, &mtime_valid);
	info.mtimeset = mtime_valid;
	info.inodeset = 1;
	info.inode = node->indaddr;
	grub_free (node);
	ret = ctx->hook (filename, &info, ctx->hook_data);
	return ret;
}

static grub_err_t
grub_adfs_dir (grub_device_t device, const char *path, grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_adfs_dir_ctx ctx = { hook, hook_data };
	struct grub_adfs_data *data;
	struct grub_fshelp_node *dir = 0;

	grub_dl_ref (my_mod);
	data = adfs_mount (device->disk);
	if (!data)
		goto out;
	grub_fshelp_find_file (path, &data->root, &dir, adfs_iterate_dir, 0, GRUB_FSHELP_DIR);
	if (!grub_errno)
		adfs_iterate_dir (dir, grub_adfs_dir_iter, &ctx);
	if (dir && dir != &data->root)
		grub_free (dir);
	adfs_free_data (data);

out:
	grub_dl_unref (my_mod);
	return grub_errno;
}

static grub_err_t
grub_adfs_label (grub_device_t device, char **label)
{
	struct grub_adfs_data *data;
	grub_uint32_t len = sizeof (data->dr.disc_name);

	grub_dl_ref (my_mod);
	data = adfs_mount (device->disk);
	if (!data)
	{
		*label = 0;
		grub_dl_unref (my_mod);
		return grub_errno;
	}
	while (len && data->dr.disc_name[len - 1] <= ' ')
		len--;
	*label = grub_malloc (len * GRUB_MAX_UTF8_PER_LATIN1 + 1);
	if (*label)
		*grub_latin1_to_utf8 ((grub_uint8_t *) *label, data->dr.disc_name, len) = '\0';
	adfs_free_data (data);
	grub_dl_unref (my_mod);
	return grub_errno;
}

static grub_err_t
grub_adfs_uuid (grub_device_t device, char **uuid)
{
	struct grub_adfs_data *data;

	grub_dl_ref (my_mod);
	data = adfs_mount (device->disk);
	if (!data)
	{
		*uuid = 0;
		grub_dl_unref (my_mod);
		return grub_errno;
	}
	*uuid = grub_xasprintf ("%04x", adfs_get_le (data->dr.disc_id, 2));
	adfs_free_data (data);
	grub_dl_unref (my_mod);
	return grub_errno;
}

static struct grub_fs grub_adfs_fs =
{
	.name = "adfs",
	.fs_dir = grub_adfs_dir,
	.fs_open = grub_adfs_open,
	.fs_read = grub_adfs_read,
	.fs_close = grub_adfs_close,
	.fs_label = grub_adfs_label,
	.fs_uuid = grub_adfs_uuid,
	.next = 0
};

GRUB_MOD_INIT(adfs)
{
	grub_adfs_fs.mod = mod;
	grub_fs_register (&grub_adfs_fs);
	my_mod = mod;
}

GRUB_MOD_FINI(adfs)
{
	grub_fs_unregister (&grub_adfs_fs);
}
