/* ReFS checkpoint selection, read hooks and failed-cache regression probes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grub/disk.h>
#include <grub/mm.h>

static grub_err_t probe_read(grub_disk_t, grub_disk_addr_t, grub_off_t,
	grub_size_t, void *);
static void *probe_malloc(grub_size_t);
#define grub_disk_read probe_read
#define grub_malloc probe_malloc
#include "../grub/grub-core/fs/refs.c"
#undef grub_disk_read
#undef grub_malloc

static unsigned char media[128 * 16384];
static unsigned block_size, reads[128], checks;
static unsigned fail_block, fail_read, alloc_count, fail_alloc;
static grub_err_t injected;

static grub_err_t
count_hook(grub_disk_addr_t sector, unsigned offset, unsigned length,
	char *buf, void *data)
{
	(void) sector; (void) offset; (void) buf;
	*(unsigned *) data += length;
	return GRUB_ERR_NONE;
}

static grub_err_t
other_hook(grub_disk_addr_t sector, unsigned offset, unsigned length,
	char *buf, void *data)
{
	return count_hook(sector, offset, length, buf, data);
}

static void *
probe_malloc(grub_size_t size)
{
	if (++alloc_count == fail_alloc)
	{
		grub_error(GRUB_ERR_OUT_OF_MEMORY, "injected allocation failure");
		return NULL;
	}
	return grub_malloc(size);
}

static grub_err_t
probe_read(grub_disk_t disk, grub_disk_addr_t sector, grub_off_t offset,
	grub_size_t size, void *buf)
{
	grub_uint64_t at = sector * 512 + offset;
	unsigned block = (unsigned) (at / block_size);

	if (at > sizeof(media) || size > sizeof(media) - at)
		return grub_error(GRUB_ERR_READ_ERROR, "probe read outside image");
	reads[block]++;
	if (block == fail_block && reads[block] == fail_read)
		return grub_error(injected, "injected read failure");
	memcpy(buf, media + at, size);
	if (disk->read_hook)
		return disk->read_hook(at / 512, (unsigned) (at % 512),
			(unsigned) size, buf, disk->read_hook_data);
	return GRUB_ERR_NONE;
}

static void put32(unsigned char *p, grub_uint32_t n) { n = grub_cpu_to_le32(n); memcpy(p, &n, 4); }
static void put64(unsigned char *p, grub_uint64_t n) { n = grub_cpu_to_le64(n); memcpy(p, &n, 8); }

static void
node(unsigned block, const char *sig, unsigned oid, int v1)
{
	unsigned char *p = media + block * block_size;
	if (v1)
	{
		put64(p, block);
		put64(p + 0x18, oid);
	}
	else
	{
		memcpy(p, sig, 4);
		put64(p + 0x20, block);
		put64(p + 0x48, oid);
	}
}

static void
fixture(unsigned major, unsigned minor, unsigned seq0, unsigned seq1)
{
	int v1 = major == 1;
	unsigned h = v1 ? 0x30 : 0x50, i;

	memset(media, 0, sizeof(media));
	memset(reads, 0, sizeof(reads));
	block_size = 16384;
	fail_block = 127;
	fail_read = fail_alloc = alloc_count = 0;
	grub_errno = GRUB_ERR_NONE;
	memcpy(media + 3, "ReFS", 4);
	memcpy(media + 0x10, "FSRS", 4);
	put32(media + 0x20, 512);
	put32(media + 0x24, 32);
	media[0x28] = (unsigned char) major;
	media[0x29] = (unsigned char) minor;
	node(30, "SUPB", 0, v1);
	put32(media + 30 * block_size + h + 0x20, 0x100);
	put32(media + 30 * block_size + h + 0x24, 2);
	put64(media + 30 * block_size + 0x100, 40);
	put64(media + 30 * block_size + 0x108, 44);
	for (i = 0; i < 2; i++)
	{
		unsigned char *p = media + (40 + 4 * i) * block_size;
		node(40 + 4 * i, "CHKP", 0, v1);
		put64(p + h + 0x10, i ? seq1 : seq0);
		put32(p + (v1 ? 0x58 : 0x90), 1);
		if (!v1 && minor >= 12)
		{
			put32(p + 0x94, 0x100);
			put32(p + 0x100, 0x180);
		}
		else
			put32(p + (v1 ? 0x5C : 0x94), 0x180);
		put64(p + 0x180, 60 + 4 * i);
		node(60 + 4 * i, "MSB+", REFS_OID_OBJECT_TABLE, v1);
	}
}

static int
mount_case(const char *name, unsigned want, grub_err_t error)
{
	struct grub_disk disk = {0};
	struct grub_refs_data *data = grub_refs_mount(&disk);
	int ok = want ? data && data->obj_table[0] == want && !grub_errno
		: !data && grub_errno == error;

	checks++;
	if (!ok)
		fprintf(stderr, "FAIL %s: root=%llu error=%u\n", name,
			(unsigned long long) (data ? data->obj_table[0] : 0), grub_errno);
	if (data)
		grub_refs_unmount(data);
	return ok;
}

static int
cache_case(void)
{
	struct grub_disk disk = {0};
	struct grub_refs_data data = {0};
	struct grub_refs_map_entry entry = {0};
	struct grub_refs_compression_range range = {0};
	unsigned char packed[64], plain[32];
	grub_uint32_t ends[] = {0, 0};
	grub_uint8_t bitmap = 1;
	grub_uint16_t rank = 0;
	unsigned callbacks = 0;
	char output[32];
	/* A decodes to 32 bytes. B overwrites the output with three bytes,
	   then fails the driver's exact decoded-length check. */
	unsigned char good[] = {0x1F, 'A', 1, 0, 7, 0x50, 'A','A','A','A','A'};
	unsigned char bad[] = {0x30, 'B', 'A', 'D'};
	int ok = 0;

	fixture(3, 14, 1, 2);
	data.disk = &disk;
	data.cluster_size = block_size;
	data.cluster_shift = 14;
	data.linear_limit = 128;
	data.bpc_mask = 1023;
	data.compression_unit_size = 32;
	data.compression_format = REFS_COMPRESSION_LZ4;
	data.compressed_buf = packed;
	data.plain_buf = plain;
	range.plain_size = 64;
	range.unit_count = 2;
	range.ends = ends;
	memcpy(media, good, sizeof(good));
	ends[0] = sizeof(good);
	memcpy(media + ends[0], bad, sizeof(bad));
	ends[1] = ends[0] + sizeof(bad);
	if (grub_refs_load_compression_unit(&data, &entry, &range, 0, 0)
		|| memcmp(plain, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32))
		goto done;
	if (grub_refs_load_compression_unit(&data, &entry, &range, 0, 1) == 0
		|| data.cache_valid || memcmp(plain, "BAD", 3))
		goto done;
	grub_errno = GRUB_ERR_NONE;
	if (grub_refs_load_compression_unit(&data, &entry, &range, 0, 0)
		|| !data.cache_valid || memcmp(plain, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32))
		goto done;
	entry.id = range.container_id = 1;
	entry.compact_bitmap = &bitmap;
	entry.compact_rank = &rank;
	data.bpc_shift = 10;
	data.map = &entry;
	data.map_len = 1;
	data.compression = &range;
	data.compression_len = 1;
	grub_file_progress_hook = count_hook;
	data.cache_valid = 0;
	if (grub_refs_read_data(&data, 2048, 0, sizeof(output), output, count_hook, &callbacks)
		|| callbacks != sizeof(output) || memcmp(output, plain, sizeof(output)))
		goto done;
	callbacks = 0;
	if (grub_refs_read_data(&data, 2048, 0, sizeof(output), output, other_hook, &callbacks)
		|| callbacks || disk.read_hook || disk.read_hook_data)
		goto done;
	if (grub_refs_read_data(&data, 1, 0, sizeof(output), output, other_hook, &callbacks)
		|| callbacks != sizeof(output) || disk.read_hook || disk.read_hook_data)
		goto done;
	fail_block = 1; fail_read = reads[1] + 1; injected = GRUB_ERR_READ_ERROR;
	if (grub_refs_read_data(&data, 1, 0, sizeof(output), output, other_hook, &callbacks)
		!= GRUB_ERR_READ_ERROR || disk.read_hook || disk.read_hook_data)
		goto done;
	ok = 1;
done:
	grub_file_progress_hook = NULL;
	checks++;
	if (!ok) fprintf(stderr, "FAIL cache/read hooks: %s\n", grub_errmsg);
	return ok;
}

int main(void)
{
	unsigned versions[][2] = {{1,2}, {3,11}, {3,12}, {3,14}};
	unsigned i;
	int ok = 1;
	for (i = 0; i < 4; i++)
	{
		unsigned major = versions[i][0], minor = versions[i][1];
		fixture(major, minor, 1, 2); ok &= mount_case("secondary newer", 64, 0);
		fixture(major, minor, 3, 2); ok &= mount_case("primary newer", 60, 0);
		fixture(major, minor, 2, 2); ok &= mount_case("equal sequence", 60, 0);
		fixture(major, minor, 1, 2);
		put64(media + 44 * block_size + 0x180, 0);
		ok &= mount_case("newer root missing", 60, 0);
		fixture(major, minor, 1, 2);
		put64(media + 40 * block_size + 0x180, 0);
		put64(media + 44 * block_size + 0x180, 0);
		ok &= mount_case("both roots missing", 0, GRUB_ERR_BAD_FS);
		fixture(major, minor, 1, 2);
		fail_block = 44; fail_read = 1; injected = GRUB_ERR_READ_ERROR;
		ok &= mount_case("checkpoint unreadable", 60, 0);
		fixture(major, minor, 1, 2);
		fail_block = 44; fail_read = 1; injected = GRUB_ERR_OUT_OF_MEMORY;
		ok &= mount_case("checkpoint probe OOM", 0, GRUB_ERR_OUT_OF_MEMORY);
		fixture(major, minor, 1, 2);
		fail_block = 44; fail_read = 2; injected = GRUB_ERR_OUT_OF_MEMORY;
		ok &= mount_case("checkpoint reload OOM", 0, GRUB_ERR_OUT_OF_MEMORY);
		fixture(major, minor, 1, 2);
		fail_block = 64; fail_read = 1; injected = GRUB_ERR_OUT_OF_MEMORY;
		ok &= mount_case("root read OOM", 0, GRUB_ERR_OUT_OF_MEMORY);
		fixture(major, minor, 1, 2); fail_alloc = 2;
		ok &= mount_case("root buffer OOM", 0, GRUB_ERR_OUT_OF_MEMORY);
	}
	ok &= cache_case();
	printf("%s %u ReFS review checks\n", ok ? "PASS" : "FAIL", checks);
	return ok ? 0 : 1;
}
