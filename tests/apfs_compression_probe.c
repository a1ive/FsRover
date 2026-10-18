/* Compile the APFS driver with ASan/UBSan; resource forks below are synthetic. */
#include <stdio.h>
#include <string.h>
#include "../grub/grub-core/fs/apfs.c"

static unsigned checks;

static int
check_block(unsigned algo, const grub_uint8_t *src, unsigned size,
	unsigned expected_size, const char *expected, int valid)
{
	grub_uint8_t output[16];
	struct grub_apfs_cmp cmp = {0};
	grub_err_t err;
	int ok;

	memset(output, 0xA5, sizeof(output));
	cmp.algo = algo;
	cmp.cbuf = output + 1;
	grub_errno = GRUB_ERR_NONE;
	err = grub_apfs_cmp_decompress(&cmp, src, size, expected_size);
	ok = valid ? (!err && cmp.cbuf_len == expected_size
		&& !memcmp(cmp.cbuf, expected, expected_size)) : (err != 0);
	ok = ok && output[0] == 0xA5 && output[expected_size + 1] == 0xA5;
	grub_free(cmp.scratch);
	checks++;
	if (!ok)
		fprintf(stderr, "FAIL block algo=%u size=%u expected=%u valid=%d err=%d\n",
			algo, size, expected_size, valid, err);
	return ok;
}

static void
put32(grub_uint8_t *p, grub_uint32_t value)
{
	value = grub_cpu_to_le32(value);
	memcpy(p, &value, sizeof(value));
}

static int
check_resource(unsigned algo)
{
	struct grub_apfs_cmp cmp = {0};
	struct grub_apfs_file file = {0};
	const unsigned first = algo == GRUB_APFS_COMPRESS_ZLIB_RSRC ? 40 : 12;
	const unsigned end = first + 65537 + 4;
	grub_uint8_t *resource = grub_zalloc(end);
	unsigned pass, i;
	int ok = 0;

	cmp.cbuf = grub_malloc(GRUB_APFS_CMP_BLOCK);
	if (!resource || !cmp.cbuf)
		goto fail;
	if (algo == GRUB_APFS_COMPRESS_ZLIB_RSRC)
	{
		resource[3] = 16; /* big-endian resource data offset */
		put32(resource + 20, 2);
		put32(resource + 24, first - 20);
		put32(resource + 28, 65537);
		put32(resource + 32, first + 65537 - 20);
		put32(resource + 36, 4);
	}
	else
	{
		put32(resource, first);
		put32(resource + 4, first + 65537);
		put32(resource + 8, end);
	}
	resource[first] = resource[first + 65537] =
		algo == GRUB_APFS_COMPRESS_PLAIN_RSRC ? 0xCC : 0xFF;
	for (i = 0; i < 65536; i++)
		resource[first + 1 + i] = (grub_uint8_t) i;
	memcpy(resource + first + 65538, "abc", 3);
	cmp.algo = algo;
	cmp.size = 65539;
	cmp.cbuf_block = ~(grub_uint64_t) 0;
	cmp.rsrc.data = resource;
	cmp.rsrc.len = end;
	file.cmp = &cmp;
	for (pass = 0; pass < 3; pass++)
	{
		grub_uint64_t block = pass == 0 ? 1 : 0;
		grub_errno = GRUB_ERR_NONE;
		if (grub_apfs_cmp_load_block(&file, block))
			goto fail;
		if (block == 1)
		{
			if (cmp.cbuf_len != 3 || memcmp(cmp.cbuf, "abc", 3))
				goto fail;
		}
		else
		{
			if (cmp.cbuf_len != 65536)
				goto fail;
			for (i = 0; i < 65536; i++)
				if (cmp.cbuf[i] != (grub_uint8_t) i)
					goto fail;
		}
		checks++;
	}
	/* The last block advertises one byte beyond the embedded resource. */
	cmp.cbuf_block = ~(grub_uint64_t) 0;
	cmp.rsrc.len--;
	grub_errno = GRUB_ERR_NONE;
	if (grub_apfs_cmp_load_block(&file, 1) != GRUB_ERR_BAD_FS)
		goto fail;
	checks++;
	ok = 1;
fail:
	if (!ok)
		fprintf(stderr, "FAIL resource algo=%u: %s\n", algo, grub_errmsg);
	grub_free(cmp.cbuf);
	grub_free(resource);
	return ok;
}

int
main(void)
{
	const unsigned algos[] = {3, 4, 7, 8, 9, 10, 11, 12, 13, 14};
	grub_uint8_t stored[] = {0, 'a', 'b', 'c', 'd', 'e'};
	grub_uint8_t raw[15] = {'b', 'v', 'x', '-', 3, 0, 0, 0,
		'a', 'b', 'c', 'b', 'v', 'x', '$'};
	grub_uint8_t lzvn[28] = {'b', 'v', 'x', 'n', 3, 0, 0, 0,
		12, 0, 0, 0, 0xE3, 'a', 'b', 'c', 6, 0, 0, 0, 0, 0, 0, 0,
		'b', 'v', 'x', '$'};
	unsigned i;
	int ok = 1;

	for (i = 0; i < ARRAY_SIZE(algos); i++)
	{
		unsigned algo = algos[i];
		stored[0] = (algo == 7 || algo == 8) ? 6 :
			(algo == 9 || algo == 10) ? 0xCC : 0xFF;
		ok &= check_block(algo, stored, 5, 4, "abcd", 1);
		ok &= check_block(algo, stored, 4, 4, NULL, 0);
		ok &= check_block(algo, stored, 6, 4, NULL, 0);
		ok &= check_block(algo, stored, 0, 4, NULL, 0);
	}
	for (i = 0; i < 16; i++)
	{
		stored[0] = (grub_uint8_t) ((i << 4) | 15);
		ok &= check_block(3, stored, 5, 4, "abcd", 1);
		ok &= check_block(4, stored, 5, 4, "abcd", 1);
	}
	for (i = 9; i <= 14; i++)
	{
		stored[0] = 0;
		ok &= check_block(i, stored, 5, 4, NULL, 0);
		stored[0] = 0x0F;
		ok &= check_block(i, stored, 5, 4, NULL, 0);
	}
	for (i = 11; i <= 12; i++)
	{
		ok &= check_block(i, raw, sizeof(raw), 3, "abc", 1);
		ok &= check_block(i, lzvn, sizeof(lzvn), 3, "abc", 1);
		ok &= check_block(i, raw, 3, 3, NULL, 0);
		raw[3] = '?';
		ok &= check_block(i, raw, sizeof(raw), 3, NULL, 0);
		raw[3] = '-';
	}
	ok &= check_resource(GRUB_APFS_COMPRESS_PLAIN_RSRC);
	ok &= check_resource(GRUB_APFS_COMPRESS_ZLIB_RSRC);
	if (!ok)
		return 1;
	printf("PASS %u APFS compression checks\n", checks);
	return 0;
}
