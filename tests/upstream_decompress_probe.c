/* Upstream decompressor lifetime regressions. GPL-3.0-or-later.
 * Build once per PROBE_GZIO/PROBE_LZOPIO/PROBE_XZ/PROBE_HFS selection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/crypto.h>
#include <rover.h>

static void *allocations[4096];
static unsigned live, attempts, fail_at, checks;

static void
check (int ok)
{
	checks++;
	if (!ok)
	{
		fprintf (stderr, "check %u failed (allocation %u/%u, live %u): %s\n",
			checks, attempts, fail_at, live, grub_errmsg);
		abort ();
	}
}

static void *
tracked_malloc (grub_size_t size)
{
	unsigned i;
	void *p;
	if (++attempts == fail_at)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "injected failure");
		return NULL;
	}
	p = malloc (size ? size : 1);
	check (p != NULL);
	for (i = 0; i < ARRAY_SIZE (allocations); i++)
		if (!allocations[i])
		{
			allocations[i] = p;
			live++;
			return p;
		}
	abort ();
}

static void
tracked_free (void *p)
{
	unsigned i;
	if (!p)
		return;
	for (i = 0; i < ARRAY_SIZE (allocations); i++)
		if (allocations[i] == p)
		{
			allocations[i] = NULL;
			live--;
			free (p);
			return;
		}
	fprintf (stderr, "invalid or double free\n");
	abort ();
}

static void *
tracked_calloc (grub_size_t count, grub_size_t size)
{
	void *p;
	check (!size || count <= GRUB_SIZE_MAX / size);
	p = tracked_malloc (count * size);
	if (p)
		memset (p, 0, count * size);
	return p;
}

static void *tracked_zalloc (grub_size_t size) { return tracked_calloc (1, size); }

#define grub_malloc tracked_malloc
#define grub_calloc tracked_calloc
#define grub_zalloc tracked_zalloc
#define grub_free tracked_free

#if defined(PROBE_GZIO)
#include "../grub/grub-core/io/gzio.c"
#elif defined(PROBE_LZOPIO)
#include "../grub/grub-core/io/lzopio.c"
#elif defined(PROBE_XZ)
/* xzembed uses libc allocation, including its checksum contexts. */
#define malloc tracked_malloc
#define free tracked_free
#include "../grub/grub-core/lib/xzembed/xz_dec_stream.c"
#include "../grub/grub-core/lib/xzembed/xz_dec_bcj.c"
#undef malloc
#undef free
#elif defined(PROBE_HFS)
#include "../grub/grub-core/fs/hfs.c"
#else
#error "Select a probe"
#endif

#undef grub_malloc
#undef grub_calloc
#undef grub_zalloc
#undef grub_free

static unsigned char *
load (const char *path, size_t *size)
{
	FILE *f = fopen (path, "rb");
	unsigned char *p;
	check (f && !fseek (f, 0, SEEK_END));
	*size = (size_t) ftell (f);
	rewind (f);
	p = malloc (*size ? *size : 1);
	check (p && fread (p, 1, *size, f) == *size);
	fclose (f);
	return p;
}

#if defined(PROBE_LZOPIO)
static grub_ssize_t
memory_read (grub_file_t file, char *buf, grub_size_t size)
{
	memcpy (buf, (char *) file->data + file->offset, size);
	return size;
}
#endif

int
main (int argc, char **argv)
{
	unsigned i;
#if defined(PROBE_HFS)
	struct grub_hfs_data data = {0};
	grub_hfs_datarecord_t dr = {{0}};
	(void) argc;
	(void) argv;
	data.blksz = 512;
	dr[0].first_block = grub_cpu_to_be16 (8);
	dr[0].count = grub_cpu_to_be16 (2);
	check (grub_hfs_block (&data, dr, 16, 1, 0) == 9);
	grub_errno = GRUB_ERR_NONE;
	check (grub_hfs_block (&data, dr, GRUB_HFS_CNID_EXT, 2, 0) == 0);
	check (grub_errno == GRUB_ERR_BAD_FS);
	memset (dr, 0, sizeof (dr));
	grub_errno = GRUB_ERR_NONE;
	check (grub_hfs_block (&data, dr, 16, 0, 0) == 0);
	check (grub_errno == GRUB_ERR_BAD_FS);
#else
	unsigned char *input, *expected, *output;
	size_t insize, outsize;
	check (argc == 3);
	input = load (argv[1], &insize);
	expected = load (argv[2], &outsize);
	output = malloc (outsize);
	check (output != NULL);
	rover_init (ROVER_INIT_NO_HOSTDISK);
#if defined(PROBE_GZIO)
	for (i = 0; i < 128; i++)
	{
		grub_errno = GRUB_ERR_NONE;
		check (grub_zlib_decompress ((char *) input, insize, 0,
			(char *) output, outsize) == (grub_ssize_t) outsize);
		check (!memcmp (output, expected, outsize));
		check (!live);
		grub_errno = GRUB_ERR_NONE;
		check (grub_deflate_decompress ((char *) input + 2, insize - 6, 0,
			(char *) output, outsize) == (grub_ssize_t) outsize);
		check (!memcmp (output, expected, outsize));
		check (!live);
	}
	attempts = 0;
	grub_zlib_decompress ((char *) input, insize, 0, (char *) output, outsize);
	{
		unsigned count = attempts;
		for (i = 1; i <= count; i++)
		{
			attempts = 0;
			fail_at = i;
			grub_errno = GRUB_ERR_NONE;
			check (grub_zlib_decompress ((char *) input, insize, 0,
				(char *) output, outsize) == -1);
			check (!live);
		}
		fail_at = 0;
	}
#elif defined(PROBE_XZ)
	{
		struct xz_dec *dec = xz_dec_init (1U << 24);
		unsigned stable = 0;
		check (dec != NULL);
		for (i = 0; i < 128; i++)
		{
			struct xz_buf b = { input, 0, insize, output, 0, outsize };
			xz_dec_reset (dec);
			check (xz_dec_run (dec, &b) == XZ_STREAM_END);
			check (b.out_pos == outsize && !memcmp (output, expected, outsize));
			if (!i)
				stable = live;
			check (live == stable);
		}
		/* Fail each checksum-context allocation, then reuse the same decoder. */
		for (i = 1; i <= 4; i++)
		{
			struct xz_buf b = { input, 0, insize, output, 0, outsize };
			xz_dec_reset (dec);
			attempts = 0;
			fail_at = i;
			grub_errno = GRUB_ERR_NONE;
			check (xz_dec_run (dec, &b) == XZ_MEMLIMIT_ERROR);
			fail_at = 0;
			grub_errno = GRUB_ERR_NONE;
			xz_dec_reset (dec);
			b.in_pos = b.out_pos = 0;
			check (xz_dec_run (dec, &b) == XZ_STREAM_END);
			check (live == stable);
		}
		xz_dec_end (dec);
		check (!live);
	}
#elif defined(PROBE_LZOPIO)
	{
		struct grub_fs fs = { .fs_read = memory_read };
		struct grub_file raw = { .fs = &fs, .data = input, .size = insize };
		for (i = 0; i < 128; i++)
		{
			struct grub_lzopio dec = { .file = &raw };
			struct grub_file wrapped = { .data = &dec };
			grub_errno = GRUB_ERR_NONE;
			raw.offset = 0;
			check (test_header (&wrapped) == 1);
			check (!live);
			check (uncompress_block (&dec) == 0);
			check (dec.block.usize <= outsize);
			check (!memcmp (dec.block.udata, expected, dec.block.usize));
			tracked_free (dec.block.udata);
			tracked_free (dec.block.cdata);
			check (!live);
		}
		{
			struct grub_lzopio dec = { .file = &raw };
			struct grub_file wrapped = { .data = &dec };
			grub_off_t start;
			raw.offset = 0;
			check (test_header (&wrapped) == 1);
			start = raw.offset;
			/* Make the declared size exceed the actual decompressed length. */
			dec.block.usize++;
			check (uncompress_block (&dec) == -1);
			check (!dec.block.udata && !dec.block.cdata && !live);
			dec.block.usize--;
			raw.offset = start;
			grub_errno = GRUB_ERR_NONE;
			check (uncompress_block (&dec) == 0);
			check (!memcmp (dec.block.udata, expected, dec.block.usize));
			tracked_free (dec.block.udata);
			tracked_free (dec.block.cdata);
			check (!live);
		}
		/* Damaged header checksum must release the temporary context. */
		input[27] ^= 1;
		{
			struct grub_lzopio dec = { .file = &raw };
			struct grub_file wrapped = { .data = &dec };
			raw.offset = 0;
			check (test_header (&wrapped) == 0);
			check (!live);
		}
	}
#endif
	grub_errno = GRUB_ERR_NONE;
	rover_fini ();
	free (output);
	free (expected);
	free (input);
#endif
	printf ("PASS %u checks, no outstanding tracked allocations\n", checks);
	return 0;
}
