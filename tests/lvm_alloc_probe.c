/* Exercise the product LVM parser with allocation failures and bounded I/O.
   Compile with GCC/Clang, -ffunction-sections and --gc-sections; link grub.lib's
   Linux counterpart for the GRUB string and error functions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grub/disk.h>
#include <grub/diskfilter.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/err.h>

static void *allocations[4096];
static unsigned attempts, fail_at, live;
static unsigned char *image;
static size_t image_size;
static struct grub_diskfilter_vg *registered_vg;

static void *
test_malloc (grub_size_t size)
{
	void *p;
	unsigned i;
	if (++attempts == fail_at)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "injected allocation failure");
		return NULL;
	}
	p = malloc (size ? size : 1);
	if (!p)
		abort ();
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
test_free (void *p)
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
	fprintf (stderr, "invalid/double free at allocation failure %u\n", fail_at);
	abort ();
}

static void *
test_calloc (grub_size_t count, grub_size_t size)
{
	void *p;
	if (size && count > GRUB_SIZE_MAX / size)
	{
		grub_error (GRUB_ERR_OUT_OF_MEMORY, "allocation overflow");
		return NULL;
	}
	p = test_malloc (count * size);
	if (p)
		memset (p, 0, count * size);
	return p;
}

static void *test_zalloc (grub_size_t size) { return test_calloc (1, size); }

static char *
test_strndup (const char *s, grub_size_t n)
{
	grub_size_t len = 0;
	char *p;
	while (len < n && s[len])
		len++;
	p = test_malloc (len + 1);
	if (p)
	{
		memcpy (p, s, len);
		p[len] = 0;
	}
	return p;
}

static char *test_strdup (const char *s) { return test_strndup (s, strlen (s)); }

static grub_err_t
test_read (grub_disk_t disk, grub_disk_addr_t sector, grub_off_t offset,
	grub_size_t size, void *buffer)
{
	grub_uint64_t start = (sector << 9) + offset;
	(void) disk;
	if (start > image_size || size > image_size - start)
		return grub_error (GRUB_ERR_READ_ERROR, "truncated test image");
	memcpy (buffer, image + start, size);
	return GRUB_ERR_NONE;
}

static struct grub_diskfilter_vg *
test_lookup (grub_size_t len, char *uuid)
{
	(void) len;
	(void) uuid;
	return NULL;
}

static grub_err_t
test_register (struct grub_diskfilter_vg *vg)
{
	registered_vg = vg;
	return GRUB_ERR_NONE;
}

#define grub_malloc test_malloc
#define grub_calloc test_calloc
#define grub_zalloc test_zalloc
#define grub_free test_free
#define grub_strdup test_strdup
#define grub_strndup test_strndup
#define grub_disk_read test_read
#define grub_diskfilter_get_vg_by_uuid test_lookup
#define grub_diskfilter_vg_register test_register
#define grub_lvm_init test_lvm_init
#define grub_lvm_fini test_lvm_fini
#include "../grub/grub-core/disk/lvm.c"

static int
run (unsigned failure, int valid)
{
	struct grub_disk disk = {0};
	struct grub_diskfilter_pv_id id = {0};
	struct grub_diskfilter_vg *vg;
	grub_disk_addr_t start = 0;
	fail_at = failure;
	attempts = 0;
	registered_vg = NULL;
	grub_errno = GRUB_ERR_NONE;
	vg = grub_lvm_detect (&disk, &id, &start);
	if (!failure && (!!vg != valid))
	{
		fprintf (stderr, "unexpected detection result: %s\n", grub_errmsg);
		return 1;
	}
	if (registered_vg)
	{
		test_free (registered_vg->name);
		grub_lvm_free_vg (registered_vg);
	}
	test_free (id.uuid);
	if (live)
	{
		fprintf (stderr, "%u allocations leaked at failure %u\n", live, failure);
		return 1;
	}
	return 0;
}

int
main (int argc, char **argv)
{
	FILE *file;
	unsigned count, i;
	int valid;
	if (argc != 3)
		return 2;
	valid = atoi (argv[2]);
	file = fopen (argv[1], "rb");
	if (!file || fseek (file, 0, SEEK_END))
		return 2;
	image_size = (size_t) ftell (file);
	rewind (file);
	image = malloc (image_size);
	if (!image || fread (image, 1, image_size, file) != image_size)
		return 2;
	fclose (file);
	if (run (0, valid))
		return 1;
	count = attempts;
	for (i = 1; i <= count; i++)
		if (run (i, valid))
			return 1;
	free (image);
	printf ("PASS %u allocation failure points; no leaked or multiply freed allocations\n", count);
	return 0;
}
