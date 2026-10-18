/* Exercise exact-size file lists with the product parser under ASan/UBSan. */
#include <stdio.h>
#include <string.h>
#include "../grub/grub-core/fs/fbfs.c"

static unsigned checks;

static int
check_entry(unsigned extra, unsigned available, unsigned entry_size,
	int terminated, int valid)
{
	struct grub_archelp_data *data;
	grub_archelp_mode_t mode = GRUB_ARCHELP_ATTR_DIR;
	grub_int32_t mtime = 0;
	char *name = NULL;
	unsigned name_start = (unsigned) offsetof(struct fbm_file, name) + extra;
	grub_err_t err;
	int ok = 0;

	data = grub_zalloc(offsetof(struct grub_archelp_data, fb_list) + available);
	if (!data)
		goto fail;
	data->name_offset = extra;
	data->list_size = available;
	memset(data->fb_list, 'a', available);
	data->fb_list[0] = (char) (entry_size - 2);
	if (terminated && entry_size <= available)
		data->fb_list[entry_size - 1] = 0;
	grub_errno = GRUB_ERR_NONE;
	err = grub_fbfs_find_file(data, &name, &mtime, &mode);
	if (!valid)
	{
		ok = err == GRUB_ERR_BAD_FS;
		goto fail;
	}
	if (err || mode != GRUB_ARCHELP_ATTR_FILE || !name
		|| strlen(name) != entry_size - name_start - 1)
		goto fail;
	grub_free(name);
	name = NULL;
	/* A complete record with no following terminator must fail at EOF. */
	if (grub_fbfs_find_file(data, &name, &mtime, &mode) != GRUB_ERR_BAD_FS)
		goto fail;
	grub_fbfs_rewind(data);
	grub_errno = GRUB_ERR_NONE;
	if (grub_fbfs_find_file(data, &name, &mtime, &mode)
		|| mode != GRUB_ARCHELP_ATTR_FILE)
		goto fail;
	ok = 1;
fail:
	checks++;
	if (!ok)
		fprintf(stderr, "FAIL extra=%u available=%u entry=%u terminated=%d\n",
			extra, available, entry_size, terminated);
	grub_free(name);
	grub_free(data);
	return ok;
}

int
main(void)
{
	unsigned extra, size;
	int ok = 1;

	for (extra = 0; extra <= 4; extra += 4)
	{
		for (size = 1; size <= 20; size++)
			ok &= check_entry(extra, size, 257, 0, 0);
		ok &= check_entry(extra, 16 + extra, 16 + extra, 1, 1);
		ok &= check_entry(extra, 16 + extra, 16 + extra, 0, 0);
		ok &= check_entry(extra, 255, 255, 1, 1);
		ok &= check_entry(extra, 255, 255, 0, 0);
		ok &= check_entry(extra, 20, 3, 1, 0);
	}
	if (!ok)
		return 1;
	printf("PASS %u FBFS list checks\n", checks);
	return 0;
}
