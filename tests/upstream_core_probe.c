/* Build with ASan/UBSan and section garbage collection; include the driver
   sources to exercise their internal parsers without unlocking a volume. */
#include <stdio.h>
#include <string.h>
#include "../grub/grub-core/disk/luks2.c"
#define grub_module_license af_module_license
#include "../grub/grub-core/disk/AFSplitter.c"
#undef grub_module_license
#include "../grub/grub-core/lib/datetime.c"

int
main (void)
{
	const unsigned indices[] = {0, 31, 32, 63, 64, 255};
	const struct {
		grub_int64_t stamp;
		struct grub_datetime date;
	} dates[] = {
		{-2208988800LL, {1900, 1, 1, 0, 0, 0}},
		{0, {1970, 1, 1, 0, 0, 0}},
		{2147483648LL, {2038, 1, 19, 3, 14, 8}},
		{4102444800LL, {2100, 1, 1, 0, 0, 0}}
	};
	unsigned i, which;
	for (which = 0; which < 2; which++)
		for (i = 0; i < ARRAY_SIZE (indices); i++)
		{
			char text[256];
			grub_json_t *json = NULL;
			grub_luks2_digest_t digest = {0};
			grub_err_t err;
			unsigned bit = indices[i];
			snprintf (text, sizeof (text),
				"{\"type\":\"pbkdf2\",\"segments\":[\"%u\"],"
				"\"keyslots\":[\"%u\"],\"salt\":\"\",\"digest\":\"\","
				"\"hash\":\"sha256\",\"iterations\":1000}",
				which ? 0 : bit, which ? bit : 0);
			grub_errno = GRUB_ERR_NONE;
			if (grub_json_parse (&json, text, strlen (text)))
				return 1;
			err = luks2_parse_digest (&digest, json);
			grub_json_free (json);
			if ((bit >= 64) != (err != GRUB_ERR_NONE))
				return 1;
			if (bit < 64 && (which ? digest.keyslots : digest.segments)
				!= ((grub_uint64_t) 1 << bit))
				return 1;
		}
	{
		char text[] = "{}";
		grub_json_t *json = NULL;
		grub_luks2_keyslot_t keyslot = {0};
		grub_luks2_digest_t digest = {0};
		grub_luks2_segment_t segment = {0};
		if (grub_json_parse (&json, text, strlen (text)))
			return 1;
		if (!luks2_get_keyslot (&keyslot, &digest, &segment, json, 7)
			|| keyslot.idx != 7)
			return 1;
		grub_json_free (json);
	}
	{
		gcry_md_spec_t hash = {0};
		grub_uint8_t source[32], dest[32];
		hash.mdlen = 32;
		memset (source, 0x5a, sizeof (source));
		if (AF_merge (&hash, source, dest, sizeof (source), 0) != GPG_ERR_INV_ARG)
			return 1;
		if (AF_merge (&hash, source, dest, sizeof (source), 1)
			|| memcmp (source, dest, sizeof (source)))
			return 1;
	}
	for (i = 0; i < ARRAY_SIZE (dates); i++)
	{
		struct grub_datetime actual = {0};
		const struct grub_datetime *d = &dates[i].date;
		grub_unixtime2datetime (dates[i].stamp, &actual);
		if (actual.year != d->year || actual.month != d->month
			|| actual.day != d->day || actual.hour != d->hour
			|| actual.minute != d->minute || actual.second != d->second)
			return 1;
	}
	puts ("PASS 19 LUKS2/AF/date cases");
	return 0;
}
