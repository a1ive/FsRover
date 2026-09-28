/* Real GRUB strtol boundary regression probe. GPL-3.0-or-later. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <grub/misc.h>
#include <grub/types.h>

static unsigned checks, failures;

static void
check_strtol (const char *text, int base)
{
	char *expected_end;
	const char *actual_end;
	long expected, actual;
	grub_err_t expected_error;
	unsigned null_end;

	errno = 0;
	expected = strtol (text, &expected_end, base);
	expected_error = errno == ERANGE ? GRUB_ERR_OUT_OF_RANGE : GRUB_ERR_NONE;
	for (null_end = 0; null_end < 2; null_end++)
	{
		grub_errno = GRUB_ERR_NONE;
		actual_end = NULL;
		actual = grub_strtol (text, null_end ? NULL : &actual_end, base);
		checks++;
		if (actual != expected || grub_errno != expected_error
			|| (!null_end && actual_end != expected_end))
		{
			fprintf (stderr, "FAIL strtol [%s], base=%d, null_end=%u: "
				"value=%ld (expected %ld), error=%d (expected %d)\n",
				text, base, null_end, actual, expected,
				(int) grub_errno, (int) expected_error);
			failures++;
		}
	}
	grub_errno = GRUB_ERR_NONE;
}

int
product_strtol_probe (void)
{
	const unsigned long long magnitudes[] = {
		0, 1, (unsigned long long) LONG_MAX - 1,
		LONG_MAX, (unsigned long long) LONG_MAX + 1,
		(unsigned long long) LONG_MAX + 2, ULLONG_MAX
	};
	const int bases[] = { 10, 16, 8 };
	const char *formats[] = { "%s%llu!", "%s%llx!", "%s%llo!" };
	char text[80];
	unsigned i, j, negative;

	checks = failures = 0;
	/* The libc oracle uses the host's long limits, independently of GRUB. */
	for (i = 0; i < ARRAY_SIZE (bases); i++)
		for (j = 0; j < ARRAY_SIZE (magnitudes); j++)
			for (negative = 0; negative < 2; negative++)
			{
				snprintf (text, sizeof (text), formats[i],
					negative ? "-" : "", magnitudes[j]);
				check_strtol (text, bases[i]);
			}
	snprintf (text, sizeof (text), " \t-%llu!", (unsigned long long) LONG_MAX + 1);
	check_strtol (text, 10);
	snprintf (text, sizeof (text), "-0x%llx!", (unsigned long long) LONG_MAX + 1);
	check_strtol (text, 0);
	snprintf (text, sizeof (text), "-0%llo!", (unsigned long long) LONG_MAX + 1);
	check_strtol (text, 0);
	printf ("strtol: %u checks, %u failures\n", checks, failures);
	return failures != 0;
}
