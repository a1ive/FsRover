/* misc.c - definitions of misc functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <stdarg.h>
#include <grub/term.h>
#include <grub/env.h>
#include <grub/i18n.h>
#include <grub/types.h>
#include <grub/charset.h>
#include <stddef.h>

union printf_arg
{
  /* Yes, type is also part of union as the moment we fill the value
     we don't need to store its type anymore (when we'll need it, we'll
     have format spec again. So save some space.  */
  enum
    {
      INT, LONG, LONGLONG,
      UNSIGNED_INT = 3, UNSIGNED_LONG, UNSIGNED_LONGLONG,
      POINTER,
      STRING,
      UUID,
      DOUBLE,
      UNUSED
    } type;
  long long ll;
  unsigned long long ull;
  const void *ptr;
  double d;
};

struct printf_args
{
  union printf_arg prealloc[32];
  union printf_arg *ptr;
  grub_size_t count;
};

static void
parse_printf_args (const char *fmt0, struct printf_args *args,
		   va_list args_in);
static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args);

static void
free_printf_args (struct printf_args *args)
{
  if (args->ptr != args->prealloc)
    grub_free (args->ptr);
}

static int
grub_iswordseparator (int c)
{
  return (grub_isspace (c) || c == ',' || c == ';' || c == '|' || c == '&');
}

/* grub_gettext_dummy is not translating anything.  */
static const char *
grub_gettext_dummy (const char *s)
{
  return s;
}

const char* (*grub_gettext) (const char *s) = grub_gettext_dummy;

#define ALIGN_MASK (sizeof (grub_addr_t) - 1)
/* Set the threshold to (2 * sizeof(grub_addr_t)) to guarantee at least one word copy. */
#define WORD_COPY_THRES (sizeof (grub_addr_t) * 2)

static void *
memmove_fwd (void *dest, const void *src, grub_size_t n)
{
  grub_uint8_t *d = (grub_uint8_t *) dest;
  const grub_uint8_t *s = (const grub_uint8_t *) src;
  grub_size_t offset = 0;
  grub_addr_t *dw;
  const grub_addr_t *sw;

  /*
   * Fallback to byte-by-byte copy if the buffers are too small or do not share the same
   * alignment offset.
   */
  if (n < WORD_COPY_THRES || (((grub_addr_t) d ^ (grub_addr_t) s) & ALIGN_MASK) != 0)
    goto byte_copy;

  /* Consume the first few bytes to make 'd' and 's' aligned */
  offset = (-((grub_addr_t) d)) & ALIGN_MASK;
  n -= offset;
  while (offset--)
    *d++ = *s++;

  /*
   * Copy data in chunks
   * Although 'd' and 's' are already aligned, casting to "grub_addr_t *" still
   * triggers "cast-align" errors. Cast them to "void *" to silence the error.
   */
  dw = (grub_addr_t *)(void *) d;
  sw = (const grub_addr_t *)(const void *) s;

  for (; n >= sizeof (grub_addr_t); n -= sizeof (grub_addr_t))
    *dw++ = *sw++;

  d = (grub_uint8_t *) dw;
  s = (const grub_uint8_t *) sw;

byte_copy:
  /* Finish the remaining bytes */
  while (n--)
    *d++ = *s++;

  return dest;
}

static void *
memmove_bwd (void *dest, const void *src, grub_size_t n)
{
  grub_uint8_t *d = (grub_uint8_t *) dest + n;
  const grub_uint8_t *s = (const grub_uint8_t *) src + n;
  grub_size_t offset = 0;
  grub_addr_t *dw;
  const grub_addr_t *sw;

  /*
   * Fallback to byte-by-byte copy if the buffers are too small or do not share the same
   * alignment offset.
   */
  if (n < WORD_COPY_THRES || (((grub_addr_t) d ^ (grub_addr_t) s) & ALIGN_MASK) != 0)
    goto byte_copy;

  /* Consume the last few bytes to make 'd' and 's' aligned */
  offset = (grub_addr_t) d & ALIGN_MASK;
  n -= offset;
  while (offset--)
    *--d = *--s;

  /*
   * Copy data in chunks
   * Although 'd' and 's' are already aligned, casting to "grub_addr_t *" still
   * triggers "cast-align" errors. Cast them to "void *" to silence the error.
   */
  dw = (grub_addr_t *)(void *) d;
  sw = (const grub_addr_t *)(const void *) s;

  for (; n >= sizeof (grub_addr_t); n -= sizeof (grub_addr_t))
    *--dw = *--sw;

  d = (grub_uint8_t *) dw;
  s = (const grub_uint8_t *) sw;

byte_copy:
  /* Finish the remaining bytes */
  while (n--)
    *--d = *--s;

  return dest;
}

void *
grub_memmove (void *dest, const void *src, grub_size_t n)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  if (d < s || s + n <= d)
    return memmove_fwd (dest, src, n);

  /* Perform backward copy if dest >= src and buffers overlap to ensure memory safety. */
  return memmove_bwd (dest, src, n);
}

char *
grub_strcpy (char *dest, const char *src)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0')
    ;

  return dest;
}

int
grub_printf (const char *fmt, ...)
{
  va_list ap;
  int ret;

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  /*
   * To prevent infinite recursion when grub_mm_debug is on, disable it
   * when calling grub_vprintf(). One such call loop is:
   *   grub_vprintf() -> parse_printf_args() -> parse_printf_arg_fmt() ->
   *     grub_debug_calloc() -> grub_printf() -> grub_vprintf().
   */
  int grub_mm_debug_save = 0;

  if (grub_mm_debug)
    {
      grub_mm_debug_save = grub_mm_debug;
      grub_mm_debug = 0;
    }
#endif

  va_start (ap, fmt);
  ret = grub_vprintf (fmt, ap);
  va_end (ap);

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  grub_mm_debug = grub_mm_debug_save;
#endif

  return ret;
}

int
grub_printf_ (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vprintf (_(fmt), ap);
  va_end (ap);

  return ret;
}

int
grub_puts_ (const char *s)
{
  return grub_puts (_(s));
}

#if ( defined (__APPLE__) || defined (_MSC_VER) ) && ! defined (GRUB_UTIL)
int
grub_err_printf (const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = grub_vprintf (fmt, ap);
	va_end (ap);

	return ret;
}
#endif

#if ! defined (__APPLE__) && ! defined (_MSC_VER) && ! defined (GRUB_UTIL)
int grub_err_printf (const char *fmt, ...)
__attribute__ ((alias("grub_printf")));
#endif

int
grub_debug_enabled (const char * condition)
{
  const char *debug, *found;
  grub_size_t clen;
  int ret = 0;

  debug = grub_env_get ("debug");
  if (!debug)
    return 0;

  if (grub_strword (debug, "all"))
    {
      if (debug[3] == '\0')
	return 1;
      ret = 1;
    }

  clen = grub_strlen (condition);
  found = debug-1;
  while(1)
    {
      found = grub_strstr (found+1, condition);

      if (found == NULL)
	break;

      /* Found condition is not a whole word, so ignore it. */
      if (*(found + clen) != '\0' && *(found + clen) != ','
	 && !grub_isspace (*(found + clen)))
	continue;

      /*
       * If found condition is at the start of debug or the start is on a word
       * boundary, then enable debug. Else if found condition is prefixed with
       * '-' and the start is on a word boundary, then disable debug. If none
       * of these cases, ignore.
       */
      if (found == debug || *(found - 1) == ',' || grub_isspace (*(found - 1)))
	ret = 1;
      else if (*(found - 1) == '-' && ((found == debug + 1) || (*(found - 2) == ','
			       || grub_isspace (*(found - 2)))))
	ret = 0;
    }

  return ret;
}

void
grub_real_dprintf (const char *file, const char *function, const int line, const char *condition,
		   const char *fmt, ...)
{
  va_list args;

  if (grub_debug_enabled (condition))
    {
      grub_printf ("%s:%s:%d:%s: ", file, function, line, condition);
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

#define PREALLOC_SIZE 255

int
grub_vprintf (const char *fmt, va_list ap)
{
  grub_size_t s;
  static char buf[PREALLOC_SIZE + 1];
  char *curbuf = buf;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  s = grub_vsnprintf_real (buf, PREALLOC_SIZE, fmt, &args);
  if (s > PREALLOC_SIZE)
    {
      curbuf = grub_malloc (s + 1);
      if (!curbuf)
	{
	  grub_errno = GRUB_ERR_NONE;
	  buf[PREALLOC_SIZE - 3] = '.';
	  buf[PREALLOC_SIZE - 2] = '.';
	  buf[PREALLOC_SIZE - 1] = '.';
	  buf[PREALLOC_SIZE] = 0;
	  curbuf = buf;
	}
      else
	s = grub_vsnprintf_real (curbuf, s, fmt, &args);
    }

  free_printf_args (&args);

  grub_xputs (curbuf);

  if (curbuf != buf)
    grub_free (curbuf);

  return s;
}

int
grub_memcmp (const void *s1, const void *s2, grub_size_t n)
{
  const grub_uint8_t *t1 = s1;
  const grub_uint8_t *t2 = s2;

  while (n--)
    {
      if (*t1 != *t2)
	return (int) *t1 - (int) *t2;

      t1++;
      t2++;
    }

  return 0;
}

int
grub_strcmp (const char *s1, const char *s2)
{
  while (*s1 && *s2)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t) *s2;
}

int
grub_strncmp (const char *s1, const char *s2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*s1 && *s2 && --n)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t)  *s2;
}

char *
grub_strchr (const char *s, int c)
{
  do
    {
      if (*s == c)
	return (char *) s;
    }
  while (*s++);

  return 0;
}

char *
grub_strrchr (const char *s, int c)
{
  char *p = NULL;

  do
    {
      if (*s == c)
	p = (char *) s;
    }
  while (*s++);

  return p;
}

int
grub_strword (const char *haystack, const char *needle)
{
  const char *n_pos = needle;

  while (grub_iswordseparator (*haystack))
    haystack++;

  while (*haystack)
    {
      /* Crawl both the needle and the haystack word we're on.  */
      while(*haystack && !grub_iswordseparator (*haystack)
            && *haystack == *n_pos)
        {
          haystack++;
          n_pos++;
        }

      /* If we reached the end of both words at the same time, the word
      is found. If not, eat everything in the haystack that isn't the
      next word (or the end of string) and "reset" the needle.  */
      if ( (!*haystack || grub_iswordseparator (*haystack))
         && (!*n_pos || grub_iswordseparator (*n_pos)))
        return 1;
      else
        {
          n_pos = needle;
          while (*haystack && !grub_iswordseparator (*haystack))
            haystack++;
          while (grub_iswordseparator (*haystack))
            haystack++;
        }
    }

  return 0;
}

char *
grub_strtok_r (char *s, const char *delim, char **save_ptr)
{
  char *token;
  const char *c;
  bool is_delim;

  if (s == NULL)
    s = *save_ptr;

  /* Scan leading delimiters. */
  while (*s != '\0')
    {
      is_delim = false;
      for (c = delim; *c != '\0'; c++)
	{
	  if (*s == *c)
	    {
	      is_delim = true;
	      break;
	    }
	}
      if (is_delim == true)
	s++;
      else
	break;
    }

  if (*s == '\0')
    {
      *save_ptr = s;
      return NULL;
    }

  /* Find the end of the token. */
  token = s;
  while (*s != '\0')
    {
      for (c = delim; *c != '\0'; c++)
	{
	  if (*s == *c)
	    {
	      *s = '\0';
	      *save_ptr = s + 1;
	      return token;
	    }
	}
      s++;
    }

  *save_ptr = s;
  return token;
}

char *
grub_strtok (char *s, const char *delim)
{
  static char *last;

  return grub_strtok_r (s, delim, &last);
}

int
grub_isspace (int c)
{
  return (c == '\n' || c == '\r' || c == ' ' || c == '\t');
}

unsigned long
grub_strtoul (const char * restrict str, const char ** const restrict end,
	      int base)
{
  unsigned long long num;

  num = grub_strtoull (str, end, base);
#if GRUB_CPU_SIZEOF_LONG != 8
  if (num > ~0UL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
      return ~0UL;
    }
#endif

  return (unsigned long) num;
}

unsigned long long
grub_strtoull (const char * restrict str, const char ** const restrict end,
	       int base)
{
  unsigned long long num = 0;
  int found = 0;

  /* Skip white spaces.  */
  /* grub_isspace checks that *str != '\0'.  */
  while (grub_isspace (*str))
    str++;

  /* Guess the base, if not specified. The prefix `0x' means 16, and
     the prefix `0' means 8.  */
  if (str[0] == '0')
    {
      if (str[1] == 'x')
	{
	  if (base == 0 || base == 16)
	    {
	      base = 16;
	      str += 2;
	    }
	}
      else if (base == 0 && str[1] >= '0' && str[1] <= '7')
	base = 8;
    }

  if (base == 0)
    base = 10;

  while (*str)
    {
      unsigned long digit;

      digit = grub_tolower (*str) - '0';
      if (digit >= 'a' - '0')
	digit += '0' - 'a' + 10;
      else if (digit > 9)
	break;

      if (digit >= (unsigned long) base)
	break;

      found = 1;

      /* NUM * BASE + DIGIT > ~0ULL */
      if (num > grub_divmod64 (~0ULL - digit, base, 0))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE,
		      N_("overflow is detected"));

          if (end)
            *end = (char *) str;

	  return ~0ULL;
	}

      num = num * base + digit;
      str++;
    }

  if (! found)
    {
      grub_error (GRUB_ERR_BAD_NUMBER,
		  N_("unrecognized number"));

      if (end)
        *end = (char *) str;

      return 0;
    }

  if (end)
    *end = (char *) str;

  return num;
}

char *
grub_strdup (const char *s)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s) + 1;
  p = (char *) grub_malloc (len);
  if (! p)
    return 0;

  return grub_memcpy (p, s, len);
}

char *
grub_strndup (const char *s, grub_size_t n)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s);
  if (len > n)
    len = n;
  p = (char *) grub_malloc (len + 1);
  if (! p)
    return 0;

  grub_memcpy (p, s, len);
  p[len] = '\0';
  return p;
}

/* clang detects that we're implementing here a memset so it decides to
   optimise and calls memset resulting in infinite recursion. With volatile
   we make it not optimise in this way.  */
#ifdef __clang__
#define VOLATILE_CLANG volatile
#else
#define VOLATILE_CLANG
#endif

void *
grub_memset (void *s, int c, grub_size_t len)
{
  void *p = s;
  grub_uint8_t pattern8 = c;

  if (len >= 3 * sizeof (unsigned long))
    {
      unsigned long patternl = 0;
      grub_size_t i;

      for (i = 0; i < sizeof (unsigned long); i++)
	patternl |= ((unsigned long) pattern8) << (8 * i);

      while (len > 0 && (((grub_addr_t) p) & (sizeof (unsigned long) - 1)))
	{
	  *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
	  p = (grub_uint8_t *) p + 1;
	  len--;
	}
      while (len >= sizeof (unsigned long))
	{
	  *(VOLATILE_CLANG unsigned long *) p = patternl;
	  p = (unsigned long *) p + 1;
	  len -= sizeof (unsigned long);
	}
    }

  while (len > 0)
    {
      *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
      p = (grub_uint8_t *) p + 1;
      len--;
    }

  return s;
}

grub_size_t
grub_strlen (const char *s)
{
  const char *p = s;

  while (*p)
    p++;

  return p - s;
}

static inline void
grub_reverse (char *str)
{
  char *p = str + grub_strlen (str) - 1;

  while (str < p)
    {
      char tmp;

      tmp = *str;
      *str = *p;
      *p = tmp;
      str++;
      p--;
    }
}

/* Divide N by D, return the quotient, and store the remainder in *R.  */
grub_uint64_t
grub_divmod64 (grub_uint64_t n, grub_uint64_t d, grub_uint64_t *r)
{
  /* This algorithm is typically implemented by hardware. The idea
     is to get the highest bit in N, 64 times, by keeping
     upper(N * 2^i) = (Q * D + M), where upper
     represents the high 64 bits in 128-bits space.  */
  unsigned bits = 64;
  grub_uint64_t q = 0;
  grub_uint64_t m = 0;

  /* ARM and IA64 don't have a fast 32-bit division.
     Using that code would just make us use software division routines, calling
     ourselves indirectly and hence getting infinite recursion.
  */
#if !GRUB_DIVISION_IN_SOFTWARE || defined(__mips__)
  /* Skip the slow computation if 32-bit arithmetic is possible.  */
  if (n < 0xffffffff && d < 0xffffffff)
    {
      if (r)
	*r = ((grub_uint32_t) n) % (grub_uint32_t) d;

      return ((grub_uint32_t) n) / (grub_uint32_t) d;
    }
#endif

  while (bits--)
    {
      m <<= 1;

      if (n & (1ULL << 63))
	m |= 1;

      q <<= 1;
      n <<= 1;

      if (m >= d)
	{
	  q |= 1;
	  m -= d;
	}
    }

  if (r)
    *r = m;

  return q;
}

/* Convert a long long value to a string. This function avoids 64-bit
   modular arithmetic or divisions.  */
static inline char *
grub_lltoa (char *str, int c, unsigned long long n)
{
  unsigned base = ((c == 'x') || (c == 'X')) ? 16 : ((c == 'o') ? 8 : 10);
  char *p;

  if ((long long) n < 0 && c == 'd')
    {
      n = 0ULL - n;
      *str++ = '-';
    }

  p = str;

  if (base == 16)
    do
      {
	unsigned d = (unsigned) (n & 0xf);
	*p++ = (d > 9) ? (d + ((c == 'x') ? 'a' : 'A') - 10) : d + '0';
      }
    while (n >>= 4);
  else if (base == 8)
    do
      {
	*p++ = ((unsigned) (n & 0x7)) + '0';
      }
    while (n >>= 3);
  else
    /* BASE == 10 */
    do
      {
	grub_uint64_t m;

	n = grub_divmod64 (n, 10, &m);
	*p++ = m + '0';
      }
    while (n);

  *p = 0;

  grub_reverse (str);
  return p;
}

/* A single scanner is shared by argument collection, validation and output.
   It never advances past NUL, including incomplete flags/width/lengths. */
struct printf_format
{
	grub_size_t width, precision;
	grub_size_t arg, width_arg, precision_arg;
	int type;
	char conversion, longfmt;
	char left, zero, sign, alternate, have_precision, positional;
	char dynamic_width, dynamic_precision;
};

static grub_size_t
printf_read_uint (const char **fmt)
{
	grub_size_t value = 0;

	while (grub_isdigit (**fmt))
	{
		unsigned digit = *(*fmt)++ - '0';

		/* Widths and precisions beyond the int return range cannot be
		   represented. Saturate without wrapping or changing grub_errno. */
		if (value > (GRUB_INT_MAX - digit) / 10)
			value = GRUB_INT_MAX;
		else
			value = value * 10 + digit;
	}
	return value;
}

/* Return a one-based position, or zero for a sequential argument. */
static grub_size_t
printf_read_position (const char **fmt, struct printf_format *spec)
{
	const char *start = *fmt;
	grub_size_t position;

	if (!grub_isdigit (**fmt))
		return 0;
	position = printf_read_uint (fmt);
	if (**fmt != '$')
	{
		*fmt = start;
		return 0;
	}
	(*fmt)++;
	spec->positional = 1;
	return position ? position : GRUB_SIZE_MAX;
}

static int
parse_printf_format (const char **fmt, struct printf_format *spec,
		     grub_size_t *nextarg)
{
	grub_size_t startarg = *nextarg;
	grub_size_t position;
	char c;

	grub_memset (spec, 0, sizeof (*spec));
	spec->type = UNUSED;
	position = printf_read_position (fmt, spec);
	for (;; (*fmt)++)
	{
		switch (**fmt)
		{
		case '-':
			spec->left = 1;
			break;
		case '0':
			spec->zero = 1;
			break;
		case '+':
			spec->sign = '+';
			break;
		case ' ':
			if (!spec->sign)
				spec->sign = ' ';
			break;
		case '#':
			spec->alternate = 1;
			break;
		default:
			goto width;
		}
	}
width:
	if (**fmt == '*')
	{
		grub_size_t index;

		(*fmt)++;
		spec->dynamic_width = 1;
		index = printf_read_position (fmt, spec);
		spec->width_arg = index ? index - 1 : *nextarg;
		(*nextarg)++;
	}
	else
		spec->width = printf_read_uint (fmt);
	if (**fmt == '.')
	{
		(*fmt)++;
		spec->have_precision = 1;
		if (**fmt == '*')
		{
			grub_size_t index;

			(*fmt)++;
			spec->dynamic_precision = 1;
			index = printf_read_position (fmt, spec);
			spec->precision_arg = index ? index - 1 : *nextarg;
			(*nextarg)++;
		}
		else
			spec->precision = printf_read_uint (fmt);
	}
	if (**fmt == 'z')
	{
		(*fmt)++;
		/* Equal widths do not make different integer types compatible. */
		spec->longfmt = _Generic ((size_t) 0,
			unsigned int: 0, unsigned long: 1, unsigned long long: 2);
	}
	else if (**fmt == 'l')
	{
		(*fmt)++;
		spec->longfmt = 1;
		if (**fmt == 'l')
		{
			(*fmt)++;
			spec->longfmt = 2;
		}
	}
	c = **fmt;
	if (!c)
	{
		*nextarg = startarg;
		return 0;
	}
	(*fmt)++;
	spec->conversion = c;
	switch (c)
	{
	case 'x':
	case 'X':
	case 'u':
	case 'o':
		spec->type = UNSIGNED_INT + spec->longfmt;
		break;
	case 'd':
		spec->type = INT + spec->longfmt;
		break;
	case 'p':
		spec->type = POINTER;
		if (**fmt == 'G')
		{
			(*fmt)++;
			spec->type = UUID;
		}
		break;
	case 's':
		spec->type = STRING;
		break;
	case 'c':
	case 'C':
		spec->type = INT;
		break;
	case 'f':
	case 'F':
	case 'e':
	case 'E':
	case 'g':
	case 'G':
		spec->type = DOUBLE;
		break;
	default:
		*nextarg = startarg;
		return 1;
	}
	spec->arg = position ? position - 1 : *nextarg;
	(*nextarg)++;
	return 1;
}

static int
printf_set_arg_type (struct printf_args *args, grub_size_t index, int type)
{
	if (index >= args->count)
		return 0;
	if (args->ptr[index].type != UNUSED && args->ptr[index].type != type)
		return 0;
	args->ptr[index].type = type;
	return 1;
}

/* Check mode also rejects positional arguments, including *m$, so untrusted
   formats cannot reinterpret a previously collected argument. */
static grub_err_t
parse_printf_arg_fmt (const char *fmt0, struct printf_args *args,
		      int fmt_check, grub_size_t max_args)
{
	const char *fmt;
	struct printf_format spec;
	grub_size_t n = 0;
	grub_size_t i;

	args->count = 0;
	COMPILE_TIME_ASSERT (sizeof (int) == sizeof (grub_uint32_t));
	COMPILE_TIME_ASSERT (sizeof (int) <= sizeof (long long));
	COMPILE_TIME_ASSERT (sizeof (long) <= sizeof (long long));
	/* Only %p rendering converts a pointer to an integer, after va_arg. */
	COMPILE_TIME_ASSERT (sizeof (grub_addr_t) >= sizeof (void *));
	COMPILE_TIME_ASSERT (sizeof (grub_addr_t) <= sizeof (unsigned long long));
	COMPILE_TIME_ASSERT (sizeof (double) == sizeof (long long));

	fmt = fmt0;
	while (*fmt)
	{
		if (*fmt++ != '%')
			continue;
		if (!parse_printf_format (&fmt, &spec, &n))
		{
			if (fmt_check)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "incomplete format");
			break;
		}
		if (fmt_check)
		{
			if (spec.positional)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "positional arguments are not supported");
			if (spec.type == UNUSED && (spec.conversion != '%'
				|| spec.dynamic_width || spec.dynamic_precision))
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "unexpected format");
			if (n > max_args)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "too many arguments");
		}
	}
	args->count = n;
	if (args->count <= ARRAY_SIZE (args->prealloc))
		args->ptr = args->prealloc;
	else
	{
		args->ptr = grub_calloc (args->count, sizeof (args->ptr[0]));
		if (!args->ptr)
		{
			if (fmt_check)
				return grub_errno;
			grub_errno = GRUB_ERR_NONE;
			args->ptr = args->prealloc;
			args->count = ARRAY_SIZE (args->prealloc);
		}
	}
	for (i = 0; i < args->count; i++)
		args->ptr[i].type = UNUSED;

	fmt = fmt0;
	n = 0;
	while (*fmt)
	{
		if (*fmt++ != '%')
			continue;
		if (!parse_printf_format (&fmt, &spec, &n))
			break;
		if (spec.type == UNUSED || spec.arg >= args->count
			|| (spec.dynamic_width && spec.width_arg >= args->count)
			|| (spec.dynamic_precision && spec.precision_arg >= args->count))
			continue;
		if (!printf_set_arg_type (args, spec.arg, spec.type)
			|| (spec.dynamic_width && !printf_set_arg_type (args, spec.width_arg, INT))
			|| (spec.dynamic_precision && !printf_set_arg_type (args, spec.precision_arg, INT)))
			goto fail;
	}
	/* Repeated positions do not introduce extra va_args. Gaps cannot be read
	   safely because the missing argument's type is unknown. */
	while (args->count && args->ptr[args->count - 1].type == UNUSED)
		args->count--;
	for (i = 0; i < args->count; i++)
		if (args->ptr[i].type == UNUSED)
			goto fail;
	return GRUB_ERR_NONE;
fail:
	args->count = 0;
	return GRUB_ERR_NONE;
}

static void
parse_printf_args (const char *fmt0, struct printf_args *args, va_list args_in)
{
	grub_size_t n;

	parse_printf_arg_fmt (fmt0, args, 0, 0);

	for (n = 0; n < args->count; n++)
	{
		switch (args->ptr[n].type)
		{
		case INT:
			args->ptr[n].ll = va_arg (args_in, int);
			break;
		case LONG:
			args->ptr[n].ll = va_arg (args_in, long);
			break;
		case LONGLONG:
			args->ptr[n].ll = va_arg (args_in, long long);
			break;
		case UNSIGNED_INT:
			args->ptr[n].ull = va_arg (args_in, unsigned int);
			break;
		case UNSIGNED_LONG:
			args->ptr[n].ull = va_arg (args_in, unsigned long);
			break;
		case UNSIGNED_LONGLONG:
			args->ptr[n].ull = va_arg (args_in, unsigned long long);
			break;
		case POINTER:
			args->ptr[n].ptr = va_arg (args_in, void *);
			break;
		case STRING:
			args->ptr[n].ptr = va_arg (args_in, const char *);
			break;
		case UUID:
			args->ptr[n].ptr = va_arg (args_in, const grub_packed_guid_t *);
			break;
		case DOUBLE:
			args->ptr[n].d = va_arg (args_in, double);
			break;
		case UNUSED:
			break;
		}
	}
}

static inline void __attribute__ ((always_inline))
write_char (char *str, grub_size_t *count, grub_size_t max_len, unsigned char ch)
{
  if (*count < max_len)
    str[*count] = ch;

  (*count)++;
}

static void
write_fill (char *str, grub_size_t *count, grub_size_t max_len,
	    grub_size_t fill, char c)
{
	if (*count < max_len)
	{
		grub_size_t available = max_len - *count;

		grub_memset (str + *count, c, fill < available ? fill : available);
	}
	*count += fill;
}

static void
write_number (char *str, grub_size_t *count, grub_size_t max_len,
	      const struct printf_format *spec, unsigned long long value)
{
	char tmp[32];
	const char *p = tmp;
	char sign = 0;
	char c = spec->conversion;
	const char *prefix = "";
	grub_size_t len, zeros = 0, fill, total, prefix_len = 0;

	if (c == 'p')
		c = 'x';
	len = grub_lltoa (tmp, c, value) - tmp;
	if (*p == '-')
	{
		sign = *p++;
		len--;
	}
	else if (c == 'd')
		sign = spec->sign;
	if (spec->have_precision)
	{
		if (!spec->precision && !value)
			len = 0;
		if (spec->precision > len)
			zeros = spec->precision - len;
	}
	if (spec->alternate && c == 'o' && ((!len) || (*p != '0' && !zeros)))
		zeros = 1;
	if (spec->conversion == 'p' || (spec->alternate && value && (c == 'x' || c == 'X')))
	{
		prefix = c == 'X' ? "0X" : "0x";
		prefix_len = 2;
	}
	total = len + zeros + prefix_len + (sign != 0);
	fill = spec->width > total ? spec->width - total : 0;
	if (!spec->left && (!spec->zero || spec->have_precision))
		write_fill (str, count, max_len, fill, ' ');
	if (sign)
		write_char (str, count, max_len, sign);
	while (*prefix)
		write_char (str, count, max_len, *prefix++);
	if (!spec->left && spec->zero && !spec->have_precision)
		write_fill (str, count, max_len, fill, '0');
	write_fill (str, count, max_len, zeros, '0');
	while (len--)
		write_char (str, count, max_len, *p++);
	if (spec->left)
		write_fill (str, count, max_len, fill, ' ');
}

static void
write_text (char *str, grub_size_t *count, grub_size_t max_len,
	    const struct printf_format *spec, const char *text, grub_size_t len)
{
	grub_size_t fill = spec->width > len ? spec->width - len : 0;

	if (!spec->left)
		write_fill (str, count, max_len, fill, ' ');
	while (len--)
		write_char (str, count, max_len, *text++);
	if (spec->left)
		write_fill (str, count, max_len, fill, ' ');
}

#define PRINTF_FLOAT_LIMBS	160
#define PRINTF_FLOAT_MAXPREC	1100
#define PRINTF_FLOAT_DIGITS	1440

struct ftoa_num
{
	grub_uint32_t d[PRINTF_FLOAT_LIMBS];
	int n;
};

static void
ftoa_set (struct ftoa_num *a, grub_uint64_t v)
{
	a->d[0] = (grub_uint32_t) v;
	a->d[1] = (grub_uint32_t) (v >> 32);
	a->n = a->d[1] ? 2 : (a->d[0] ? 1 : 0);
}

static void
ftoa_mul_u32 (struct ftoa_num *a, grub_uint32_t m)
{
	grub_uint64_t acc = 0;
	int i;

	for (i = 0; i < a->n; i++)
	{
		acc += (grub_uint64_t) a->d[i] * m;
		a->d[i] = (grub_uint32_t) acc;
		acc >>= 32;
	}
	if (acc && a->n < PRINTF_FLOAT_LIMBS)
		a->d[a->n++] = (grub_uint32_t) acc;
}

static void
ftoa_mul_pow5 (struct ftoa_num *a, unsigned p)
{
	static const grub_uint32_t p5[9] = {
		1, 5, 25, 125, 625, 3125, 15625, 78125, 390625
	};

	while (p >= 13)
	{
		ftoa_mul_u32 (a, 1220703125u);
		p -= 13;
	}
	while (p >= 8)
	{
		ftoa_mul_u32 (a, 390625u);
		p -= 8;
	}
	if (p)
		ftoa_mul_u32 (a, p5[p]);
}

static void
ftoa_shl (struct ftoa_num *a, unsigned bits)
{
	unsigned words, rem, i;
	grub_uint32_t carry;

	if (!bits || !a->n)
		return;
	words = bits / 32;
	rem = bits % 32;
	if (a->n + (int) words + (rem != 0) > PRINTF_FLOAT_LIMBS)
		return;
	if (rem)
	{
		carry = 0;
		for (i = 0; i < (unsigned) a->n; i++)
		{
			grub_uint32_t cur = a->d[i];
			a->d[i] = (cur << rem) | carry;
			carry = cur >> (32 - rem);
		}
		if (carry)
			a->d[a->n++] = carry;
	}
	if (words)
	{
		for (i = (unsigned) a->n; i-- > 0;)
			a->d[i + words] = a->d[i];
		for (i = 0; i < words; i++)
			a->d[i] = 0;
		a->n += (int) words;
	}
}

static int
ftoa_bit (const struct ftoa_num *a, unsigned bit)
{
	unsigned i = bit / 32;

	if (i >= (unsigned) a->n)
		return 0;
	return (a->d[i] >> (bit % 32)) & 1;
}

static int
ftoa_any_below (const struct ftoa_num *a, unsigned bit)
{
	unsigned w = bit / 32, rem = bit % 32, j;

	for (j = 0; j < w && j < (unsigned) a->n; j++)
		if (a->d[j])
			return 1;
	if (w < (unsigned) a->n && rem
	    && (a->d[w] & ((1U << rem) - 1)))
		return 1;
	return 0;
}

static void
ftoa_add1 (struct ftoa_num *a)
{
	int i;

	for (i = 0; i < a->n; i++)
		if (++a->d[i])
			return;
	if (a->n < PRINTF_FLOAT_LIMBS)
		a->d[a->n++] = 1;
}

static void
ftoa_shr_round (struct ftoa_num *a, unsigned bits)
{
	int round_up = 0;
	unsigned words, rem, i;

	if (!bits)
		return;
	if (ftoa_bit (a, bits - 1))
	{
		if (ftoa_any_below (a, bits - 1))
			round_up = 1;
		else
			round_up = ftoa_bit (a, bits);
	}
	words = bits / 32;
	rem = bits % 32;
	if (words >= (unsigned) a->n)
		a->n = 0;
	else
	{
		if (words)
		{
			for (i = 0; i < (unsigned) a->n - words; i++)
				a->d[i] = a->d[i + words];
			a->n -= (int) words;
		}
		if (rem && a->n)
		{
			grub_uint32_t carry = 0;
			for (i = (unsigned) a->n; i-- > 0;)
			{
				grub_uint32_t cur = a->d[i];
				a->d[i] = (cur >> rem) | (carry << (32 - rem));
				carry = cur & ((1U << rem) - 1);
			}
			while (a->n && !a->d[a->n - 1])
				a->n--;
		}
	}
	if (round_up)
		ftoa_add1 (a);
}

static grub_uint32_t
ftoa_div_u32 (struct ftoa_num *a, grub_uint32_t d)
{
	grub_uint64_t rem = 0;
	int i;

	for (i = a->n - 1; i >= 0; i--)
	{
		rem = (rem << 32) | a->d[i];
		a->d[i] = (grub_uint32_t) (rem / d);
		rem %= d;
	}
	while (a->n && !a->d[a->n - 1])
		a->n--;
	return (grub_uint32_t) rem;
}

static int
ftoa_to_dec (struct ftoa_num *a, char *buf, int cap)
{
	int pos = cap, n;

	if (!a->n)
	{
		if (cap > 0)
			buf[0] = '0';
		return 1;
	}
	while (a->n && pos > 0)
	{
		grub_uint32_t r = ftoa_div_u32 (a, 1000000000u);
		int j;

		for (j = 0; j < 9 && pos > 0 && (a->n || r); j++)
		{
			buf[--pos] = (char) ('0' + (r % 10));
			r /= 10;
		}
	}
	n = cap - pos;
	if (pos > 0)
		grub_memmove (buf, buf + pos, n);
	return n;
}

static int
ftoa_scale (char *buf, int cap, grub_uint64_t m, int e2, unsigned prec)
{
	struct ftoa_num a;
	int exp2;

	ftoa_set (&a, m);
	ftoa_mul_pow5 (&a, prec);
	exp2 = e2 + (int) prec;
	if (exp2 >= 0)
		ftoa_shl (&a, (unsigned) exp2);
	else
		ftoa_shr_round (&a, (unsigned) (-exp2));
	return ftoa_to_dec (&a, buf, cap);
}

static int
ftoa_log10_est (grub_uint64_t m, int e2)
{
	long long log2 = (long long) e2 + grub_log2ull (m);
	long long prod = log2 * 1292913986LL;
	long long q = prod / 4294967296LL;

	if (prod < 0 && q * 4294967296LL != prod)
		q--;
	return (int) q;
}

static int
round_at (char *d, int n, int keep, int *exp_adj)
{
	int i, up = 0;

	*exp_adj = 0;
	if (keep >= n)
		return n;
	if (keep <= 0)
		return 0;
	if (d[keep] > '5')
		up = 1;
	else if (d[keep] == '5')
	{
		for (i = keep + 1; i < n; i++)
			if (d[i] != '0')
			{
				up = 1;
				break;
			}
		if (!up)
			up = (d[keep - 1] & 1) != 0;
	}
	if (!up)
		return keep;
	for (i = keep - 1; i >= 0; i--)
	{
		if (d[i] != '9')
		{
			d[i]++;
			return keep;
		}
		d[i] = '0';
	}
	d[0] = '1';
	for (i = 1; i < keep; i++)
		d[i] = '0';
	*exp_adj = 1;
	return keep;
}

static int
ftoa_sigdigits (char *digits, int ndigits, int *exp10, grub_uint64_t m, int e2)
{
	int k, dlen = 1, tries, prev_k = -1;

	*exp10 = 0;
	if (!m)
	{
		grub_memset (digits, '0', ndigits);
		return ndigits;
	}
	k = ndigits - 1 - ftoa_log10_est (m, e2);
	if (k < 0)
		k = 0;
	if (k > PRINTF_FLOAT_MAXPREC)
		k = PRINTF_FLOAT_MAXPREC;
	for (tries = 0; tries < 8; tries++)
	{
		int i, pow10, k_exact, adj;

		if (k == prev_k)
			break;
		prev_k = k;
		dlen = ftoa_scale (digits, PRINTF_FLOAT_DIGITS, m, e2, (unsigned) k);
		if (dlen == 1 && digits[0] == '0')
		{
			if (k >= PRINTF_FLOAT_MAXPREC)
				break;
			k += ndigits > 1 ? ndigits : 1;
			if (k > PRINTF_FLOAT_MAXPREC)
				k = PRINTF_FLOAT_MAXPREC;
			continue;
		}
		*exp10 = dlen - 1 - k;
		if (dlen < ndigits)
		{
			if (k >= PRINTF_FLOAT_MAXPREC)
				break;
			k += ndigits - dlen;
			if (k > PRINTF_FLOAT_MAXPREC)
				k = PRINTF_FLOAT_MAXPREC;
			continue;
		}
		if (dlen == ndigits)
			return ndigits;
		pow10 = digits[0] == '1';
		for (i = 1; pow10 && i < dlen; i++)
			if (digits[i] != '0')
				pow10 = 0;
		if (dlen == ndigits + 1 && pow10)
		{
			grub_memset (digits + 1, '0', ndigits - 1);
			return ndigits;
		}
		k_exact = ndigits - 1 - *exp10;
		if (k_exact < 0)
		{
			/* Rounding at or left of the units place.  ftoa_scale
			   rounds its result to an integer, so rounding the
			   already-rounded digits here would round twice.  Scale
			   by enough to make value*10^k exact first: this case
			   only occurs for values >= 1, where -e2 is small. */
			int k_full = e2 < 0 ? -e2 : 0;

			if (k_full <= PRINTF_FLOAT_MAXPREC && k_full != k)
			{
				k = k_full;
				continue;
			}
			round_at (digits, dlen, ndigits, &adj);
			*exp10 += adj;
			return ndigits;
		}
		if (k_exact > PRINTF_FLOAT_MAXPREC)
			k_exact = PRINTF_FLOAT_MAXPREC;
		k = k_exact;
	}
	if (dlen < ndigits)
		grub_memset (digits + dlen, '0', ndigits - dlen);
	else if (dlen > ndigits)
	{
		int adj;

		round_at (digits, dlen, ndigits, &adj);
		*exp10 += adj;
	}
	return ndigits;
}

static grub_size_t
exp_chars (int exp10)
{
	unsigned ae = (unsigned) (exp10 < 0 ? -exp10 : exp10);

	return ae >= 100 ? 5 : 4;
}

static void
write_exp (char *str, grub_size_t *count, grub_size_t max_len, int exp10, int upper)
{
	unsigned ae = (unsigned) (exp10 < 0 ? -exp10 : exp10);

	write_char (str, count, max_len, upper ? 'E' : 'e');
	write_char (str, count, max_len, exp10 < 0 ? '-' : '+');
	if (ae >= 100)
		write_char (str, count, max_len, (char) ('0' + ae / 100));
	write_char (str, count, max_len, (char) ('0' + (ae / 10) % 10));
	write_char (str, count, max_len, (char) ('0' + ae % 10));
}

static void
write_digits (char *str, grub_size_t *count, grub_size_t max_len,
	      const char *digits, int n)
{
	while (n-- > 0)
		write_char (str, count, max_len, *digits++);
}

static void
write_float_pad (char *str, grub_size_t *count, grub_size_t max_len,
		 const struct printf_format *spec, char signch, grub_size_t len)
{
	grub_size_t total = len + (signch != 0);
	grub_size_t fill = spec->width > total ? spec->width - total : 0;

	if (!spec->left && !spec->zero)
		write_fill (str, count, max_len, fill, ' ');
	if (signch)
		write_char (str, count, max_len, signch);
	if (!spec->left && spec->zero)
		write_fill (str, count, max_len, fill, '0');
}

static void
write_float (char *str, grub_size_t *count, grub_size_t max_len,
	     const struct printf_format *spec, double value)
{
	char digits[PRINTF_FLOAT_DIGITS];
	grub_uint64_t bits, mant, m;
	int negative, biased, e2, exp10 = 0, upper, use_e, sig, dlen, ip;
	unsigned prec, ndigits, lead_zeros;
	grub_size_t extra_zeros = 0, fill, len;
	char signch = 0, conv = spec->conversion;

	grub_memcpy (&bits, &value, sizeof (bits));
	negative = (int) (bits >> 63);
	biased = (int) ((bits >> 52) & 0x7ff);
	mant = bits & 0xfffffffffffffULL;
	upper = conv == 'F' || conv == 'E' || conv == 'G';
	if (negative)
		signch = '-';
	else if (spec->sign)
		signch = spec->sign;
	if (biased == 0x7ff)
	{
		const char *lit = mant ? (upper ? "NAN" : "nan") : (upper ? "INF" : "inf");
		char tmp[8];
		grub_size_t n = 0;

		if (signch)
			tmp[n++] = signch;
		tmp[n++] = lit[0];
		tmp[n++] = lit[1];
		tmp[n++] = lit[2];
		write_text (str, count, max_len, spec, tmp, n);
		return;
	}
	prec = spec->have_precision ? (unsigned) spec->precision : 6;
	if ((conv == 'g' || conv == 'G') && !prec)
		prec = 1;
	if (prec > PRINTF_FLOAT_MAXPREC)
	{
		/* %g strips trailing zeros again, so only '#' needs them. */
		extra_zeros = (conv == 'g' || conv == 'G') && !spec->alternate
			? 0 : prec - PRINTF_FLOAT_MAXPREC;
		prec = PRINTF_FLOAT_MAXPREC;
	}
	if (biased == 0)
	{
		m = mant;
		e2 = -1074;
	}
	else
	{
		m = mant | (1ULL << 52);
		e2 = biased - 1023 - 52;
	}
	if (conv == 'f' || conv == 'F')
	{
		dlen = ftoa_scale (digits, PRINTF_FLOAT_DIGITS, m, e2, prec);
		if (!prec)
			len = (grub_size_t) dlen + (spec->alternate ? 1 : 0);
		else if (dlen <= (int) prec)
			len = 2 + prec;
		else
			len = (grub_size_t) dlen + 1;
		len += extra_zeros;
		write_float_pad (str, count, max_len, spec, signch, len);
		if (!prec)
		{
			write_digits (str, count, max_len, digits, dlen);
			if (spec->alternate)
				write_char (str, count, max_len, '.');
		}
		else if (dlen <= (int) prec)
		{
			write_char (str, count, max_len, '0');
			write_char (str, count, max_len, '.');
			write_fill (str, count, max_len, (grub_size_t) ((int) prec - dlen), '0');
			write_digits (str, count, max_len, digits, dlen);
		}
		else
		{
			ip = dlen - (int) prec;
			write_digits (str, count, max_len, digits, ip);
			write_char (str, count, max_len, '.');
			write_digits (str, count, max_len, digits + ip, (int) prec);
		}
		write_fill (str, count, max_len, extra_zeros, '0');
	}
	else if (conv == 'e' || conv == 'E')
	{
		ndigits = prec + 1;
		ftoa_sigdigits (digits, (int) ndigits, &exp10, m, e2);
		len = 1;
		if (prec || spec->alternate)
			len += 1 + prec;
		len += extra_zeros + exp_chars (exp10);
		write_float_pad (str, count, max_len, spec, signch, len);
		write_char (str, count, max_len, digits[0]);
		if (prec || spec->alternate)
		{
			write_char (str, count, max_len, '.');
			if (prec)
				write_digits (str, count, max_len, digits + 1, (int) prec);
		}
		write_fill (str, count, max_len, extra_zeros, '0');
		write_exp (str, count, max_len, exp10, upper);
	}
	else
	{
		ndigits = prec;
		ftoa_sigdigits (digits, (int) ndigits, &exp10, m, e2);
		sig = (int) ndigits;
		if (!spec->alternate)
			while (sig > 1 && digits[sig - 1] == '0')
				sig--;
		use_e = exp10 < -4 || exp10 >= (int) prec;
		if (use_e)
		{
			len = 1;
			if (sig > 1 || spec->alternate)
				len += 1 + (grub_size_t) (sig - 1);
			len += extra_zeros + exp_chars (exp10);
			write_float_pad (str, count, max_len, spec, signch, len);
			write_char (str, count, max_len, digits[0]);
			if (sig > 1 || spec->alternate)
			{
				write_char (str, count, max_len, '.');
				if (sig > 1)
					write_digits (str, count, max_len, digits + 1, sig - 1);
			}
			write_fill (str, count, max_len, extra_zeros, '0');
			write_exp (str, count, max_len, exp10, upper);
		}
		else if (exp10 >= 0)
		{
			ip = exp10 + 1;
			if (ip >= sig)
			{
				len = (grub_size_t) ip + (spec->alternate ? 1 : 0) + extra_zeros;
				write_float_pad (str, count, max_len, spec, signch, len);
				write_digits (str, count, max_len, digits, sig);
				write_fill (str, count, max_len, (grub_size_t) (ip - sig), '0');
				if (spec->alternate)
					write_char (str, count, max_len, '.');
				write_fill (str, count, max_len, extra_zeros, '0');
			}
			else
			{
				len = (grub_size_t) sig + 1 + extra_zeros;
				write_float_pad (str, count, max_len, spec, signch, len);
				write_digits (str, count, max_len, digits, ip);
				write_char (str, count, max_len, '.');
				write_digits (str, count, max_len, digits + ip, sig - ip);
				write_fill (str, count, max_len, extra_zeros, '0');
			}
		}
		else
		{
			lead_zeros = (unsigned) (-exp10 - 1);
			len = 2 + lead_zeros + (grub_size_t) sig + extra_zeros;
			write_float_pad (str, count, max_len, spec, signch, len);
			write_char (str, count, max_len, '0');
			write_char (str, count, max_len, '.');
			write_fill (str, count, max_len, lead_zeros, '0');
			write_digits (str, count, max_len, digits, sig);
			write_fill (str, count, max_len, extra_zeros, '0');
		}
	}
	if (spec->left)
	{
		len += signch != 0;
		fill = spec->width > len ? spec->width - len : 0;
		write_fill (str, count, max_len, fill, ' ');
	}
}

static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args)
{
	grub_size_t n = 0;
	grub_size_t count = 0;
	const char *fmt = fmt0;

	while (*fmt)
	{
		struct printf_format spec;
		char c = *fmt++;

		if (c != '%')
		{
			write_char (str, &count, max_len, c);
			continue;
		}
		if (!parse_printf_format (&fmt, &spec, &n))
			break;
		c = spec.conversion;
		if (c == '%')
		{
			write_char (str, &count, max_len, c);
			continue;
		}
		if (spec.type == UNUSED || spec.arg >= args->count)
			continue;
		if (spec.dynamic_width)
		{
			int width;

			if (spec.width_arg >= args->count)
				continue;
			width = (int) args->ptr[spec.width_arg].ll;
			if (width < 0)
			{
				spec.left = 1;
				spec.width = 0U - (unsigned) width;
			}
			else
				spec.width = (unsigned) width;
		}
		if (spec.dynamic_precision)
		{
			int precision;

			if (spec.precision_arg >= args->count)
				continue;
			precision = (int) args->ptr[spec.precision_arg].ll;
			spec.have_precision = precision >= 0;
			if (spec.have_precision)
				spec.precision = (unsigned) precision;
		}
		switch (c)
		{
		case 'p':
			if (spec.type == UUID)
			{
				const grub_packed_guid_t *guid = args->ptr[spec.arg].ptr;
				struct printf_format field;
				unsigned i;

				if (!guid)
				{
					write_text (str, &count, max_len, &spec, "(null)", 6);
					break;
				}
				grub_memset (&field, 0, sizeof (field));
				field.zero = 1;
				field.conversion = 'x';
				field.width = 8;
				write_number (str, &count, max_len, &field, guid->data1);
				write_char (str, &count, max_len, '-');
				field.width = 4;
				write_number (str, &count, max_len, &field, guid->data2);
				write_char (str, &count, max_len, '-');
				write_number (str, &count, max_len, &field, guid->data3);
				field.width = 2;
				for (i = 0; i < 8; i++)
				{
					if (i == 0 || i == 2)
						write_char (str, &count, max_len, '-');
					write_number (str, &count, max_len, &field, guid->data4[i]);
				}
				break;
			}
			write_number (str, &count, max_len, &spec,
				(grub_addr_t) args->ptr[spec.arg].ptr);
			break;
		case 'd':
			write_number (str, &count, max_len, &spec,
				(unsigned long long) args->ptr[spec.arg].ll);
			break;
		case 'x':
		case 'X':
		case 'u':
		case 'o':
			write_number (str, &count, max_len, &spec, args->ptr[spec.arg].ull);
			break;
		case 'c':
		{
			char ch = args->ptr[spec.arg].ll & 0xff;

			write_text (str, &count, max_len, &spec, &ch, 1);
			break;
		}
		case 'C':
		{
			grub_uint32_t code = args->ptr[spec.arg].ll;
			int shift;
			unsigned mask;
			char encoded[4];
			grub_size_t len = 0;

			if (code <= 0x7f)
			{
				shift = 0;
				mask = 0;
			}
			else if (code <= 0x7ff)
			{
				shift = 6;
				mask = 0xc0;
			}
			else if (code <= 0xffff)
			{
				shift = 12;
				mask = 0xe0;
			}
			else if (code <= 0x10ffff)
			{
				shift = 18;
				mask = 0xf0;
			}
			else
			{
				code = '?';
				shift = 0;
				mask = 0;
			}
			encoded[len++] = mask | (code >> shift);
			for (shift -= 6; shift >= 0; shift -= 6)
				encoded[len++] = 0x80 | (0x3f & (code >> shift));
			write_text (str, &count, max_len, &spec, encoded, len);
			break;
		}
		case 'f':
		case 'F':
		case 'e':
		case 'E':
		case 'g':
		case 'G':
			write_float (str, &count, max_len, &spec, args->ptr[spec.arg].d);
			break;
		case 's':
		{
			grub_size_t len = 0;
			const char *p = args->ptr[spec.arg].ptr;

			if (!p)
				p = "(null)";

			while ((!spec.have_precision || len < spec.precision) && p[len])
				len++;
			write_text (str, &count, max_len, &spec, p, len);
			break;
		}
		}
	}
	str[count < max_len ? count : max_len] = '\0';
	return count;
}

int
grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap)
{
  grub_size_t ret;
  struct printf_args args;

  if (!n)
    return 0;

  n--;

  parse_printf_args (fmt, &args, ap);

  ret = grub_vsnprintf_real (str, n, fmt, &args);

  free_printf_args (&args);

  return ret;
}

int
grub_snprintf (char *str, grub_size_t n, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vsnprintf (str, n, fmt, ap);
  va_end (ap);

  return ret;
}

char *
grub_xvasprintf (const char *fmt, va_list ap)
{
  grub_size_t s, as = PREALLOC_SIZE;
  char *ret;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  while (1)
    {
      ret = grub_malloc (as + 1);
      if (!ret)
	{
	  free_printf_args (&args);
	  return NULL;
	}

      s = grub_vsnprintf_real (ret, as, fmt, &args);

      if (s <= as)
	{
	  free_printf_args (&args);
	  return ret;
	}

      grub_free (ret);
      as = s;
    }
}

char *
grub_xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *ret;

  va_start (ap, fmt);
  ret = grub_xvasprintf (fmt, ap);
  va_end (ap);

  return ret;
}

grub_err_t
grub_printf_fmt_check (const char *fmt, const char *fmt_expected)
{
  struct printf_args args_expected, args_fmt;
  grub_err_t ret;
  grub_size_t n;

  if (fmt == NULL || fmt_expected == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid format");

  ret = parse_printf_arg_fmt (fmt_expected, &args_expected, 1, GRUB_SIZE_MAX);
  if (ret != GRUB_ERR_NONE)
    return ret;

  /* Limit parsing to the number of expected arguments. */
  ret = parse_printf_arg_fmt (fmt, &args_fmt, 1, args_expected.count);
  if (ret != GRUB_ERR_NONE)
    {
      free_printf_args (&args_expected);
      return ret;
    }

  for (n = 0; n < args_fmt.count; n++)
    if (args_fmt.ptr[n].type != args_expected.ptr[n].type)
     {
	ret = grub_error (GRUB_ERR_BAD_ARGUMENT, "arguments types do not match");
	break;
     }

  free_printf_args (&args_expected);
  free_printf_args (&args_fmt);

  return ret;
}


/* Abort GRUB. This function does not return.  */
void __attribute__ ((noreturn))
grub_abort (void)
{
  grub_printf ("\nAborted.");

#ifndef GRUB_UTIL
  if (grub_term_inputs)
#endif
    {
      grub_printf (" Press any key to exit.");
      grub_getkey ();
    }

  grub_exit ();
}

void
grub_fatal (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  grub_vprintf (_(fmt), ap);
  va_end (ap);

  grub_refresh ();

  grub_abort ();
}

grub_ssize_t
grub_utf8_to_utf16_alloc (const char *str8, grub_uint16_t **utf16_msg, grub_uint16_t **last_position)
{
  grub_size_t len;
  grub_size_t len16;

  len = grub_strlen (str8);

  /* Check for integer overflow */
  if (len > GRUB_SSIZE_MAX / GRUB_MAX_UTF16_PER_UTF8 - 1)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("string too long"));
      *utf16_msg = NULL;
      return -1;
    }

  len16 = len * GRUB_MAX_UTF16_PER_UTF8;

  *utf16_msg = grub_calloc (len16 + 1, sizeof (*utf16_msg[0]));
  if (*utf16_msg == NULL)
    return -1;

  len16 = grub_utf8_to_utf16 (*utf16_msg, len16, (grub_uint8_t *) str8, len, NULL);

  if (last_position != NULL)
    *last_position = *utf16_msg + len16;

  return len16;
}


#if BOOT_TIME_STATS

#include <grub/time.h>

struct grub_boot_time *grub_boot_time_head;
static struct grub_boot_time **boot_time_last = &grub_boot_time_head;

void
grub_real_boot_time (const char *file,
		     const int line,
		     const char *fmt, ...)
{
  struct grub_boot_time *n;
  va_list args;

  grub_error_push ();
  n = grub_malloc (sizeof (*n));
  if (!n)
    {
      grub_errno = 0;
      grub_error_pop ();
      return;
    }
  n->file = file;
  n->line = line;
  n->tp = grub_get_time_ms ();
  n->next = 0;

  va_start (args, fmt);
  n->msg = grub_xvasprintf (fmt, args);
  va_end (args);

  *boot_time_last = n;
  boot_time_last = &n->next;

  grub_errno = 0;
  grub_error_pop ();
}
#endif
