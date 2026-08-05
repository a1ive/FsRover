/* Optparse --- portable, reentrant, embeddable, getopt-like option parser
 *
 * This is free and unencumbered software released into the public domain.
 *
 * To get the implementation, define OPTPARSE_IMPLEMENTATION.
 * Optionally define OPTPARSE_API to control the API's visibility
 * and/or linkage (static, __attribute__, __declspec).
 *
 * The POSIX getopt() option parser has three fatal flaws. These flaws
 * are solved by Optparse.
 *
 * 1) Parser state is stored entirely in global variables, some of
 * which are static and inaccessible. This means only one thread can
 * use getopt(). It also means it's not possible to recursively parse
 * nested sub-arguments while in the middle of argument parsing.
 * Optparse fixes this by storing all state on a local struct.
 *
 * 2) The POSIX standard provides no way to properly reset the parser.
 * This means for portable code that getopt() is only good for one
 * run, over one argv with one option string. It also means subcommand
 * options cannot be processed with getopt(). Most implementations
 * provide a method to reset the parser, but it's not portable.
 * Optparse provides an optparse_arg() function for stepping over
 * subcommands and continuing parsing of options with another option
 * string. The Optparse struct itself can be passed around to
 * subcommand handlers for additional subcommand option parsing. A
 * full reset can be achieved by with an additional optparse_init().
 *
 * 3) Error messages are printed to stderr. This can be disabled with
 * opterr, but the messages themselves are still inaccessible.
 * Optparse solves this by writing an error message in its errmsg
 * field. The downside to Optparse is that this error message will
 * always be in English rather than the current locale.
 *
 * Optparse should be familiar with anyone accustomed to getopt(), and
 * it could be a nearly drop-in replacement. The option string is the
 * same and the fields have the same names as the getopt() global
 * variables (optarg, optind, optopt).
 *
 * Optparse also supports GNU-style long options with optparse_long().
 * The interface is slightly different and simpler than getopt_long().
 *
 * By default, argv is permuted as it is parsed, moving non-option
 * arguments to the end. This can be disabled by setting the `permute`
 * field to 0 after initialization.
 *
 * Rover: ported to UTF-16, the encoding Win32 hands out through
 * CommandLineToArgvW, so a path never loses characters on its way to
 * the parser. Long options also accept the Windows "/name" spelling
 * and short names match case-insensitively.
 */
#ifndef OPTPARSE_H
#define OPTPARSE_H

#include <wchar.h>

#ifndef OPTPARSE_API
#define OPTPARSE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* optparse() returns one of these instead of an option index.  */
#define OPTPARSE_ERR (-2)
#define OPTPARSE_DONE (-1)

struct optparse
{
	wchar_t **argv;
	int permute;
	int optind;
	int optopt;
	wchar_t *optarg;
	wchar_t errmsg[64];
	int subopt;
};

enum optparse_argtype
{
	OPTPARSE_NONE,
	OPTPARSE_REQUIRED,
	OPTPARSE_OPTIONAL
};

struct optparse_option
{
	const wchar_t *longname;
	int shortname;
	enum optparse_argtype argtype;
};

/**
 * Initializes the parser state.
 */
OPTPARSE_API
void optparse_init(struct optparse *options, wchar_t **argv);

/**
 * Handles GNU-style long options in addition to getopt() options.
 * This works a lot like GNU's getopt_long(). The last option in
 * longopts must be all zeros, marking the end of the array. The
 * longindex argument may be NULL.
 *
 * @return the zero-based index in the longopts array,
 *         OPTPARSE_DONE for done, or OPTPARSE_ERR for error.
 */
OPTPARSE_API
int optparse(struct optparse *options,
			 const struct optparse_option *longopts,
			 int *longindex);

/**
 * Used for stepping over non-option arguments.
 * @return the next non-option argument, or NULL for no more arguments
 *
 * Argument parsing can continue with optparse() after using this
 * function. That would be used to parse the options for the
 * subcommand returned by optparse_arg(). This function allows you to
 * ignore the value of optind.
 */
OPTPARSE_API
wchar_t *optparse_arg(struct optparse *options);

#ifdef __cplusplus
}
#endif

#endif /* OPTPARSE_H */
