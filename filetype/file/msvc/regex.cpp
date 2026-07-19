/* SPDX-License-Identifier: LGPL-3.0-or-later */
#include "regex.h"

#include <cstring>
#include <regex>
#include <string>

struct fx_regex_state
{
	std::regex regex;
};

extern "C" int regcomp(regex_t *preg, const char *pattern, int cflags)
{
	try
	{
		std::regex_constants::syntax_option_type flags = std::regex_constants::extended;

		if ((cflags & REG_ICASE) != 0)
			flags |= std::regex_constants::icase;

		fx_regex_state *state = new fx_regex_state{std::regex(pattern, flags)};
		preg->opaque = state;
		preg->cflags = cflags;
		return 0;
	}
	catch (const std::bad_alloc &)
	{
		return REG_ESPACE;
	}
	catch (const std::regex_error &)
	{
		preg->opaque = nullptr;
		return REG_BADPAT;
	}
}

extern "C" int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags)
{
	const fx_regex_state *state = static_cast<const fx_regex_state *>(preg->opaque);
	std::cmatch match;
	std::regex_constants::match_flag_type flags = std::regex_constants::match_default;

	if (!state)
		return REG_BADPAT;
	if ((eflags & REG_NOTBOL) != 0)
		flags |= std::regex_constants::match_not_bol;
	if ((eflags & REG_NOTEOL) != 0)
		flags |= std::regex_constants::match_not_eol;

	if (!std::regex_search(string, match, state->regex, flags))
		return REG_NOMATCH;

	if ((preg->cflags & REG_NOSUB) == 0 && nmatch != 0 && pmatch)
	{
		size_t count = match.size() < nmatch ? match.size() : nmatch;

		for (size_t i = 0; i < count; i++)
		{
			pmatch[i].rm_so = match[i].matched ? static_cast<regoff_t>(match.position(i)) : -1;
			pmatch[i].rm_eo = match[i].matched ? static_cast<regoff_t>(match.position(i) + match.length(i)) : -1;
		}
		for (size_t i = count; i < nmatch; i++)
		{
			pmatch[i].rm_so = -1;
			pmatch[i].rm_eo = -1;
		}
	}

	return 0;
}

extern "C" size_t regerror(int errcode, const regex_t *, char *errbuf, size_t errbuf_size)
{
	const char *message = "regex error";

	switch (errcode)
	{
	case 0:
		message = "no error";
		break;
	case REG_NOMATCH:
		message = "no match";
		break;
	case REG_BADPAT:
		message = "bad pattern";
		break;
	case REG_ESPACE:
		message = "out of memory";
		break;
	default:
		break;
	}

	if (errbuf_size != 0 && errbuf)
	{
		strncpy_s(errbuf, errbuf_size, message, _TRUNCATE);
	}

	return strlen(message) + 1;
}

extern "C" void regfree(regex_t *preg)
{
	delete static_cast<fx_regex_state *>(preg->opaque);
	preg->opaque = nullptr;
}
