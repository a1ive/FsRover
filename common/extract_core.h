#ifndef ROVER_EXTRACT_H
#define ROVER_EXTRACT_H	1

#include <functional>
#include <string>
#include <vector>

namespace rover_extract
{

enum class progress_kind
{
	started,
	advanced,
	completed,
	failed
};

struct progress
{
	progress_kind kind;
	unsigned long long file_index;
	unsigned long long file_total;
	int percent;
	const std::string &source;
};

struct options
{
	bool preserve_times = true;
	std::function<bool ()> cancelled;
	std::function<void ()> service;
	std::function<void (const progress &)> report_progress;
};

struct result
{
	unsigned long long files = 0;
	unsigned long long bytes = 0;
	unsigned long long links = 0;
	std::vector<std::string> errors;
};

bool extract (const std::vector<std::string> &sources,
	const std::wstring &destination, const options &opts,
	result *stats, std::string *error);

} /* namespace rover_extract */

#endif /* ! ROVER_EXTRACT_H */
