#ifndef CLIROVER_EXTRACT_H
#define CLIROVER_EXTRACT_H	1

#include <string>
#include <vector>

struct extract_result
{
	unsigned long long files = 0;
	unsigned long long bytes = 0;
	unsigned long long links = 0;
};

bool extract_paths (const std::vector<std::string> &sources,
	const std::wstring &destination, extract_result *result, std::string *error);

#endif /* ! CLIROVER_EXTRACT_H */
