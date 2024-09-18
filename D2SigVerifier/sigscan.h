#pragma once
#include "rtti.h"
#include <array>
#include <string_view>

// Boyer-Moore-Horspool with wildcards implementation
static std::array<size_t, 256> FillShiftTable(std::string_view pattern, const uint8_t wildcard) {
	std::array<size_t, 256> bad_char_skip = {};
	size_t idx = 0;
	const size_t last = pattern.size() - 1;

	// Get last wildcard position
	for (idx = last; idx > 0 && (uint8_t)pattern[idx] != wildcard; --idx);
	size_t diff = last - idx;
	if (diff == 0)
		diff = 1;

	// Prepare shift table
	for (idx = 0; idx < 256; ++idx)
		bad_char_skip[idx] = diff;
	for (idx = last - diff; idx < last; ++idx)
		bad_char_skip[(uint8_t)pattern[idx]] = last - idx;
	return bad_char_skip;
}

static std::string ParseCombo(std::string_view combo)
{
	const size_t patternLen = (combo.size() + 1) / 3;
	std::string pattern;
	pattern.reserve(patternLen);

	int index = 0;
	for (unsigned int i = 0; i < combo.size(); i++)
	{
		if (combo[i] == ' ')
			continue;
		else if (combo[i] == '?')
		{
			pattern += '\xCC';
			i += 1;
		}
		else
		{
			pattern += (char)strtol(&combo[i], 0, 16);
			i += 2;
		}
	}
	return pattern;
}

template<typename T>
static T PatternScan(T begin, T end, std::string_view pattern)
{
	const size_t last = pattern.size() - 1;
	const auto bad_char_skip = FillShiftTable(pattern, 0xCC);

	// Search
	for (; begin <= end; begin += bad_char_skip[begin[last]])
		for (size_t idx = last; idx >= 0; --idx) {
			const uint8_t elem = pattern[idx];
			if (elem != 0xCC && elem != begin[idx])
				break;

			if (idx == 0)
				return begin;
		}

	return nullptr;
}


static uintptr_t PatternScanInSection(const rtti::PEImage& image, std::string_view section, std::string_view pattern)
{
	using namespace std::literals::string_view_literals;

	const auto begin = (uintptr_t)image.data.data();

	uint8_t* scanPos = nullptr, * scanEnd = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(image.pNTHeaders);
	auto sec = image.GetSection(section);
	if (!sec) return 0;

	scanPos = (uint8_t*)((uintptr_t)image.data.data() + sec->PointerToRawData);
	scanEnd = scanPos + sec->SizeOfRawData - pattern.size();

	return (uintptr_t)PatternScan(scanPos, scanEnd, pattern);
}