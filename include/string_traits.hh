#pragma once

#include "string_view.hh"

constexpr bool has_prefix(StringView str, StringView prefix) noexcept {
	return (str.compare(0, prefix.size(), prefix) == 0);
}

template <class... T>
constexpr bool has_one_of_prefixes(StringView str, T&&... prefixes) noexcept {
	return (... or has_prefix(str, std::forward<T>(prefixes)));
}

constexpr bool has_suffix(StringView str, StringView suffix) noexcept {
	return (str.size() >= suffix.size() and
	        str.compare(str.size() - suffix.size(), suffix.size(), suffix) ==
	           0);
}

template <class... T>
constexpr bool has_one_of_suffixes(StringView str, T&&... suffixes) noexcept {
	return (... or has_suffix(str, std::forward<T>(suffixes)));
}

constexpr bool is_digit(int c) noexcept { return ('0' <= c and c <= '9'); }

constexpr bool is_digit(StringView str) noexcept {
	if (str.empty())
		return false;

	for (char c : str) {
		if (not is_digit(c))
			return false;
	}

	return true;
}

constexpr bool is_alpha(int c) noexcept {
	return (('A' <= c and c <= 'Z') or ('a' <= c and c <= 'z'));
}

constexpr bool is_alpha(StringView str) noexcept {
	if (str.empty())
		return false;

	for (char c : str) {
		if (not is_alpha(c))
			return false;
	}

	return true;
}

constexpr bool is_alnum(int c) noexcept { return (is_alpha(c) or is_digit(c)); }

constexpr bool is_alnum(StringView str) noexcept {
	if (str.empty())
		return false;

	for (char c : str) {
		if (not is_alnum(c))
			return false;
	}

	return true;
}

constexpr bool is_word(int c) noexcept {
	return (is_alnum(c) or c == '_' or c == '-');
}

constexpr bool is_word(StringView str) noexcept {
	if (str.empty())
		return false;

	for (char c : str) {
		if (not is_word(c))
			return false;
	}

	return true;
}

/**
 * @brief Check whether string @p str is an integer
 * @details Equivalent to check id string matches regex \-?[0-9]+
 *   Notes:
 *   - empty string is not an integer
 *   - sign is not an integer
 *
 * @param str string
 *
 * @return result - whether string @p str is an integer
 */

constexpr bool is_integer(StringView str) noexcept {
	if (str.empty())
		return false;

	if (str[0] == '-')
		str.remove_prefix(1);

	return is_digit(str);
}

constexpr bool is_real(StringView str) noexcept {
	if (str.empty())
		return false;

	if (str.front() == '-')
		str.remove_prefix(1);

	size_t dot_pos = str.find('.');
	if (dot_pos >= str.size())
		return is_digit(str);

	return (is_digit(str.substring(0, dot_pos)) and
	        is_digit(str.substring(dot_pos + 1)));
}