#pragma once

#include "inplace_buff.hh"

/**
 * @brief Concentrates @p args into std::string
 *
 * @param args string-like objects
 *
 * @return concentration of @p args
 */
template <size_t IBUFF_SIZE = 4096, class... Args>
constexpr auto concat(Args&&... args) {
	InplaceBuff<IBUFF_SIZE> res;
	res.append(std::forward<Args>(args)...);
	return res;
}
