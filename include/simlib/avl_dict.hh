#pragma once

#include "simlib/debug.hh"
#include "simlib/meta.hh"
#include "simlib/repeating.hh"

#include <cassert>
#include <optional>
#include <vector>

template <class size_type>
struct AVLNodeBase {
	static constexpr int L = 0; // left
	static constexpr int R = 1; // right

	std::array<size_type, 2> kid;
	uint8_t h;

	AVLNodeBase(size_type left_kid, size_type right_kid, uint8_t height)
	: kid{{left_kid, right_kid}}
	, h{height} {}
};

/// To use within AVLDictionary only
template <class T, class size_type = size_t>
class AVLPoolAllocator {
	using AVLNB = AVLNodeBase<size_type>;
	static_assert(std::is_base_of<AVLNB, T>::value,
	              "T has to derive from AVLNodeBase");

	union Elem {
		size_type ptr;
		T val;

		// NOLINTNEXTLINE(modernize-use-equals-default): val is manually managed
		Elem() {}
		Elem(const Elem&) = delete;
		Elem(Elem&&) = delete;
		Elem& operator=(const Elem&) = delete;
		Elem& operator=(Elem&&) = delete;
		// NOLINTNEXTLINE(modernize-use-equals-default): val is manually managed
		~Elem() {}
	};

	std::unique_ptr<Elem[]> data;
	size_type capacity_ = 0;
	size_type head = 0;

	template <class Array>
	static T& elem(Array& arr, size_type i) {
		return arr[i].val;
	}

	T& elem(size_type i) { return elem(data, i); }

	[[nodiscard]] const T& elem(size_type i) const { return elem(data, i); }

	template <class Array>
	static size_type& ptr(Array& arr, size_type i) {
		return arr[i].ptr;
	}

	size_type& ptr(size_type i) { return ptr(data, i); }

	[[nodiscard]] const size_type& ptr(size_type i) const {
		return ptr(data, i);
	}

public:
	struct AssertAllIsDeallocated {};

	AVLPoolAllocator()
	: data(new Elem[1])
	, capacity_(1) {
		ptr(0) = 1;
	}

	// Provides strong exception guarantee
	AVLPoolAllocator(const AVLPoolAllocator& apa)
	: data(new Elem[apa.capacity_])
	, capacity_(apa.capacity_)
	, head(apa.head) {
		// Initialize pool -> unallocated nodes will have value
		// max_capacity()
		for (size_type i = 0; i < capacity(); ++i) {
			ptr(i) = 0;
		}
		for (size_type i = head; i != capacity(); i = apa.ptr(i)) {
			ptr(i) = max_capacity();
		}

		// Update pool -> copy allocated nodes and initialize
		// unallocated nodes
		auto emergency_destruct = [&](int beg) {
			for (size_type i = beg; i < capacity(); ++i) {
				if (i == head) { // unallocated
					head = ptr(i); // next unallocated
				} else {
					elem(i).~T();
				}
			}
		};

		head = capacity();
		for (size_type i = capacity() - 1; i > 0; --i) {
			if (ptr(i) == max_capacity()) {
				ptr(i) = head;
				head = i;
			} else {
				try {
					::new (&elem(i)) T(apa.elem(i));
				} catch (...) {
					// Need to deallocate already copied elements
					emergency_destruct(i + 1);
					throw;
				}
			}
		}

		// 0 element has to be copied in a different way
		if (ptr(0) == max_capacity()) {
			ptr(0) = head;
			head = 0;
		} else {
			try {
				::new (&elem(0)) AVLNB(reinterpret_cast<AVLNB&>(data[0]));
			} catch (...) {
				// Need to deallocate already copied elements
				emergency_destruct(1);
				throw;
			}
		}
	}

	// Provides strong exception guarantee
	AVLPoolAllocator& operator=(const AVLPoolAllocator& apa) {
		*this = AVLPoolAllocator(apa);
	}

	// After moving out @p apa should be reinitialized (e.g. apa =
	// {}), before using it in any way other than destructing
	AVLPoolAllocator(AVLPoolAllocator&& apa) noexcept
	: data(std::move(apa.data))
	, capacity_(apa.capacity_)
	, head(apa.head) {
		apa.capacity_ = 0;
		// apa.head = 0; // It is not necessary to set head
	}

	// After moving out @p apa should be reinitialized (e.g. apa =
	// {}), before using it in any way other than destructing
	AVLPoolAllocator& move_assign(AVLPoolAllocator&& apa,
	                              AssertAllIsDeallocated /*unused*/) noexcept {
		// As there is nothing to destruct we can proceed to moving
		// the data
		data = std::move(apa.data);
		capacity_ = apa.capacity_;
		head = apa.head;

		apa.capacity_ = 0;
		// apa.head = 0; // It is not necessary to set head
		return *this;
	}

	// After moving out @p apa should be reinitialized (e.g. apa =
	// {}), before using it in any way other than destructing
	AVLPoolAllocator& operator=(AVLPoolAllocator&& apa) noexcept {
		if (capacity() > 0) {
			// Destruct all previously held data
			// Mark allocated elements
			std::vector<bool> allocated(capacity_, true);
			for (size_type i = head; i < capacity(); i = ptr(i)) {
				allocated[i] = false;
			}
			// Destruct them
			if (allocated[0]) { // 0 is a special case
				reinterpret_cast<AVLNB&>(data[0]).~AVLNB();
			}
			for (size_type i = 1; i < capacity(); ++i) {
				if (allocated[i]) {
					elem(i).~T();
				}
			}
		}

		// All has been destructed, so we can proceed to moving the
		// data
		move_assign(std::move(apa), AssertAllIsDeallocated{});
		return *this;
	}

	explicit AVLPoolAllocator(size_type reverve_size)
	: data{new Elem[meta::max(1, reverve_size)]}
	, capacity_{meta::max(1, reverve_size)} {
		for (size_type i = 0; i < capacity(); ++i) {
			ptr(i) = i + 1;
		}
	}

	T& operator[](size_type n) noexcept { return elem(n); }

	const T& operator[](size_type n) const noexcept { return elem(n); }

	[[nodiscard]] size_type capacity() const noexcept { return capacity_; }

	static constexpr size_type max_capacity() noexcept {
		return std::numeric_limits<size_type>::max();
	}

	// Provides strong exception guarantee
	void reserve_for(size_type n) {
		static_assert(std::is_nothrow_move_constructible<T>::value,
		              "Needed below");
		if (n < capacity()) {
			return;
		}

		if (capacity() == max_capacity()) {
			THROW("The AVLPool is full");
		}

		size_type new_capacity =
		   meta::max(n, capacity() < (max_capacity() >> 1) ? capacity() << 1
		                                                   : max_capacity());
		std::unique_ptr<Elem[]> new_data{new Elem[new_capacity]};
		// Initialize new data
		for (size_type i = 0; i < capacity(); ++i) {
			ptr(new_data, i) = new_capacity;
		}
		for (size_type i = capacity(); i < new_capacity; ++i) {
			ptr(new_data, i) = i + 1;
		}

		// Move and mark unallocated cells (allocated cells will
		// still have new_capacity as value, it works because
		// new_capacity > capacity())
		for (size_type i = head; i != capacity(); i = ptr(i)) {
			ptr(new_data, i) = ptr(i);
		}

		// Find allocated nodes and move them to the new_data
		// 0 element has to be moved in a different way
		if (ptr(new_data, 0) == new_capacity) {
			::new (&elem(new_data, 0))
			   AVLNB{std::move(reinterpret_cast<AVLNB&>(data[0]))};
		};

		for (size_type i = 1; i < capacity(); ++i) {
			if (ptr(new_data, i) == new_capacity) {
				::new (&elem(new_data, i)) T{std::move(elem(i))};
				elem(i).~T();
			}
		}

		data.reset(new_data.release());
		capacity_ = new_capacity;
	}

	// Provides strong exception guarantee
	size_type allocate() {
		static_assert(std::is_nothrow_move_constructible<T>::value,
		              "Needed below");
		if (head == capacity()) {
			if (capacity() == max_capacity()) {
				THROW("The AVLPool is full");
			}

			size_type new_capacity =
			   (capacity() < (max_capacity() >> 1) ? capacity() << 1
			                                       : max_capacity());
			std::unique_ptr<Elem[]> new_data{new Elem[new_capacity]};
			// Initialize new data (move old and initialize new
			// cells) 0 element has to be moved in a different way
			::new (&elem(new_data, 0))
			   AVLNB{std::move(reinterpret_cast<AVLNB&>(data[0]))};
			for (size_type i = 1; i < capacity(); ++i) {
				::new (&elem(new_data, i)) T(std::move(elem(i)));
				elem(i).~T();
			}

			for (size_type i = capacity(); i < new_capacity; ++i) {
				ptr(new_data, i) = i + 1;
			}

			data = std::move(new_data);
			capacity_ = new_capacity;
		}

		size_type res = head;
		head = ptr(head);
		return res;
	}

	void deallocate(size_type n) noexcept {
		ptr(n) = head;
		head = n;
	}

	void destruct_and_deallocate(size_type n) noexcept {
		elem(n).~T();
		ptr(n) = head;
		head = n;
	}

	// Warning: works in O(capacity)
	void deallocate_all() noexcept {
		for (size_type i = 0; i < capacity(); ++i) {
			ptr(i) = i + 1;
		}
		head = 0;
	}

#if 0
	void cerr_info() const noexcept {
		for (size_type i = 0; i < capacity(); ++i)
			cerr << i << ": " << ptr(i) << endl;
	}
#endif

	~AVLPoolAllocator() =
	   default; // It is user duty to destruct all the held objects
};

template <template <class...> class NodeT, class Comp = std::less<>,
          class size_type = size_t, class... NodeArgs>
class AVLDictionary {
protected:
	using Node = NodeT<size_type, NodeArgs...>;

	static_assert(std::is_base_of<AVLNodeBase<size_type>, Node>::value,
	              "NodeT has to derive from AVLNodeBase");

	static constexpr int L = Node::L;
	static constexpr int R = Node::R;

	AVLPoolAllocator<Node, size_type> pool;

	size_type nil = pool.allocate(); // it is always equal to 0
	size_type root = nil;
	size_type size_ = 0;
	Comp compare;

public:
	explicit AVLDictionary(size_type reserve_n = 1, Comp cmp = {})
	: pool(reserve_n)
	, compare(std::move(cmp)) {
		throw_assert(nil == 0);
		pool[nil].kid[L] = nil;
		pool[nil].kid[R] = nil;
		pool[nil].h = 0;
	}

	explicit AVLDictionary(Comp cmp)
	: AVLDictionary(1, std::move(cmp)) {}

	AVLDictionary(const AVLDictionary&) = default;
	AVLDictionary& operator=(const AVLDictionary&) = default;

	// After moving out @p avld should be reinitialized (e.g. avld =
	// {}), before using it in any way other than destructing
	AVLDictionary(AVLDictionary&& avld) noexcept
	: pool(std::move(avld.pool))
	, nil(avld.nil)
	, root(avld.root)
	, size_(avld.size_)
	, compare(std::move(avld.compare)) {
		// Set avld to a clear state
		avld.root = nil;
	}

	// After moving out @p avld should be reinitialized (e.g. avld =
	// {}), before using it in any way other than destructing
	AVLDictionary& operator=(AVLDictionary&& avld) noexcept {
		delete_subtree(root);

		pool.move_assign(std::move(avld.pool),
		                 typename decltype(pool)::AssertAllIsDeallocated{});
		// nil = avld.nil; (nil is always equal to 0)
		root = avld.root;
		size_ = avld.size_;
		compare = std::move(avld.compare);

		// Set avld to a clear state
		avld.root = nil;
		return *this;
	}

protected:
	void deallocate_node(size_type x) noexcept {
		pool.destruct_and_deallocate(x);
		--size_;
	}

	template <class... Args>
	size_type allocate_node(Args&&... args) {
		size_t x = pool.allocate();

		try {
			::new (&pool[x]) Node{std::forward<Args>(args)...};
		} catch (...) {
			pool.deallocate(x);
			throw;
		}

		++size_;
		return x;
	}

	void delete_subtree(size_type x) {
		if constexpr (std::is_trivially_destructible_v<Node>) {
			return;
		}

		if (x == nil) {
			return;
		}

		delete_subtree(pool[x].kid[L]);
		delete_subtree(pool[x].kid[R]);

		deallocate_node(x);
	}

public:
	~AVLDictionary() {
		delete_subtree(root);

		static_assert(
		   std::is_trivially_destructible<AVLNodeBase<size_type>>::value,
		   "Needed to avoid destructing nil and simplify "
		   "move assignments");
	}

	void clear() {
		delete_subtree(root);
		root = nil;
	}

	static constexpr size_type max_capacity() noexcept {
		return decltype(pool)::max_capacity();
	}

	[[nodiscard]] size_type capacity() const noexcept {
		return pool.capacity();
	}

	void reserve_for(size_type n) { pool.reserve_for(n); }

	[[nodiscard]] size_type size() const noexcept { return size_; }

	[[nodiscard]] bool empty() const noexcept { return (size() == 0); }

protected:
	void seth(size_type x) noexcept {
		pool[x].h = uint8_t(
		   1 + meta::max(pool[pool[x].kid[L]].h, pool[pool[x].kid[R]].h));
	}

	/// rotating nil node up is invalid
	size_type rotate(size_type x, int dir) noexcept {
		int revdir = dir ^ 1;
		size_type res = pool[x].kid[revdir];
		pool[x].kid[revdir] = pool[res].kid[dir];
		pool[res].kid[dir] = x;
		seth(x);
		// assert(pool[nil].kid[L] == nil);
		// assert(pool[nil].kid[R] == nil);
		return res;
	}

	/// rotating nil node up is invalid
	size_type rotate_and_seth(size_type x, int dir) noexcept {
		size_type res = rotate(x, dir);
		seth(res);
		return res;
	}

	size_type rebalance_and_seth(size_type x) noexcept {
		int b = (pool[pool[x].kid[L]].h - pool[pool[x].kid[R]].h) / 2;
		assert(-1 <= b and b <= 1);
		if (b) {
			int dir = (b + 1) >> 1;
			int revdir = dir ^ 1;
			size_type aux_B = pool[x].kid[revdir];
			if (pool[pool[aux_B].kid[R]].h - pool[pool[aux_B].kid[L]].h == b) {
				size_type aux_C = pool[aux_B].kid[dir];
				pool[x].kid[revdir] = pool[aux_C].kid[dir];
				seth(x);
				pool[aux_B].kid[dir] = pool[aux_C].kid[revdir];
				seth(aux_B);
				pool[aux_C].kid[dir] = x;
				pool[aux_C].kid[revdir] = aux_B;
				seth(aux_C);
				return aux_C;
			}

			return rotate_and_seth(x, dir);
		}

		seth(x);
		return x;
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior  of subtree of @p x. For deleting traversed nodes
	 * see filter()
	 * @param x node representing subtree
	 * @param func function to call on every element, it should take
	 *   one argument of type Node&, if it return sth convertible to
	 *   false the lookup will break
	 */
	template <class Func,
	          std::enable_if_t<
	             std::is_same_v<repeating, std::invoke_result_t<Func, Node&>>,
	             int> = 0>
	repeating for_each(size_type x, Func&& func) {
		if (x == nil) {
			return continue_repeating;
		}

		if (for_each(pool[x].kid[L], func) == stop_repeating or
		    func(pool[x]) == stop_repeating)
		{
			return stop_repeating;
		}
		return for_each(pool[x].kid[R], func);
	}

	template <
	   class Func,
	   std::enable_if_t<std::is_same_v<void, std::invoke_result_t<Func, Node&>>,
	                    int> = 0>
	void for_each(size_type x, Func&& func) {
		if (x == nil) {
			return;
		}

		for_each(pool[x].kid[L], func);
		func(pool[x]);
		for_each(pool[x].kid[R], func);
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior  of subtree of @p x. For deleting traversed nodes
	 * see filter()
	 * @param x node representing subtree
	 * @param func function to call on every element, it should take
	 *   one argument of type Node&, if it return sth convertible to
	 *   false the lookup will break
	 */
	template <
	   class Func,
	   std::enable_if_t<
	      std::is_same_v<repeating, std::invoke_result_t<Func, const Node&>>,
	      int> = 0>
	repeating for_each(size_type x, Func&& func) const {
		if (x == nil) {
			return continue_repeating;
		}

		if (for_each(pool[x].kid[L], func) == stop_repeating or
		    func(pool[x]) == stop_repeating)
		{
			return stop_repeating;
		}
		return for_each(pool[x].kid[R], func);
	}

	template <class Func,
	          std::enable_if_t<
	             std::is_same_v<void, std::invoke_result_t<Func, const Node&>>,
	             int> = 0>
	void for_each(size_type x, Func&& func) const {
		if (x == nil) {
			return;
		}

		for_each(pool[x].kid[L], func);
		func(pool[x]);
		for_each(pool[x].kid[R], func);
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior. For deleting traversed nodes see filter()
	 * @param func function to call on every element, it should take
	 *   one argument of type Node&, if it return sth convertible to
	 *   false the lookup will break
	 */
	template <
	   class Func,
	   std::enable_if_t<
	      meta::is_one_of<std::invoke_result_t<Func, Node&>, void, repeating>,
	      int> = 0>
	void for_each(Func&& func) {
		for_each(root, std::forward<Func>(func));
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior. For deleting traversed nodes see filter()
	 * @param func function to call on every element, it should take
	 *   one argument of type const Node&, if it return sth convertible
	 *   to false the lookup will break
	 */
	template <
	   class Func,
	   std::enable_if_t<meta::is_one_of<std::invoke_result_t<Func, const Node&>,
	                                    void, repeating>,
	                    int> = 0>
	void for_each(Func&& func) const {
		for_each(root, std::forward<Func>(func));
	}

	/** @brief Calls @p condition on every element and removes it if
	 *    @p condition returns true
	 * @param condition function to call on every element do decide whether to
	 *    remove it. It should take one argument of type Node&.
	 * @complexity O(n + k log n) where n = size() and k = number of deleted
	 * elements
	 */
	template <class Condition,
	          std::enable_if_t<
	             std::is_same_v<bool, std::invoke_result_t<Condition, Node&>>,
	             int> = 0>
	void filter(Condition&& condition) {
		std::optional<typename Node::Key> key_opt;
		auto processor = [&](Node& node) {
			if (condition(node)) {
				key_opt.emplace(node.key());
				return stop_repeating;
			}

			return continue_repeating;
		};

		for_each(processor);
		while (key_opt.has_value()) {
			auto key = std::move(*key_opt);
			key_opt = std::nullopt;
			erase(key);
			foreach_since_upper_bound(key, processor);
		}
	}

public:
	/// Returns a pointer to the found value or nullptr if there is
	/// no such value
	template <class T>
	typename Node::Data* find(T&& key) {
		for (size_type x = root; x != nil;) {
			bool dir = compare(pool[x].key(), key);
			if (not dir and not compare(key, pool[x].key()))
			{ // we have a match
				return &pool[x].data();
			}

			x = pool[x].kid[dir];
		}

		return nullptr;
	}

	/// Returns a pointer to the found value or nullptr if there is
	/// no such value
	template <class T>
	[[nodiscard]] const typename Node::Data* find(T&& key) const {
		for (size_type x = root; x != nil;) {
			bool dir = compare(pool[x].key(), key);
			if (not dir and not compare(key, pool[x].key()))
			{ // we have a match
				return &pool[x].data();
			}

			x = pool[x].kid[dir];
		}

		return nullptr;
	}

protected:
	void insert(size_type& x, size_type inserted) {
		if (x == nil) {
			x = inserted;
			return;
		}

		bool dir = compare(pool[x].key(), pool[inserted].key());
		insert(pool[x].kid[dir], inserted);
		x = rebalance_and_seth(x);
	}

	/// Return value - @p inserted if the insertion took place, found
	/// node id otherwise
	size_type insert_if_not_exists(size_type& x, size_type inserted) {
		if (x == nil) {
			return x = inserted;
		}

		bool dir = compare(pool[x].key(), pool[inserted].key());
		// if we have just found a duplicate
		if (not dir and not compare(pool[inserted].key(), pool[x].key())) {
			return x;
		}

		auto res = insert_if_not_exists(pool[x].kid[dir], inserted);
		x = rebalance_and_seth(x);
		return res;
	}

private:
	template <class Key, class NData = typename Node::RealData>
	static constexpr std::enable_if_t<is_pair<NData>, NData>
	construct_node_data(Key&& key) {
		return {std::piecewise_construct,
		        std::forward_as_tuple(std::forward<Key>(key)), std::tuple<>()};
	}

	template <class Key, class NData = typename Node::RealData>
	static constexpr std::enable_if_t<!is_pair<NData>, NData>
	construct_node_data(Key&& key) {
		return {std::forward<Key>(key)};
	}

	/// Return value - what to replace x with and emplaced node id if
	/// the insertion took place, or found node id otherwise
	template <class T>
	std::pair<size_type, size_type> emplace_if_not_exists_impl(size_type x,
	                                                           T key) {
		// x cannot be taken by reference since allocation may move
		// all the data in the pool causing these references to
		// become invalid
		if (x == nil) {
			x = allocate_node(construct_node_data(std::forward<T>(key)), nil,
			                  nil, uint8_t{0});
			return {x, x};
		}

		bool dir = compare(pool[x].key(), key);
		// if we have just found a duplicate
		if (not dir and not compare(key, pool[x].key())) {
			return {x, x};
		};

		auto p = emplace_if_not_exists_impl<T>(pool[x].kid[dir],
		                                       std::forward<T>(key));
		pool[x].kid[dir] = p.first; // As the pool may have changed this has to
		                            // be done strictly after the recursive call
		return {rebalance_and_seth(x), p.second};
	}

protected:
	/// Return value - emplaced node id if the insertion took place,
	/// or found node id otherwise
	size_type emplace_if_not_exists(const typename Node::Key& key) {
		auto p =
		   emplace_if_not_exists_impl<const typename Node::Key&>(root, key);
		root = p.first; // As the pool may have changed this has to
		                // be done strictly after the recursive call
		return p.second;
	}

	/// Return value - emplaced node id if the insertion took place,
	/// or found node id otherwise
	size_type emplace_if_not_exists(typename Node::Key&& key) {
		auto p = emplace_if_not_exists_impl<typename Node::Key&&>(
		   root, std::move(key));
		root = p.first; // As the pool may have changed this has to
		                // be done strictly after the recursive call
		return p.second;
	}

	/// Return value - a bool denoting whether the insertion took
	/// place
	bool insert_or_replace(size_type& x, size_type inserted) {
		if (x == nil) {
			x = inserted;
			return true;
		}

		bool dir = compare(pool[x].key(), pool[inserted].key());
		// if we have just found a duplicate
		if (not dir and not compare(pool[inserted].key(), pool[x].key())) {
			pool[inserted].kid = pool[x].kid;
			pool[inserted].h = pool[x].h;
			deallocate_node(x);
			x = inserted;
			return false;
		}

		auto res = insert_or_replace(pool[x].kid[dir], inserted);
		x = rebalance_and_seth(x);
		return res;
	}

	/// @p direction: left - 0, right - 1
	Node* dirmost(size_type node, int direction) noexcept {
		while (node != nil) {
			auto next = pool[node].kid[direction];
			if (next == nil) {
				return &pool[node];
			}

			node = next;
		}

		return nullptr;
	}

	/// @p direction: left - 0, right - 1
	[[nodiscard]] const Node* dirmost(size_type node,
	                                  int direction) const noexcept {
		while (node != nil) {
			auto next = pool[node].kid[direction];
			if (next == nil) {
				return &pool[node];
			}

			node = next;
		}

		return nullptr;
	}

	Node* insert(size_type node_id) {
		insert(root, node_id);
		return &pool[node_id];
	}

	/// Return value - @p node_id if the insertion took place, found
	/// node id otherwise (in this case you have to manually
	/// deallocate @p node_id)
	size_type insert_if_not_exists(size_type node_id) {
		return insert_if_not_exists(root, node_id);
	}

	std::pair<Node*, bool> insert_or_replace(size_type node_id) {
		auto b = insert_or_replace(root, node_id);
		return {&pool[node_id], b};
	}

	Node* front() noexcept { return dirmost(root, L); }

	[[nodiscard]] const Node* front() const noexcept {
		return dirmost(root, L);
	}

	Node* back() noexcept { return dirmost(root, R); }

	[[nodiscard]] const Node* back() const noexcept { return dirmost(root, R); }

	// return value - pulled out node; x is updated automatically
	size_type pull_out_rightmost(size_type& x) {
		if (pool[x].kid[R] == nil) {
			auto res = x;
			x = pool[x].kid[L];
			return res; // In this case tree is well-balanced
		}

		auto res = pull_out_rightmost(pool[x].kid[R]);
		x = rebalance_and_seth(x);
		return res;
	}

	template <class T, class FuncIdxToRetVal>
	std::result_of_t<FuncIdxToRetVal(size_type)>
	erase_impl(size_type& x, T&& key, FuncIdxToRetVal&& to_ret_val) {
		if (x == nil) {
			return to_ret_val();
		}

		bool dir = compare(pool[x].key(), key);
		if (not dir and not compare(key, pool[x].key())) {
			if (pool[x].kid[L] == nil) {
				size_type new_x = pool[x].kid[R];

				auto res = to_ret_val(x);

				if (new_x != nil) {
					x = rebalance_and_seth(new_x);
				} else {
					x = new_x;
				}

				return res;
			}
			auto x_left = pool[x].kid[L];
			auto pulled = pull_out_rightmost(x_left);
			// pulled replaces x in the tree structure
			pool[pulled].kid[L] = x_left;
			pool[pulled].kid[R] = pool[x].kid[R];

			auto res = to_ret_val(x);

			x = rebalance_and_seth(pulled);
			return res;
		}

		auto res =
		   erase_impl(pool[x].kid[dir], key, to_ret_val); /* Intentionally
		       without std::move() to avoid unnecessary move constructing of
		       the to_ret_val, as it will be taken by reference from now on */
		x = rebalance_and_seth(x);
		return res;
	}

	/// Return value - a bool denoting whether the erasing took place
	template <class T>
	bool erase(size_type& x, T&& key) {
		using AVLD = decltype(*this);
		struct SemiLambda {
			AVLD& avld_;
			explicit SemiLambda(AVLD& avld)
			: avld_(avld) {}

			bool operator()() const noexcept { return false; }

			bool operator()(size_type node) const noexcept {
				avld_.deallocate_node(node);
				return true;
			}
		};

		return erase_impl(x, key, SemiLambda(*this));
	}

	/// Return value - a node id of pulled out node or nil if no such
	/// node was found
	template <class T>
	size_type pull_out(size_type& x, T&& key) {
		using AVLD = decltype(*this);
		struct SemiLambda {
			AVLD& avld_;
			explicit SemiLambda(AVLD& avld)
			: avld_(avld) {}

			size_type operator()() const noexcept { return avld_.nil; }

			size_type operator()(size_type node) const noexcept {
				// Reset node kids to nils
				avld_.pool[node].kid = {{avld_.nil, avld_.nil}};
				return node;
			}
		};

		return erase_impl(x, key, SemiLambda(*this));
	}

public:
	/// Return value - a bool denoting whether the erasing took place
	template <class T>
	bool erase(T&& key) {
		return erase(root, key);
	}

	template <class T>
	typename Node::Data* lower_bound(T&& key) {
		typename Node::Data* res = nullptr;
		size_type x = root;
		while (x != nil) {
			if (compare(pool[x].key(), key)) {
				x = pool[x].kid[R];
			} else {
				res = &pool[x].data();
				x = pool[x].kid[L];
			}
		}

		return res;
	}

	template <class T>
	const typename Node::Data* lower_bound(T&& key) const {
		typename Node::Data* res = nullptr;
		size_type x = root;
		while (x != nil) {
			if (compare(pool[x].key(), key)) {
				x = pool[x].kid[R];
			} else {
				res = &pool[x].data();
				x = pool[x].kid[L];
			}
		}

		return res;
	}

	template <class T>
	typename Node::Data* upper_bound(T&& key) {
		typename Node::Data* res = nullptr;
		size_type x = root;
		while (x != nil) {
			if (compare(key, pool[x].key())) {
				res = &pool[x].data();
				x = pool[x].kid[L];
			} else {
				x = pool[x].kid[R];
			}
		}

		return res;
	}

	template <class T>
	[[nodiscard]] const typename Node::Data* upper_bound(T&& key) const {
		const typename Node::Data* res = nullptr;
		size_type x = root;
		while (x != nil) {
			if (compare(key, pool[x].key())) {
				res = &pool[x].data();
				x = pool[x].kid[L];
			} else {
				x = pool[x].kid[R];
			}
		}

		return res;
	}

protected:
	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<repeating, std::invoke_result_t<Func, Node&>>,
	             int> = 0>
	repeating foreach_since_lower_bound(size_type x, T&& key, Func&& callback) {
		if (x == nil) {
			return continue_repeating;
		}

		if (compare(pool[x].key(), key)) {
			return foreach_since_lower_bound(pool[x].kid[R], key, callback);
		}

		if (foreach_since_lower_bound(pool[x].kid[L], key, callback) ==
		       stop_repeating or
		    callback(pool[x]) == stop_repeating)
		{
			return stop_repeating;
		}
		return for_each(pool[x].kid[R], callback);
	}

	template <
	   class T, class Func,
	   std::enable_if_t<std::is_same_v<void, std::invoke_result_t<Func, Node&>>,
	                    int> = 0>
	void foreach_since_lower_bound(T&& key, Func&& callback) {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_lower_bound(root, key, [&](Node& n) {
			callback(n);
			return continue_repeating;
		});
	}

	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<repeating, std::invoke_result_t<Func, Node&>>,
	             int> = 0>
	void foreach_since_lower_bound(T&& key, Func&& callback) {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_lower_bound(root, key, callback);
	}

	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<repeating, std::invoke_result_t<Func, Node&>>,
	             int> = 0>
	repeating foreach_since_upper_bound(size_type x, T&& key, Func&& callback) {
		if (x == nil) {
			return continue_repeating;
		}

		if (compare(key, pool[x].key())) {
			if (foreach_since_upper_bound(pool[x].kid[L], key, callback) ==
			       stop_repeating or
			    callback(pool[x]) == stop_repeating)
			{
				return stop_repeating;
			}
			return for_each(pool[x].kid[R], callback);
		}
		return foreach_since_upper_bound(pool[x].kid[R], key, callback);
	}

	template <
	   class T, class Func,
	   std::enable_if_t<std::is_same_v<void, std::invoke_result_t<Func, Node&>>,
	                    int> = 0>
	void foreach_since_upper_bound(T&& key, Func&& callback) {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_upper_bound(root, key, [&](Node& n) {
			callback(n);
			return continue_repeating;
		});
	}

	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<repeating, std::invoke_result_t<Func, Node&>>,
	             int> = 0>
	void foreach_since_upper_bound(T&& key, Func&& callback) {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_upper_bound(root, key, callback);
	}

	template <
	   class T, class Func,
	   std::enable_if_t<
	      std::is_same_v<repeating, std::invoke_result_t<Func, const Node&>>,
	      int> = 0>
	repeating foreach_since_lower_bound(size_type x, T&& key,
	                                    Func&& callback) const {
		if (x == nil) {
			return continue_repeating;
		}

		if (compare(pool[x].key(), key)) {
			return foreach_since_lower_bound(pool[x].kid[R], key, callback);
		}

		if (foreach_since_lower_bound(pool[x].kid[L], key, callback) ==
		       stop_repeating or
		    callback(pool[x]) == stop_repeating)
		{
			return stop_repeating;
		}
		return for_each(pool[x].kid[R], callback);
	}

	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<void, std::invoke_result_t<Func, const Node&>>,
	             int> = 0>
	void foreach_since_lower_bound(T&& key, Func&& callback) const {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_lower_bound(root, key, [&](Node& n) {
			callback(n);
			return continue_repeating;
		});
	}

	template <
	   class T, class Func,
	   std::enable_if_t<
	      std::is_same_v<repeating, std::invoke_result_t<Func, const Node&>>,
	      int> = 0>
	void foreach_since_lower_bound(T&& key, Func&& callback) const {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_lower_bound(root, key, callback);
	}

	template <
	   class T, class Func,
	   std::enable_if_t<
	      std::is_same_v<repeating, std::invoke_result_t<Func, const Node&>>,
	      int> = 0>
	repeating foreach_since_upper_bound(size_type x, T&& key,
	                                    Func&& callback) const {
		if (x == nil) {
			return continue_repeating;
		}

		if (compare(key, pool[x].key())) {
			if (foreach_since_upper_bound(pool[x].kid[L], key, callback) ==
			       stop_repeating or
			    callback(pool[x]) == stop_repeating)
			{
				return stop_repeating;
			}
			return for_each(pool[x].kid[R], callback);
		}
		return foreach_since_upper_bound(pool[x].kid[R], key, callback);
	}

	template <class T, class Func,
	          std::enable_if_t<
	             std::is_same_v<void, std::invoke_result_t<Func, const Node&>>,
	             int> = 0>
	void foreach_since_upper_bound(T&& key, Func&& callback) const {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_upper_bound(root, key, [&](Node& n) {
			callback(n);
			return continue_repeating;
		});
	}

	template <
	   class T, class Func,
	   std::enable_if_t<
	      std::is_same_v<repeating, std::invoke_result_t<Func, const Node&>>,
	      int> = 0>
	void foreach_since_upper_bound(T&& key, Func&& callback) const {
		// std::forward omitted intentionally as the callback will be
		// taken by a (maybe const) reference
		foreach_since_upper_bound(root, key, callback);
	}

public:
#if 0
	void print(size_type x, int tabs = 0) const {
		if (tabs > 50)
			abort(); // sth went wrong

		if (x == nil)
			return;

		print(pool[x].kid[R], tabs + 1);

		stdlog(std::string(tabs * 3, ' '), x,  "- h: ", (int)pool[x].h,
			", {", pool[x].kid[L], " ", pool[x].kid[R], "}\t", pool[x].key());

		print(pool[x].kid[L], tabs + 1);

	}

	void print() const {
		stdlog('\n', nil, " NIL: ", pool[nil].kid[L], " ", pool[nil].kid[R]);
		print(root);
		assert(pool[pool[nil].kid[L]].h == 0);
		assert(pool[nil].kid[L] == nil);
		assert(pool[nil].kid[R] == nil);
	}
#endif
};

template <template <class...> class NodeT, class... ArgsToForward>
class AVLDictContainer : public AVLDictionary<NodeT, ArgsToForward...> {
protected:
	using AVLBase = AVLDictionary<NodeT, ArgsToForward...>;
	using AVLBase::nil;
	using AVLBase::pool;
	using typename AVLBase::Node;

public:
	using value_type = typename Node::value_type;
	using AVLBase::AVLBase;

	typename Node::Data* front() {
		auto x = AVLBase::front();
		return (x ? &x->data() : nullptr);
	}

	[[nodiscard]] const typename Node::Data* front() const {
		auto x = AVLBase::front();
		return (x ? &x->data() : nullptr);
	}

	typename Node::Data* back() {
		auto x = AVLBase::back();
		return (x ? &x->data() : nullptr);
	}

	[[nodiscard]] const typename Node::Data* back() const {
		auto x = AVLBase::back();
		return (x ? &x->data() : nullptr);
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior. For deleting traversed nodes see filter()
	 * @param func function to call on every element, it should take
	 *   one argument of type Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class Func>
	void for_each(Func&& func) {
		static_assert(
		   meta::is_one_of<std::invoke_result_t<Func, typename Node::Data&>,
		                   void, repeating>);
		AVLBase::for_each([&func](Node& node) { return func(node.data()); });
	}

	/**
	 * @brief Calls @p func on every element
	 * @details IMPORTANT: Adding or removing nodes within @p func is an
	 *   undefined behavior. For deleting traversed nodes see filter()
	 * @param func function to call on every element, it should take
	 *   one argument of type const Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class Func>
	void for_each(Func&& func) const {
		static_assert(meta::is_one_of<
		              std::invoke_result_t<Func, const typename Node::Data&>,
		              void, repeating>);
		AVLBase::for_each(
		   [&func](const Node& node) { return func(node.data()); });
	}

protected:
	/**
	 * @brief Calls @p condition on every element and removes it if
	 *    @p condition returns true
	 * @param condition function to call on every element do decide whether to
	 *    remove it. It should take one argument of type Node&.
	 * @complexity O(n + k log n) where n = size() and k = number of deleted
	 * elements
	 */
	template <class Condition,
	          std::enable_if_t<
	             std::is_same_v<bool, std::invoke_result_t<
	                                     Condition, typename Node::Data&>>,
	             int> = 0>
	void filter(Condition&& condition) {
		AVLBase::filter(
		   [&condition](Node& node) { return condition(node.data()); });
	}

public:
	/**
	 * @brief Calls @p callback on every element since the first element
	 *   >= @p k
	 * @param callback function to call on every element, it should take
	 *   one argument of type Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class T, class Func>
	void foreach_since_lower_bound(T&& key, Func&& callback) {
		static_assert(
		   meta::is_one_of<std::invoke_result_t<Func, typename Node::Data&>,
		                   void, repeating>);
		AVLBase::foreach_since_lower_bound(
		   key, [&](Node& node) { return callback(node.data()); });
	}

	/**
	 * @brief Calls @p callback on every element since the first element
	 *   >= @p k
	 * @param callback function to call on every element, it should take
	 *   one argument of type const Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class T, class Func>
	void foreach_since_lower_bound(T&& key, Func&& callback) const {
		static_assert(meta::is_one_of<
		              std::invoke_result_t<Func, const typename Node::Data&>,
		              void, repeating>);
		AVLBase::foreach_since_lower_bound(
		   key, [&](const Node& node) { return callback(node.data()); });
	}

	/**
	 * @brief Calls @p callback on every element since the first element
	 *   > @p k
	 * @param callback function to call on every element, it should take
	 *   one argument of type Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class T, class Func>
	void foreach_since_upper_bound(T&& key, Func&& callback) {
		static_assert(
		   meta::is_one_of<std::invoke_result_t<Func, typename Node::Data&>,
		                   void, repeating>);
		AVLBase::foreach_since_upper_bound(
		   key, [&](Node& node) { return callback(node.data()); });
	}

	/**
	 * @brief Calls @p callback on every element since the first element
	 *   > @p k
	 * @param callback function to call on every element, it should take
	 *   one argument of type const Node::Data&.
	 *   It should return void or something convertible to repeating.
	 */
	template <class T, class Func>
	void foreach_since_upper_bound(T&& key, Func&& callback) const {
		static_assert(meta::is_one_of<
		              std::invoke_result_t<Func, const typename Node::Data&>,
		              void, repeating>);
		AVLBase::foreach_since_upper_bound(
		   key, [&](const Node& node) { return callback(node.data()); });
	}
};

template <class size_type, class ValueT>
class AVLSetNode : public AVLNodeBase<size_type> {
public:
	using Key = ValueT;
	using Value = const Key;
	using RealData = Key;
	using Data = const Key;
	using value_type = Key;

	Key key_;

	template <class... Args>
	explicit AVLSetNode(Key key, Args&&... args)
	: AVLNodeBase<size_type>{std::forward<Args>(args)...}
	, key_(std::move(key)) {}

	AVLSetNode(const AVLSetNode&) = default;
	AVLSetNode(AVLSetNode&&) noexcept(
	   std::is_nothrow_move_constructible<Key>::value) = default;

	AVLSetNode& operator=(const AVLSetNode&) = delete;
	AVLSetNode& operator=(AVLSetNode&&) = delete;

	~AVLSetNode() = default;

	[[nodiscard]] const Key& key() const noexcept { return key_; }

	[[nodiscard]] const Data& data() const { return key(); }
};

template <class Value, class Comp = std::less<>, class size_type = size_t>
class AVLDictSet : public AVLDictContainer<AVLSetNode, Comp, size_type, Value> {
	using ADC = AVLDictContainer<AVLSetNode, Comp, size_type, Value>;
	using ADC::nil;
	using typename ADC::AVLBase;
	using typename ADC::Node;

public:
	using ADC::ADC;
	using ADC::operator=;
	using ADC::filter;

	/// Return value - a bool denoting whether the insertion took
	/// place
	template <class... Args>
	bool emplace(Args&&... args) {
		auto new_node = AVLBase::allocate_node(
		   Value(std::forward<Args>(args)...), nil, nil, uint8_t{0});
		auto x = AVLBase::insert_if_not_exists(new_node);
		if (x != new_node) {
			AVLBase::deallocate_node(new_node);
			return false;
		}

		return true;
	}

	/// Return value - a bool denoting whether the insertion took
	/// place
	bool insert(Value val) { return emplace(std::move(val)); }
};

template <class Value, class Comp = std::less<>, class size_type = size_t>
class AVLDictMultiset
: public AVLDictContainer<AVLSetNode, Comp, size_type, Value> {
	using ADC = AVLDictContainer<AVLSetNode, Comp, size_type, Value>;
	using ADC::nil;
	using typename ADC::AVLBase;
	using typename ADC::Node;

public:
	using ADC::ADC;
	using ADC::operator=;

	/// Return value - a bool denoting whether the insertion took
	/// place
	template <class... Args>
	void emplace(Args&&... args) {
		AVLBase::insert(AVLBase::allocate_node(
		   Value{std::forward<Args>(args)...}, nil, nil, uint8_t{0}));
	}

	/// Return value - a bool denoting whether the insertion took
	/// place
	void insert(Value val) { emplace(std::move(val)); }
};

template <class size_type, class KeyT, class ValueT>
class AVLMapNode : public AVLNodeBase<size_type> {
public:
	using Key = KeyT;
	using Value = ValueT;
	using RealData = std::pair<Key, Value>;
	using Data = std::pair<const Key, Value>;
	using value_type = std::pair<const Key, Value>;

	union DataU {
		RealData rdt;
		Data dt;

		static_assert(sizeof(rdt) == sizeof(dt), "Needed to cast between");

		explicit DataU(RealData&& rdata) noexcept(
		   std::is_move_constructible<RealData>::value)
		: rdt(std::move(rdata)) {}

		DataU(const DataU&) = delete;
		DataU(DataU&&) = delete;
		DataU& operator=(const DataU&) = delete;
		DataU& operator=(DataU&&) = delete;

		~DataU() { rdt.~RealData(); }

	} data_;

	template <class... Args>
	explicit AVLMapNode(RealData&& rdata, Args&&... args)
	: AVLNodeBase<size_type>(std::forward<Args>(args)...)
	, data_(std::move(rdata)) {}

	AVLMapNode(const AVLMapNode&) = delete;

	AVLMapNode(AVLMapNode&& amn) noexcept(
	   std::is_nothrow_move_constructible<AVLNodeBase<size_type>>::value&&
	      std::is_nothrow_move_constructible<RealData>::value)
	: AVLNodeBase<size_type>(std::move(amn))
	, data_(std::move(amn.data_.rdt)) {}

	AVLMapNode& operator=(const AVLMapNode&) = delete;

	AVLMapNode& operator=(AVLMapNode&& amn) noexcept(
	   std::is_nothrow_move_assignable<AVLNodeBase<size_type>>::value&&
	      std::is_nothrow_move_assignable<decltype(data_)>::value) {
		AVLNodeBase<size_type>::operator=(std::move(amn));
		data_.rdt = std::move(amn.data_.rdt);
		return *this;
	}

	~AVLMapNode() = default;

	RealData& real_data() noexcept { return data_.rdt; }

	Data& data() noexcept { return data_.dt; }

	[[nodiscard]] const Data& data() const noexcept { return data_.dt; }

	[[nodiscard]] const Key& key() const noexcept { return data_.dt.first; }

	Value& value() noexcept { return data_.dt.second; }

	[[nodiscard]] const Value& value() const noexcept {
		return data_.dt.second;
	}
};

template <class Key, class Value, class Comp = std::less<>,
          class size_type = size_t>
class AVLDictMap
: public AVLDictContainer<AVLMapNode, Comp, size_type, Key, Value> {
	using ADC = AVLDictContainer<AVLMapNode, Comp, size_type, Key, Value>;
	using typename ADC::AVLBase;
	using typename ADC::Node;
	using KeyValPair = typename ADC::Node::Data;
	using ADC::nil;
	using ADC::pool;

public:
	using ADC::ADC;
	using ADC::operator=;
	using ADC::filter;

	/// Return value - a pair of a pointer to pair (key, value) and a
	/// bool denoting whether the insertion took place (if false, the
	/// replacing took place)
	template <class... Args>
	std::pair<KeyValPair*, bool> emplace(Args&&... args) {
		auto new_node = AVLBase::allocate_node(
		   typename ADC::Node::RealData(std::forward<Args>(args)...), nil, nil,
		   uint8_t{0});

		auto x = AVLBase::insert_or_replace(new_node);
		return {&x.first->data(), x.second};
	}

	/// Return value - a pair of a pointer to pair (key, value) and a
	/// bool denoting whether the insertion took place (if false, the
	/// replacing took place)
	std::pair<KeyValPair*, bool> insert(KeyValPair kvp) {
		return emplace(std::move(kvp));
	}

	/// Return value - a pair of a pointer to pair (key, value) and a
	/// bool denoting whether the insertion took place (if false, the
	/// replacing took place)
	std::pair<KeyValPair*, bool> insert(typename Node::Key key,
	                                    typename Node::Value val) {
		return insert({std::move(key), std::move(val)});
	}

	Value& operator[](const Key& key) {
		return pool[AVLBase::emplace_if_not_exists(key)].value();
	}

	Value& operator[](Key&& key) {
		return pool[AVLBase::emplace_if_not_exists(std::move(key))].value();
	}

	/// Changes the key of an element with key @p old_key to a @p
	/// new_key without moving any data. Replaces other element with
	/// a @p new_key if necessary. Return value: a pair of bools
	/// denoting accordingly: whether the key change took place and
	/// whether some element was replaced.
	std::pair<bool, bool> alter_key(const Key& old_key, const Key& new_key) {
		size_type x = AVLBase::pull_out(AVLBase::root, old_key);
		if (x == nil) {
			return {false, false};
		};

		pool[x].real_data().first = new_key;
		return {true, not AVLBase::insert_or_replace(x).second};
	}

	/// Changes the key of an element with key @p old_key to a @p
	/// new_key without moving any data. Replaces other element with
	/// a @p new_key if necessary. Return value: a pair of bools
	/// denoting accordingly: whether the key change took place and
	/// whether some element was replaced.
	std::pair<bool, bool> alter_key(const Key& old_key, Key&& new_key) {
		size_type x = AVLBase::pull_out(AVLBase::root, old_key);
		if (x == nil) {
			return {false, false};
		};

		pool[x].real_data().first = std::move(new_key);
		return {true, not AVLBase::insert_or_replace(x).second};
	}
};

template <class Key, class Value, class Comp = std::less<>,
          class size_type = size_t>
class AVLDictMultimap
: public AVLDictContainer<AVLMapNode, Comp, size_type, Key, Value> {
	using ADC = AVLDictContainer<AVLMapNode, Comp, size_type, Key, Value>;
	using typename ADC::AVLBase;
	using typename ADC::Node;
	using KeyValPair = typename ADC::Node::Data;
	using ADC::nil;
	using ADC::pool;

public:
	using ADC::ADC;
	using ADC::operator=;

	/// Return value - a pointer to pair (key, value)
	template <class... Args>
	KeyValPair* emplace(Args&&... args) {
		auto new_node = AVLBase::allocate_node(
		   typename ADC::Node::RealData{std::forward<Args>(args)...}, nil, nil,
		   uint8_t{0});

		AVLBase::insert(new_node);
		return &pool[new_node].data();
	}

	/// Return value - a pointer to pair (key, value)
	KeyValPair* insert(KeyValPair kvp) { return emplace(std::move(kvp)); }

	/// Return value - a pointer to pair (key, value)
	KeyValPair* insert(typename Node::Key key, typename Node::Value val) {
		return insert({std::move(key), std::move(val)});
	}

	/// Changes the key of an element with key @p old_key to a @p
	/// new_key without moving any data. Return value: a bool
	/// denoting whether the key change took place.
	bool alter_key(const Key& old_key, const Key& new_key) {
		size_type x = AVLBase::pull_out(AVLBase::root, old_key);
		if (x == nil) {
			return false;
		}

		pool[x].real_data().first = new_key;
		AVLBase::insert(x);
		return true;
	}

	/// Changes the key of an element with key @p old_key to a @p
	/// new_key without moving any data. Return value: a bool
	/// denoting whether the key change took place.
	bool alter_key(const Key& old_key, Key&& new_key) {
		size_type x = AVLBase::pull_out(AVLBase::root, old_key);
		if (x == nil) {
			return false;
		}

		pool[x].real_data().first = std::move(new_key);
		AVLBase::insert(x);
		return true;
	}
};

template <class T, class Class, T Class::*member, class Comp = std::less<>>
class MemberComparator {
	Comp compare;

	static const T& value(const Class& x) noexcept { return x.*member; }

	static const T& value(Class&& x) noexcept { return x.*member; }

	template <class A>
	static A value(A&& a) noexcept {
		return a;
	}

public:
	template <class... Args>
	explicit MemberComparator(Args&&... args)
	: compare(std::forward<Args>(args)...) {}

	template <class A, class B>
	bool operator()(A&& a, B&& b) {
		return compare(value(std::forward<A>(a)), value(std::forward<B>(b)));
	}
};

#define MEMBER_COMPARATOR(Class, member)                                       \
	MemberComparator<decltype(Class::member), Class, &Class::member>