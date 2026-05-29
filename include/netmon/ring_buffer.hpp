#pragma once

#include <cstddef>
#include <deque>
#include <vector>

namespace netmon {

template <typename T>
class RingBuffer {
 public:
  explicit RingBuffer(std::size_t capacity = 0) : capacity_(capacity) {}

  void setCapacity(std::size_t capacity) {
    capacity_ = capacity;
    trim();
  }

  void push(T value) {
    if (capacity_ == 0) {
      return;
    }
    items_.push_back(std::move(value));
    trim();
  }

  std::vector<T> items(std::size_t limit = 0) const {
    std::vector<T> out;
    if (items_.empty()) {
      return out;
    }

    const std::size_t wanted = limit == 0 || limit > items_.size() ? items_.size() : limit;
    out.reserve(wanted);
    const std::size_t start = items_.size() - wanted;
    for (std::size_t i = start; i < items_.size(); ++i) {
      out.push_back(items_[i]);
    }
    return out;
  }

  const std::deque<T>& raw() const { return items_; }
  std::deque<T>& raw() { return items_; }

  std::size_t size() const { return items_.size(); }
  std::size_t capacity() const { return capacity_; }
  bool empty() const { return items_.empty(); }
  void clear() { items_.clear(); }

 private:
  void trim() {
    while (capacity_ > 0 && items_.size() > capacity_) {
      items_.pop_front();
    }
    if (capacity_ == 0) {
      items_.clear();
    }
  }

  std::size_t capacity_ = 0;
  std::deque<T> items_;
};

}  // namespace netmon
