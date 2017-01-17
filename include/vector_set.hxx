#include <algorithm>
#include <vector>

template<typename T, class Compare = std::less<T> >
class vector_set {
private:
    std::vector<T> contents;
    typedef typename std::vector<T>::iterator iterator;
    typedef typename std::vector<T>::const_iterator const_iterator;
    Compare comp;

    inline std::pair<iterator, bool> insert_internal(iterator hint, const T& val) {
        // precondition *hint is lower bound of val, i.e. first elem >=.
        if (hint == contents.end() || comp(val, *hint)) {
            return std::make_pair(contents.insert(hint, val), true);
        } else {
            return std::make_pair(hint, false);
        }
    }

    inline std::pair<iterator, bool> insert_internal(iterator hint, T&& val) {
        if (hint == contents.end() || comp(val, *hint)) {
            return std::make_pair(contents.insert(hint, std::move(val)), true);
        } else {
            return std::make_pair(hint, false);
        }
    }

public:
    struct already_sorted_t {};

    template<typename... Args>
    vector_set(Args&&... args) : contents(std::forward<Args>(args)...) {
        std::sort(contents.begin(), contents.end(), comp);
    }

    template<typename... Args>
    vector_set(Args&&... args, already_sorted_t x)
        : contents(std::forward<Args>(args)...) {}

    inline iterator begin() { return contents.begin(); }
    inline const_iterator begin() const { return contents.begin(); }
    inline const_iterator cbegin() const { return contents.cbegin(); }
    inline iterator end() { return contents.end(); }
    inline const_iterator end() const { return contents.end(); }
    inline const_iterator cend() const { return contents.cend(); }

    std::pair<iterator, bool> insert(T&& val) {
        auto it = std::lower_bound(contents.begin(), contents.end(), val, comp);
        return insert_internal(it, std::move(val));
    }

    std::pair<iterator, bool> insert(const T& val) {
        auto it = std::lower_bound(contents.begin(), contents.end(), val, comp);
        return insert_internal(it, val);
    }

    iterator insert(iterator hint, T&& val) {
        return insert_internal(hint, std::move(val)).first;
    }

    iterator insert(iterator hint, const T &val) {
        return insert_internal(hint, val).first;
    }

    const_iterator find(const T &val) const {
        return std::binary_search(contents.cbegin(), contents.cend(), val, comp);
    }

    iterator find(const T &val) {
        return std::binary_search(contents.begin(), contents.end(), val, comp);
    }

    iterator erase(iterator it) {
        return contents.erase(it);
    }

    size_t erase(const T &val) {
        auto it = std::binary_search(
                contents.begin(), contents.end(), val, comp);
        if (it == contents.end()) return 0;
        else {
            erase(it);
            return 1;
        }
    }
};
