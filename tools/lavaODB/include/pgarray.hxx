#include <cstdint>
#include <sstream>

#include <odb/core.hxx>
#include <odb/pgsql/database.hxx>

// Represent arrays of integers as std::vector.
namespace odb
{
    namespace pgsql
    {
        template <>
        class value_traits<std::vector<uint64_t>, id_string>
        {
        public:
            typedef std::vector<uint64_t> value_type;
            typedef value_type query_type;
            typedef details::buffer image_type;

            static void
            set_value (value_type& v, const details::buffer& b,
                    std::size_t n, bool is_null)
            {
                v.clear ();

                if (!is_null)
                {
                    char c;
                    std::istringstream is (std::string (b.data (), n));

                    is >> c; // '{'

                    for (c = static_cast<char> (is.peek ()); c != '}'; is >> c)
                    {
                        v.push_back (int ());
                        is >> v.back ();
                    }
                }
            }

            static void
            set_image (details::buffer& b, std::size_t& n,
                    bool& is_null, const value_type& v)
            {
                is_null = false;
                std::ostringstream os;

                os << '{';

                for (value_type::const_iterator i (v.begin ()), e (v.end ());
                         i != e;)
                {
                    os << *i;

                    if (++i != e)
                        os << ',';
                }

                os << '}';

                const std::string& s (os.str ());
                n = s.size ();

                if (n > b.capacity ())
                    b.capacity (n);

                std::memcpy (b.data (), s.c_str (), n);
            }
        };

        template<>
        struct type_traits<std::vector<uint64_t> >
        {
             static const database_type_id db_type_id = id_string;
             struct conversion {
                 static const char* to() { return "(?)::BIGINT[]"; }
             };
        };

        template <>
        class value_traits<std::vector<uint32_t>, id_string>
        {
        public:
            typedef std::vector<uint32_t> value_type;
            typedef value_type query_type;
            typedef details::buffer image_type;

            static void
            set_value (value_type& v, const details::buffer& b,
                    std::size_t n, bool is_null)
            {
                v.clear ();

                if (!is_null)
                {
                    char c;
                    std::istringstream is (std::string (b.data (), n));

                    is >> c; // '{'

                    for (c = static_cast<char> (is.peek ()); c != '}'; is >> c)
                    {
                        v.push_back (int ());
                        is >> v.back ();
                    }
                }
            }

            static void
            set_image (details::buffer& b, std::size_t& n,
                    bool& is_null, const value_type& v)
            {
                is_null = false;
                std::ostringstream os;

                os << '{';

                for (value_type::const_iterator i (v.begin ()), e (v.end ());
                         i != e;)
                {
                    os << *i;

                    if (++i != e)
                        os << ',';
                }

                os << '}';

                const std::string& s (os.str ());
                n = s.size ();

                if (n > b.capacity ())
                    b.capacity (n);

                std::memcpy (b.data (), s.c_str (), n);
            }
        };

        template<>
        struct type_traits<std::vector<uint32_t> >
        {
             static const database_type_id db_type_id = id_string;
             struct conversion {
                 static const char* to() { return "(?)::INTEGER[]"; }
             };
        };
    }
}

