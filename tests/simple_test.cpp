#define BOOST_UT_DISABLE_MODULE
#include <boost/ut.hpp>

int main() {
    using namespace boost::ut;
    
    "simple_test"_test = [] {
        expect(2 + 2 == 4_i);
        expect(true);
    };
    
    return 0;
}
