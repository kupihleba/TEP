cmake_minimum_required(VERSION 3.12)
project(proxy)

# We use g++ version 8 to use latest c++17 features
set(CMAKE_CXX_COMPILER g++-8)
set(CMAKE_CXX_STANDARD 17)
set(CXX_STANDARD 17)

if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra  -Wstrict-aliasing -pedantic -fmax-errors=5 -Werror -Wunreachable-code \
    -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs \
    -Wnoexcept -Wold-style-cast -Woverloaded-virtual  -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 \
    -Wswitch-default -Wundef -Wno-unused -Wno-variadic-macros -Wno-parentheses -fdiagnostics-show-option")
    #-Wredundant-decls
endif ()

include_directories(libs/logger/Headers)

#link_libraries(pcap)
link_libraries(pthread)
#link_libraries(dl)
link_libraries(rt)
link_libraries(tins)

# Download here https://netfilter.org/projects/libnetfilter_queue/downloads.html
#link_libraries(nfnetlink) # apt-get install libmnl-dev
link_libraries(mnl)
link_libraries(netfilter_queue)
#link_libraries(iptc)


# execute ldconfig

# add_executable(proxy src/main.cpp libs/logger/Binaries/libP7.a src/cap_exception.cpp src/cap_exception.h src/Logger.cpp src/Logger.h src/FirewallDeprecated.cpp src/FirewallDeprecated.h src/Firewall.cpp src/Firewall.h)
add_executable(proxy src/main.cpp src/Firewall.cpp src/Firewall.h src/Exception.h)

target_link_libraries(proxy ${CMAKE_SOURCE_DIR}/libs/logger/Binaries/libP7.a)
# add_executable(proxy main.cpp src/Sniffer.cpp src/Sniffer.h src/cap_exception.cpp src/cap_exception.h)
