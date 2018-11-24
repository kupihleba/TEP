#pragma once

#include <functional>
#include <tins/tins.h>
#include <atomic>
#include <thread>
#include <libmnl/libmnl.h>
#include <vector>
#include <experimental/propagate_const>

namespace fw {

    using std::vector;

    namespace config {
        // kernels 3.8 and later treated new
        // use OLD_KERNEL option on kernels < 3.8
        static const bool OLD_KERNEL = false;
    }


/**
 * Meyers Singleton Firewall class
 */
    class Firewall {
    public:
        Firewall(const Firewall &) = delete;

        Firewall &operator=(Firewall &) = delete;

        void run();

        void stop();

        typedef std::function<bool(Tins::IP &packet)> handler_t;

        void addHandler(handler_t &&handler);

        void addHandler(const handler_t &handler);

        static Firewall &instance();

    private:
        // Pointer to implementation idiom
        struct Implementation;
        //std::unique_ptr<Implementation> pImpl;
        std::experimental::propagate_const<std::unique_ptr<Implementation>> pImpl;

        Firewall();

        std::vector<handler_t> handlers;
    };
}


