#pragma once

#include <functional>
#include <tins/tins.h>
#include <atomic>
#include <thread>
#include <libmnl/libmnl.h>
#include <vector>

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

        Firewall() : isRunning(false) {};

        std::vector<handler_t> handlers;

        std::atomic_bool isRunning;

        void loop(int queue_num);

        static int queue_callback(const nlmsghdr *nlh, void *data);

        //void nfq_send_verdict(int queue_num, uint32_t id, Verdict verdict);

        //nlmsghdr *nfq_hdr_put(char *buf, int type, uint32_t queue_num);
    };
}


