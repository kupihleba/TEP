#pragma once

#include <functional>
#include <tins/tins.h>
#include <atomic>
#include <thread>
#include <libmnl/libmnl.h>
#include <vector>
#include <experimental/propagate_const>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <iostream>

namespace fw {

    class Worker;

    enum Verdict {
        ACCEPT = NF_ACCEPT,
        DROP = NF_DROP,
        CONSUME = NF_STOLEN
    };

    using std::vector;

    namespace config {
        // kernels 3.8 and later treated new
        // use OLD_KERNEL option on kernels < 3.8
        static const bool OLD_KERNEL = false;
    }
    class QueueBlock;

    using handler_ip_t = std::function<Verdict(Tins::IP &packet)>;
    using handler_raw_t = std::function<Verdict(uint8_t *data, uint32_t length)>;

/**
 * Meyers Singleton Firewall class
 */
    class Firewall {
    public:

        Firewall(const Firewall &) = delete;

        Firewall &operator=(Firewall &) = delete;


        QueueBlock &initQueue(uint32_t queue);

        void loopOver(uint32_t queue, QueueBlock *context);

        static Firewall &instance();

        /**
         * Start all workers
         */
        void run();

    private:
        // Pointer to implementation idiom
        friend class Worker;
        struct Implementation;

        //std::unique_ptr<Implementation> pImpl;
        std::experimental::propagate_const<std::unique_ptr<Implementation>> pImpl;

        std::vector<QueueBlock> queues; // TODO create std::shared_ptr<>

        Firewall();

        ~Firewall();
    };

    class QueueBlock {

    public:
        explicit QueueBlock(uint32_t queue);

//        QueueBlock(const QueueBlock&);

//        QueueBlock(QueueBlock&&) noexcept;
//        QueueBlock &operator=(QueueBlock &) = delete;


        ~QueueBlock();

        QueueBlock &addHandler(handler_ip_t &&handler);

        QueueBlock &addRawHandler(handler_raw_t &&handler);

        QueueBlock &addHandler(const handler_ip_t &handler);

        const vector<handler_ip_t> &getHandlers() const;

        const vector<handler_raw_t> &getRawHandlers() const;

        QueueBlock &spawnWorkers();


    private:
        uint32_t queue_start_index;
        int queue_n;

        vector<Worker> workers;

        vector<handler_raw_t> rawHandlers;
        vector<handler_ip_t> handlers;

        friend class Firewall;

        void run();
    };

    class Worker {
    public:

        using work_fun_t = std::function<void(fw::QueueBlock *)>;


        Worker(Worker &&w) noexcept
                : interrupted(w.interrupted.load()),
                  work(std::move(w.work)) {
        }

        Worker(const Worker &w)
                : interrupted(w.interrupted.load()),
                  work(w.work) {
        }

        explicit Worker(work_fun_t &&work)
                : interrupted(false),
                  work(std::move(work)) {
        }

        void start(QueueBlock *context) {
            interrupted.store(false);
            thread = std::make_unique<std::thread>([&](QueueBlock *context) -> void {
                std::cout << "thread started" << std::endl;
                while (!interrupted.load()) {
                    work(context);
                }
                std::cout << "thread done" << std::endl;
            }, context);
            thread->detach();
        }

        void stop() {
            interrupted.store(true);
        }

        void join() {}

    private:
        std::atomic_bool interrupted;

        work_fun_t work;

//        static thread_local uint32_t queue;

        std::unique_ptr<std::thread> thread;
    };
}
