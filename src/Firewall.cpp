#include "Firewall.h"
#include "Exception.h"
#include <iostream>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

#define DEBUG false
#define DEB if (DEBUG)

// Typedef aliases for C types
typedef nlmsghdr NetlinkMsgHeader;
typedef nlattr NetlinkAttribute;

//https://netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html
struct fw::Firewall::Implementation {

    friend class Worker;

    explicit Implementation(Firewall *context) :
            super(context),
            isRunning(false) {}

    Firewall *super;

    static mnl_socket *netlink_sock;

    std::atomic_bool isRunning;

    void loop(uint32_t queue_num, QueueBlock *context);

    static int queue_callback(const NetlinkMsgHeader *netlinkMsgHeader, void *data);

    static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data);

    void run(uint32_t queue, QueueBlock *context);

    static void nfq_send_verdict(uint32_t queue_num, uint32_t id, Verdict verdict);

    static NetlinkMsgHeader *nfq_hdr_put(char *buf, int type, uint32_t queue_num);
};

mnl_socket *fw::Firewall::Implementation::netlink_sock;

int fw::Firewall::Implementation::callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                           struct nfq_data *nfa, void *data) {
//        uint32_t id = print_pkt(nfa);
    auto *context = reinterpret_cast<QueueBlock *>(data);
    unsigned char *packet;
    auto packet_len = nfq_get_payload(nfa, &packet);

    auto packet_id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);
    DEB std::cout << "len:" << packet_len << std::endl;

    for (const auto &handler : context->getRawHandlers()) {
        Verdict v = handler(static_cast<uint8_t *>(packet), packet_len / sizeof(uint8_t));
        if (v == Verdict::DROP) {
            DEB std::cout << "DROPPED" << std::endl;
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
        } else if (v == Verdict::CONSUME) {
            DEB std::cout << "CONSUMED" << std::endl;
            return nfq_set_verdict(qh, packet_id, NF_STOLEN, 0, nullptr);

        }
    }

    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
}

void fw::Firewall::Implementation::run(uint32_t queue, QueueBlock *context) {
    int fd;
    struct nfq_handle *h;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    struct nfq_q_handle *qh;

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        throw Exception("error during nfq_open()\n");
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        throw Exception("error during nfq_unbind_pf()\n");
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        throw Exception("error during nfq_bind_pf()\n");
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &callback, context);
    if (!qh) {
        throw Exception("error during nfq_create_queue()\n");
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        throw Exception("can't set packet_copy mode\n");
    }

    printf("setting flags to request UID and GID\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        throw Exception("This kernel version does not allow to "
                        "retrieve process UID/GID.\n");
    }

#ifdef ENABLE_SEC_CONTEXT
    printf("setting flags to request security context\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        throw Exception("This kernel version does not allow to "
                        "retrieve security context.\n");
    }
#endif

    printf("Waiting for packets...\n");

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            DEB printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue %d\n", queue);
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
           * it detaches other programs/sockets from AF_INET, too ! */
          printf("unbinding from AF_INET\n");
          nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
}

void fw::Firewall::Implementation::loop(uint32_t queue_num, QueueBlock *context) {
    char *buf;
    /* largest possible packet payload, plus netlink data overhead: */
    auto sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE);
    NetlinkMsgHeader *nlHeader;
    int ret;
    uint portid;

    netlink_sock = mnl_socket_open(NETLINK_NETFILTER); // open a netlink socket
    if (netlink_sock == nullptr) {
        throw Exception("mnl_socket_open");
    }
    /* mnl_socket_bind - bind netlink socket
        Parameters:
        netlink_sock 	netlink socket obtained via mnl_socket_open()
        groups 	the group of message you're interested in
        pid 	the port ID you want to use (use zero for automatic selection)
    */
    if (mnl_socket_bind(netlink_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw Exception("mnl_socket_bind");
    }
    portid = mnl_socket_get_portid(netlink_sock); //obtain Netlink PortID from netlink socket

    buf = static_cast<char *>(alloca(sizeof_buf * sizeof(char)));
    if (!buf) {
        throw Exception("allocate receive buffer");
    }

//   PF_(UN)BIND is not needed with kernels 3.8 and later
    if constexpr (config::OLD_KERNEL) {
        nlHeader = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
        nfq_nlmsg_cfg_put_cmd(nlHeader, AF_INET, NFQNL_CFG_CMD_PF_UNBIND);

        if (mnl_socket_sendto(netlink_sock, nlHeader, nlHeader->nlmsg_len) < 0) {
            throw Exception("mnl_socket_send");
        }

        nlHeader = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
        nfq_nlmsg_cfg_put_cmd(nlHeader, AF_INET, NFQNL_CFG_CMD_PF_BIND);

        if (mnl_socket_sendto(netlink_sock, nlHeader, nlHeader->nlmsg_len) < 0) {
            throw Exception("mnl_socket_send");
        }
    }

    nlHeader = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlHeader, AF_INET, NFQNL_CFG_CMD_BIND);
    printf("init success\n");
    if (mnl_socket_sendto(netlink_sock, nlHeader, nlHeader->nlmsg_len) < 0) {
        throw Exception("mnl_socket_send");
    }

    nlHeader = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlHeader, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlHeader, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlHeader, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(netlink_sock, nlHeader, nlHeader->nlmsg_len) < 0) {
        throw Exception("mnl_socket_send");
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */
    ret = 1;
    mnl_socket_setsockopt(netlink_sock, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    while (true) {
        ret = mnl_socket_recvfrom(netlink_sock, buf, sizeof_buf);
        if (ret == -1) {
            throw Exception("mnl_socket_recvfrom");
        }

        ret = mnl_cb_run(buf, ret, 0, portid, Implementation::queue_callback, reinterpret_cast<void *>(context));
        if (ret < 0) {
            throw Exception("mnl_cb_run");
        }
    }

    mnl_socket_close(netlink_sock);
}


NetlinkMsgHeader *fw::Firewall::Implementation::nfq_hdr_put(char *buf, int type, uint32_t queue_num) {
    NetlinkMsgHeader *nlHeader = mnl_nlmsg_put_header(buf);
    nlHeader->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlHeader->nlmsg_flags = NLM_F_REQUEST;

    nfgenmsg *nfg = static_cast<nfgenmsg *>(mnl_nlmsg_put_extra_header(nlHeader, sizeof(*nfg)));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlHeader;
}

void fw::Firewall::Implementation::nfq_send_verdict(uint32_t queue_num, uint32_t id, Verdict verdict) {
    char *buf = static_cast<char *>(alloca(MNL_SOCKET_BUFFER_SIZE));
    NetlinkMsgHeader *nlHeader;
    NetlinkAttribute *nest;

    nlHeader = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlHeader, id, static_cast<int>(verdict));

    /* example to set the connmark. First, start NFQA_CT section: */
    nest = mnl_attr_nest_start(nlHeader, NFQA_CT);

    /* then, add the connmark attribute: */
    mnl_attr_put_u32(nlHeader, CTA_MARK, htonl(42));
    /* more conntrack attributes, e.g. CTA_LABEL, could be set here */

    /* end conntrack section */
    mnl_attr_nest_end(nlHeader, nest);

    if (mnl_socket_sendto(netlink_sock, nlHeader, nlHeader->nlmsg_len) < 0) {
        throw Exception("mnl_socket_send");
    }
}

[[nodiscard]]
int fw::Firewall::Implementation::queue_callback(const NetlinkMsgHeader *netlinkMsgHeader, void *data) {

    nfqnl_msg_packet_hdr *packetHeader = nullptr;
    NetlinkAttribute *attr[NFQA_MAX + 1] = {};
    uint32_t packet_id = 0, skbinfo;
    nfgenmsg *nfg;
    uint16_t payloadLength;
    auto *context = reinterpret_cast<QueueBlock *>(data);

    if (nfq_nlmsg_parse(netlinkMsgHeader, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }


    nfg = static_cast<nfgenmsg *>(mnl_nlmsg_get_payload(netlinkMsgHeader));

    if (attr[NFQA_PACKET_HDR] == nullptr) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    packetHeader = static_cast<nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));


    payloadLength = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != payloadLength)
            printf("truncated ");
    }

    if (skbinfo & NFQA_SKB_GSO)
        printf("GSO ");

    packet_id = ntohl(packetHeader->packet_id);
    printf("packet received (packet_id=%u hw=0x%04x hook=%u, payload len %u",
           packet_id, ntohs(packetHeader->hw_protocol), packetHeader->hook, payloadLength);

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
    if (skbinfo & NFQA_SKB_CSUMNOTREADY)
        printf(", checksum not ready");
    puts(")");

    for (const auto &handler : context->getRawHandlers()) {
        Verdict v = handler(static_cast<uint8_t *>(payload), payloadLength / sizeof(uint8_t));
        if (v == Verdict::DROP) {
            nfq_send_verdict(ntohs(nfg->res_id), packet_id, Verdict::DROP);
//            std::cout << "DROPPED" << std::endl;
            return MNL_CB_OK;
        } else if (v == Verdict::CONSUME) {
            nfq_send_verdict(ntohs(nfg->res_id), packet_id, Verdict::CONSUME);
//            std::cout << "CONSUMED" << std::endl;
            return MNL_CB_OK;
        }
    }

    Tins::IP pdu(static_cast<const uint8_t *>(payload), payloadLength / sizeof(uint8_t));
    //Tins::IP ip(static_cast<const uint8_t *>(payload), payloadLength);
    //Tins::PacketSender sender;
    try {
        auto *ip = pdu.find_pdu<Tins::IP>();

        if (ip != nullptr) {
            for (auto &handler : context->getHandlers()) {
                handler(*ip);
            }
        }

        //sender.send(ip);

        //nfq_send_verdict(ntohs(nfg->res_id), packet_id, Verdict::DROP);
        nfq_send_verdict(ntohs(nfg->res_id), packet_id, Verdict::ACCEPT);
        return MNL_CB_OK;

    } catch (const std::exception &err) {
        std::cout << err.what();
    }

    nfq_send_verdict(ntohs(nfg->res_id), packet_id, Verdict::ACCEPT);

    return MNL_CB_OK;
}

fw::Firewall &fw::Firewall::instance() {
    static Firewall fw;
    return fw;
}


fw::Firewall::Firewall() {
    pImpl = std::make_unique<Implementation>(this);
}


void fw::Firewall::loopOver(uint32_t queue, QueueBlock *context) {
//    pImpl->loop(queue, context);
    printf("context %p", static_cast<void *>(context));
    pImpl->run(queue, context);
}

fw::QueueBlock &fw::Firewall::initQueue(uint32_t queue) {
    queues.emplace_back(queue);
    std::cout << "initQueue" << std::endl;
    return queues.back();
}

fw::Firewall::~Firewall() {
    std::cout << "FW is dead!" << std::endl;
}

void fw::Firewall::run() {
    for (auto &q : queues) {
        q.run();
    }

}


fw::QueueBlock &fw::QueueBlock::addHandler(handler_ip_t &&handler) {
    handlers.emplace_back(handler);
    return *this;
}

fw::QueueBlock &fw::QueueBlock::addHandler(const handler_ip_t &handler) {
    handlers.push_back(handler);
    return *this;
}

const std::vector<fw::handler_ip_t> &fw::QueueBlock::getHandlers() const {
    return handlers;
}

fw::QueueBlock &fw::QueueBlock::addRawHandler(handler_raw_t &&handler) {
    rawHandlers.push_back(std::move(handler));
    return *this;
}

const std::vector<fw::handler_raw_t> &fw::QueueBlock::getRawHandlers() const {
    return rawHandlers;
}

fw::QueueBlock::QueueBlock(uint32_t queue)
        : queue_start_index(queue), queue_n(1) {
    std::cout << "QueueBlock constructor arg " << queue_start_index << std::endl;
}

fw::QueueBlock &fw::QueueBlock::spawnWorkers() {
    for (auto &w : workers) {
        w.stop();
    }
    for (auto &w : workers) {
        w.join();
    }
    workers.clear();
    for (int i = 0; i < queue_n; i++) {
        workers.emplace_back([i](QueueBlock *context) -> void {
            printf("[] context %p", static_cast<void *>(context));
            fw::Firewall::instance().loopOver(context->queue_start_index + i, context);
        });
    }
    return *this;
}

void fw::QueueBlock::run() {
    for (auto &w : workers) {
        w.start(this);
    }
}

fw::QueueBlock::~QueueBlock() {
    std::cout << "Queue Block_" << queue_start_index << ": \"I'm dead!\"" << std::endl;
}

//fw::QueueBlock::QueueBlock(fw::QueueBlock &&qb) noexcept
//        : queue_start_index(qb.queue_start_index),
//          queue_n(qb.queue_n),
//          workers(std::move(qb.workers)),
//          rawHandlers(std::move(qb.rawHandlers)),
//          handlers(std::move(qb.handlers)) {
//    std::cout << "q_s_i:" << queue_start_index << std::endl;
//    std::cout << "n:" << queue_n << std::endl;
////    for (auto &rh : qh.raw)
//}

//fw::QueueBlock::QueueBlock(const fw::QueueBlock &qb)
//    :workers(qb.workers),
//    rawHandlers(qb.rawHandlers),
//    handlers(qb.handlers) {
//    this->queue_start_index = qb.queue_start_index;
//    this->queue_n = qb.queue_n;
//}
