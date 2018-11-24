#include "Firewall.h"
#include "Exception.h"
#include <iostream>

using namespace fw;

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

enum Verdict {
    ACCEPT = NF_ACCEPT,
    DROP = NF_DROP
};

// Typedef aliases for C types
typedef nlmsghdr NetlinkMsgHeader;
typedef nlattr NetlinkAttribute;

struct Firewall::Implementation {
    Implementation() : isRunning(false) {}

    static mnl_socket *netlink_sock;

    std::atomic_bool isRunning;

    void loop(int queue_num);

    static int queue_callback(const NetlinkMsgHeader *netlinkMsgHeader, void *data);

    static void nfq_send_verdict(int queue_num, uint32_t id, Verdict verdict);

    static NetlinkMsgHeader *nfq_hdr_put(char *buf, int type, uint32_t queue_num);
};

mnl_socket *Firewall::Implementation::netlink_sock;

void Firewall::Implementation::loop(int queue_num) {
    char *buf;
    /* largest possible packet payload, plus netlink data overhead: */
    auto sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE);
    NetlinkMsgHeader *nlHeader;
    int ret;
    unsigned int portid;

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
    portid = mnl_socket_get_portid(netlink_sock);

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

    while (isRunning) {
        ret = mnl_socket_recvfrom(netlink_sock, buf, sizeof_buf);
        if (ret == -1) {
            throw Exception("mnl_socket_recvfrom");
        }

        ret = mnl_cb_run(buf, ret, 0, portid, Implementation::queue_callback, buf);
        if (ret < 0) {
            throw Exception("mnl_cb_run");
        }
    }

    mnl_socket_close(netlink_sock);
}


NetlinkMsgHeader *Firewall::Implementation::nfq_hdr_put(char *buf, int type, uint32_t queue_num) {
    NetlinkMsgHeader *nlHeader = mnl_nlmsg_put_header(buf);
    nlHeader->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlHeader->nlmsg_flags = NLM_F_REQUEST;

    nfgenmsg *nfg = static_cast<nfgenmsg *>(mnl_nlmsg_put_extra_header(nlHeader, sizeof(*nfg)));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlHeader;
}

void Firewall::Implementation::nfq_send_verdict(int queue_num, uint32_t id, Verdict verdict) {
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
int Firewall::Implementation::queue_callback(const NetlinkMsgHeader *netlinkMsgHeader, void *data) {

    nfqnl_msg_packet_hdr *packetHeader = nullptr;
    NetlinkAttribute *attr[NFQA_MAX + 1] = {};
    uint32_t _id = 0, skbinfo;
    nfgenmsg *nfg;
    uint16_t payloadLength;

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

    _id = ntohl(packetHeader->packet_id);
    printf("packet received (_id=%u hw=0x%04x hook=%u, payload len %u",
           _id, ntohs(packetHeader->hw_protocol), packetHeader->hook, payloadLength);

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

    Tins::IP pdu(static_cast<const uint8_t *>(payload), payloadLength);
    //Tins::IP ip(static_cast<const uint8_t *>(payload), payloadLength);
    //Tins::PacketSender sender;
    try {
        auto *ip = pdu.find_pdu<Tins::IP>();
        if (ip != nullptr) {
            auto *tcp = pdu.find_pdu<Tins::TCP>();
            auto *udp = pdu.find_pdu<Tins::UDP>();

            if (tcp != nullptr) {
                std::cout << ip->src_addr() << ':' << tcp->sport() << " -> " << ip->dst_addr() << ':' << tcp->dport()
                          << " [TCP]"
                          << std::endl;

            } else if (udp != nullptr) {
                std::cout << ip->src_addr() << ':' << udp->sport() << " -> " << ip->dst_addr() << ':' << udp->dport()
                          << " [UDP]"
                          << std::endl;
            } else {
                std::cout << ip->src_addr() << " -> " << ip->dst_addr() << " [IP]" << std::endl;
            }
        }

        //sender.send(ip);

        //nfq_send_verdict(ntohs(nfg->res_id), _id, Verdict::DROP);
        nfq_send_verdict(ntohs(nfg->res_id), _id, Verdict::ACCEPT);
        return MNL_CB_OK;

    } catch (const std::exception &err) {
        std::cout << err.what();
    }

    nfq_send_verdict(ntohs(nfg->res_id), _id, Verdict::ACCEPT);

    return MNL_CB_OK;
}

void Firewall::run() {
    if (!pImpl->isRunning) {
        pImpl->isRunning.store(true);
        pImpl->loop(0);
    }
}

Firewall &Firewall::instance() {
    static Firewall fw;
    return fw;
}

void Firewall::stop() {
    pImpl->isRunning.store(false);
}

void Firewall::addHandler(Firewall::handler_t &&handler) {
    handlers.push_back(std::move(handler));
    handler = nullptr;
}

void Firewall::addHandler(const Firewall::handler_t &handler) {
    handlers.emplace_back(handler);
}

fw::Firewall::Firewall() {
    pImpl = std::make_unique<Implementation>();
}
