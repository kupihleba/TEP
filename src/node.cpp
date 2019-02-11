#include "Firewall.h"
#include <sstream>
#include <chrono>
#include <tins/tins.h>
#include <zmq.hpp>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>

#include "Exception.h"
#include "Link.h"
#include "Firewall.h"
#include "Crypton.h"
#include "Header.h"

#define ENABLE_NAT

static int START_RANGE;
static int END_RANGE;
static string my_IP;
static uint32_t OUTGOING_QUEUE_INDEX;
static uint32_t INCOMING_QUEUE_INDEX;
static bool ENCRYPTION;

#define DEBUG true
#define DEB if (DEBUG)

static std::unordered_map<Link, Link> inetToLocal;
static std::unordered_map<Link, Link> localToInet;
static std::unordered_map<uint32_t, zmq::socket_t> connections;


static int start = START_RANGE, end = START_RANGE;

void loadConfigs() {
    std::ifstream ifs("node.config");
    Json::Reader reader;
    Json::Value val;
    reader.parse(ifs, val);

    START_RANGE = val["queue"]["start_range"].asInt();
    END_RANGE = val["queue"]["end_range"].asInt();
    my_IP = val["self_ip"].asString();
    OUTGOING_QUEUE_INDEX = val["outgoing_q_index"].asUInt();
    INCOMING_QUEUE_INDEX = val["incoming_q_index"].asUInt();
    ENCRYPTION = val["encryption"].asBool();
}

Link createNatLink(const Link &link) {
    auto match = localToInet.find(link);
    if (match != localToInet.end()) {
        return match->second;
    }

    if (end >= END_RANGE) {
        throw Exception("No ports left!");
    }
    Link tmp(link);
    tmp.setSource(my_IP);
    tmp.setSrc_port(end++);

    inetToLocal.insert(std::pair{link, tmp});
    localToInet.insert(std::pair{tmp, link});

    return link;
}

void reverseNAT(Tins::IP &packet) {
    auto src = packet.src_addr();
    auto dst = packet.dst_addr();
    Link searchLink(src, dst); // reversed arguments!
    auto match = inetToLocal.find(searchLink);
    if (match == inetToLocal.end()) { // Connection is new
        DEB std::cout << "NO NAT DATA!" << std::endl;
    } else {
        auto new_dst = match->second.getDestination();
        packet.dst_addr(new_dst);
    }
}

void applyNAT(Tins::IP &packet) {
    using std::pair;
    auto src_ip = packet.src_addr();
    auto dst_ip = packet.dst_addr();

    DEB std::cout << src_ip << std::endl;
    DEB std::cout << dst_ip << std::endl;

    Link link_back(dst_ip, src_ip);
    Link link(src_ip, dst_ip);

    packet.src_addr(my_IP); // modify to local IP
    Link nat_link_back(packet.dst_addr(), packet.src_addr());
    Link nat_link(packet.src_addr(), packet.dst_addr());

    auto match = localToInet.find(link_back);
    if (match == localToInet.end()) { // Connection is new
        inetToLocal.insert(pair{nat_link_back, link_back});
        localToInet.insert(pair{link, nat_link});
    }
    for (auto &i : inetToLocal) {
        DEB std::cout << '(' << i.first.getSource() << ',' << i.first.getDestination() << ") -> ("
                      << i.second.getSource() << ',' << i.second.getDestination() << ')' << std::endl;
    }
}


int main() {
    loadConfigs();
    std::cout << "sizeof(Header) = " << sizeof(Header) << std::endl;

#if AUTO_IPTABLES
    //    system("iptables -A INPUT ! -d 192.168.1.1 -j NFQUEUE --queue-num " + OUTGOING_QUEUE_INDEX);
    system((string("iptables -A INPUT ! -s 192.168.100.0/24 -j NFQUEUE --queue-num ") + std::to_string(INCOMING_QUEUE_INDEX)).c_str());
#endif

    zmq::context_t context = zmq::context_t(1);
    zmq::socket_t publisher(context, ZMQ_PUB);
    Tins::IPv4Address last_addr(my_IP);

    fw::Firewall::instance().initQueue(INCOMING_QUEUE_INDEX).addRawHandler(
            [&publisher, &last_addr](uint8_t *data, uint32_t length) -> fw::Verdict {
                try {

                    Tins::IP packet(data, length);

                    Link link(packet);
                    DEB std::cout << "ANSW SRC:\t" << packet.src_addr() << std::endl <<
                                  "DST:\t" << packet.dst_addr() << std::endl;

#ifdef ENABLE_NAT
                    reverseNAT(packet);
#endif
                    if (last_addr != packet.dst_addr()) {
                        publisher.connect("tcp://" + packet.dst_addr().to_string() + ":5000");
                        last_addr = packet.dst_addr();
                    }

                    auto serialized = packet.serialize();
                    auto *ptr = static_cast<uint8_t *>(serialized.data());
                    packet = Tins::IP(static_cast<uint8_t *>(data), length);
                    DEB std::cout << "ANSW RNAT SRC:\t" << Tins::IP(ptr, serialized.size()).src_addr() << std::endl <<
                                  "DST:\t" << Tins::IP(ptr, serialized.size()).dst_addr() << std::endl;

                    publisher.send(serialized.data(), serialized.size());

                } catch (Tins::malformed_packet &e) {
                    std::cout << std::string(e.what()) << std::endl;
                } catch (std::exception &e) {
                    std::cout << std::string(e.what()) << std::endl;
                }
                return fw::Verdict::DROP;
            }).spawnWorkers();

    fw::Firewall::instance().run();

    using Tins::IP, Tins::TCP, Tins::RawPDU;
    zmq::socket_t subscriber(context, ZMQ_SUB);
    subscriber.bind("tcp://*:5000");
    subscriber.setsockopt(ZMQ_SUBSCRIBE, "", 0);
    std::cout << "Bind" << std::endl;

    Tins::PacketSender sender;
    Crypton crypton;
    std::vector<std::byte> key(16);
    std::fill(key.begin(), key.end(), (std::byte) 0x00);
    while (true) {
        try {
            zmq::message_t msg;
            subscriber.recv(&msg);

            IP packet;
            Header *header;
            if (ENCRYPTION) {
                auto dec = crypton.decrypt(reinterpret_cast<std::byte *>(msg.data()), msg.size(), key.data(),
                                           key.size());

                packet = IP(reinterpret_cast<uint8_t *>(dec.data() + sizeof(Header)), dec.size());
                header = reinterpret_cast<Header *>(dec.data());
            } else {
                packet = IP(reinterpret_cast<uint8_t *>(reinterpret_cast<std::byte *>(msg.data()) + sizeof(Header)),
                            msg.size());
                header = reinterpret_cast<Header *>(msg.data());
            }

            Tins::IP *ip = packet.find_pdu<Tins::IP>();

            if (ip != nullptr) {
                applyNAT(*ip);
                Tins::IP *p = packet.find_pdu<Tins::IP>();
                DEB std::cout << "ZMQ NAT:\t" << p->src_addr() << " --> " << p->dst_addr() << "\tlen: " << msg.size()
                              << std::endl;
                sender.send(packet);
            } else {
                DEB std::cout << "RAW" << std::endl;
                sender.send(packet);
            }
        } catch (Tins::malformed_packet &p) {
            std::cout << p.what() << std::endl;
        }
    }
}