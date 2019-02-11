#include "Firewall.h"
#include <sstream>
#include <chrono>
#include <tins/tins.h>
#include <zmq.hpp>
#include <thread>
#include <iostream>
#include <string>
#include "Crypton.h"
#include "Header.h"
#include <jsoncpp/json/json.h>
#include <fstream>


#define DEBUG true
#define DEB if (DEBUG)

using std::string;

// Configs
static string NODE;
static string LOCAL_NET;
static string MY_IP;
static const int32_t POST_PORT(5000);
static bool ENCRYPTION;

void loadConfigs() {
    std::ifstream ifs("proxy.config");
    Json::Reader reader;
    Json::Value val;
    reader.parse(ifs, val);

    MY_IP = val["self_ip"].asString();
    NODE = val["node_ip"].asString();
    LOCAL_NET = val["local_net"].asString();
    ENCRYPTION = val["encryption"].asBool();
}

int main() {
    loadConfigs();

    std::cout << "sizeof(Header) = " << sizeof(Header) << std::endl;
#ifdef AUTO_IPTABLES
    system("iptables -N vpnOUT");
    system(("iptables -A vpnOUT -d " + NODE + " -j RETURN").c_str());
//    system(("iptables -A vpnOUT -d 192.168.1.1 -j NFQUEUE --queue-num 0"));
//    system(("iptables -A vpnOUT -d " + LOCAL_NET + " -j RETURN").c_str());
    system(("iptables -A vpnOUT -d " + MY_IP + " -j RETURN").c_str());
    system(("iptables -A vpnOUT ! -s " + LOCAL_NET + " -j RETURN").c_str());

    system(("iptables -A vpnOUT -j NFQUEUE --queue-num 0"));
    system("iptables -A OUTPUT -j vpnOUT");
#endif

//    system("iptables -A OUTPUT ! -d 192.168.1.218 -j NFQUEUE --queue-num 0"); // Pass all outgoing traffic to the 0 queue
//    const string rule_out( "iptables -A OUTPUT ! -d " + NODE + "," + LOCAL_NET + " -j NFQUEUE --queue-num 0"); // OUTGOING TRAFFIC
//    system(rule_out.c_str());
//    const string rule_in( "iptables -A INPUT -s " + NODE + " -j NFQUEUE --queue-num 1"); // RECEIVED TRAFFIC
//    system(rule_in.c_str());
//    system("iptables -A OUTPUT -j NFQUEUE --queue-balance 0:1");

    zmq::context_t context(1);

    zmq::socket_t publisher(context, ZMQ_PUB);
    publisher.connect("tcp://" + NODE + ":5000");

    Crypton crypton;

    std::vector<std::byte> key(16);
    std::fill(key.begin(), key.end(), (std::byte) 0x00);
    fw::Firewall::instance().initQueue(0) // Encapsulate and send traffic to the exit node
            .addRawHandler([&publisher, &crypton, &key, ip = MY_IP, port = POST_PORT]
                                   (const uint8_t *data, uint32_t length) -> fw::Verdict {
                DEB std::cout << length << "->" << std::endl;

                Header header(reinterpret_cast<const std::byte *>(data), length, ip, port);

                auto ptr = reinterpret_cast<std::byte *>(&header);
                std::vector<std::byte> parsel(ptr, ptr + sizeof(Header));
                parsel.insert(
                        parsel.end(),
                        std::move_iterator(reinterpret_cast<const std::byte *>(data)),
                        std::move_iterator(reinterpret_cast<const std::byte *>(data) + length)
                );
                if (ENCRYPTION) {
//                    auto encrypted = crypton.encrypt(reinterpret_cast<const std::byte *>(data), length, key.data(),
//                                                     key.size());
                    auto encrypted = crypton.encrypt(parsel, key);
                    publisher.send(encrypted.data(), encrypted.size());
                } else {
                    publisher.send(parsel.data(), parsel.size());
                }
                return fw::Verdict::DROP;
            }).spawnWorkers();

    zmq::socket_t subscriber(context, ZMQ_SUB); // Subscribe for replies
    subscriber.bind("tcp://*:5000");
    subscriber.setsockopt(ZMQ_SUBSCRIBE, "", 0);

    Tins::PacketSender sender;

    fw::Firewall::instance().run();


    while (true) {
        zmq::message_t msg;
        subscriber.recv(&msg);
//        std::cout << msg.size() << std::endl;
#if 0
        try {
            std::cout << "Trying to parse packet len " << msg.size() << std::endl;
            Tins::PDU::serialization_type serialized;
            serialized.resize(msg.size());
            std::memcpy(serialized.data(), msg.data(), msg.size());
            Tins::RawPDU packet(serialized.data(), serialized.size());

            Tins::IP *ip = packet.find_pdu<Tins::IP>();
//
        if (ip != nullptr) {
            ip->dst_addr("192.168.1.10");
            std::cout << "ANSWER:\t" << ip->src_addr() << " --> " << ip->dst_addr() << "\tlen: " << msg.size()
                      << std::endl;
            try {
                sender.send(packet); // Simply send this packet
            } catch (Tins::malformed_packet &e) {
                std::cout << "send loop" << e.what() << std::endl;
            }
        } else {
            sender.send(packet);
        }
        } catch (Tins::malformed_packet &e) {
            std::cout << "error" << std::endl;
        }
#else
        try {
            Tins::IP packet(static_cast<uint8_t *>(msg.data()), msg.size());
//        packet.dst_addr("192.168.1.10");
            DEB std::cout << "got\t\t" << packet.src_addr() << '\t' << msg.size() << std::endl;
            sender.send(packet);
        } catch (Tins::malformed_packet &p) {
            std::cout << "ERROR!!!\n" << p.what() << std::endl;
        }
#endif
    }
}