#pragma once

#include <zmq.hpp>
#include "Firewall.h"
#include "Crypton.h"

void testRun(zmq::context_t *context, const std::string &node) {
    zmq::socket_t publisher(*context, ZMQ_PUB);
    publisher.connect("tcp://" + node + ":5000");

//    zmq::message_t x;

    fw::Firewall::instance().initQueue(0).addRawHandler(
            [&publisher](const uint8_t *data, uint32_t length) -> fw::Verdict {
                using Tins::IP, Tins::TCP, Tins::RawPDU;
                std::cout << "Forwarding " << length << " bytes" << std::endl;
                //IP packet = IP("10.10.10.10") / TCP() / RawPDU(data, length);
                //Tins::PacketSender sender;
                //sender.send(packet);

                IP ip(data, length);

                auto *tcp = ip.find_pdu<Tins::TCP>();
                auto *udp = ip.find_pdu<Tins::UDP>();

                if (tcp != nullptr) {
                    std::cout << ip.src_addr() << ':' << tcp->sport() << " -> " << ip.dst_addr() << ':' << tcp->dport()
                              << " [TCP]"
                              << std::endl;

                } else if (udp != nullptr) {
                    std::cout << ip.src_addr() << ':' << udp->sport() << " -> " << ip.dst_addr() << ':' << udp->dport()
                              << " [UDP]"
                              << std::endl;
                } else {
                    std::cout << ip.src_addr() << " -> " << ip.dst_addr() << " [IP]" << std::endl;
                }

                publisher.send(data, length);

                return fw::Verdict::DROP;
            }).spawnWorkers();

    fw::Firewall::instance().run();


    std::cout << "Resources destroyed" << std::endl;
    publisher.close();
    context->close();
}

void testCrypton() {
    std::string data("test string here 123 qwerty");

    Crypton crypton;

//    std::vector<std::byte> vec(reinterpret_cast<std::byte*>(&data[0]), reinterpret_cast<std::byte*>(&(data.end())[0]));
    std::vector<std::byte> key(16);
    std::fill(key.begin(), key.end(), (std::byte) 0x00);

    auto enc = crypton.encrypt(reinterpret_cast<std::byte *>(data.data()), data.length(), key.data(), key.size());

    auto dec = crypton.decrypt(reinterpret_cast<std::byte *>(enc.data()), enc.size(), key.data(), key.size());
    std::string recovered(reinterpret_cast<char *>(&dec[0]), reinterpret_cast<char *>(&dec.end()[0]));
    std::cout << "recovered " << recovered << std::endl;
}


//    fw::Firewall::instance().initQueue(1)
//            .addRawHandler([&subscriber, &sender](const uint8_t *data, uint32_t length) -> fw::Verdict {
//                zmq::message_t msg;
//                subscriber.recv(&msg);
//                std::cout << "<- " << msg.size() << std::endl;
//                Tins::IP packet(static_cast<uint8_t *>(msg.data()), msg.size());
//                Tins::IP *ip = packet.find_pdu<Tins::IP>();
//
//                if (ip != nullptr) {
//                    Tins::IP *p = packet.find_pdu<Tins::IP>();
//                    sender.send(packet);
//                } else {
//                    std::cout << "error" << std::endl;
//                }
//                return fw::Verdict::CONSUME;
//            }).spawnWorkers();

void tests() {
    auto src = Tins::IPv4Address("192.168.1.10");
    auto dst = Tins::IPv4Address("8.8.8.8");

    Tins::IP out(dst, src);
//    applyNAT(out);

    auto nat = Tins::IPv4Address("192.168.1.218");

    Tins::IP resp(nat, dst);
//    reverseNAT(resp);
    std::cout << resp.src_addr() << " -> " << resp.dst_addr() << std::endl;
}