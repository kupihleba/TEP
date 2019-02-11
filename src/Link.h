#pragma once

#include <tins/tins.h>
#include <string>

class Link {
public:
    typedef Tins::IP::address_type address_t;

    Link(const address_t &src, const address_t &dest);

    Link(const address_t &src, int32_t src_port, const address_t &dest, int32_t dest_port);

    inline explicit Link(const Tins::IP &packet) : Link(packet.src_addr(), packet.dst_addr()) {}

    inline explicit Link(const Tins::TCP &packet) : src_port(packet.sport()), dst_port(packet.dport()) {
        net_layer = Layer::TRANSPORT_LAYER;
        source = packet.find_pdu<Tins::IP>()->src_addr();
        destination = packet.find_pdu<Tins::IP>()->dst_addr();
    }

    Link(const Link &link);

    friend bool operator==(const Link &linkA, const Link &linkB);

    friend bool operator!=(const Link &linkA, const Link &linkB);

    friend struct std::hash<Link>;

private:
    enum Layer {
        NETWORK_LAYER, TRANSPORT_LAYER
    };

    address_t source, destination;
    int32_t src_port, dst_port;
    Layer net_layer;

public:
    const address_t &getSource() const;

    const address_t &getDestination() const;

    int32_t getSrc_port() const;

    int32_t getDest_port() const;

    Layer getNet_layer() const;

    void setSource(const address_t &source);

    void setDestination(const address_t &destination);

    void setSrc_port(int32_t src_port);

    void setDest_port(int32_t dest_port);
};

namespace std {
    template<>
    struct hash<Link> {
        std::size_t operator()(const Link &link) const {
            using std::size_t, std::hash, std::string;
            std::hash<Link::address_t> hash_func;
            std::hash<int32_t> hash_func_int;
            size_t a = hash_func(link.source);
            size_t b = hash_func(link.destination);
            size_t c = hash_func_int(link.src_port);
            size_t d = hash_func_int(link.dst_port);
            return a ^ (b << 1);
        }
    };
}

