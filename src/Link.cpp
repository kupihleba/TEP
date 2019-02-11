#include "Link.h"
#include "Exception.h"

Link::Link(const Link::address_t &src, const Link::address_t &dest)
        : source(src), destination(dest),
          net_layer(Layer::NETWORK_LAYER) {

}

Link::Link(const Link::address_t &src, int32_t src_port, const Link::address_t &dest, int32_t dest_port)
        : source(src), destination(dest),
          src_port(src_port), dst_port(dest_port),
          net_layer(Layer::TRANSPORT_LAYER) {

}

Link::Link(const Link &link) {
    this->source = link.source;
    this->destination = link.destination;
    this->net_layer = link.net_layer;
    if (net_layer == Link::TRANSPORT_LAYER) {
        this->src_port = link.src_port;
        this->dst_port = link.dst_port;
    }
}


const Link::address_t &Link::getSource() const {
    return source;
}

const Link::address_t &Link::getDestination() const {
    return destination;
}

int32_t Link::getSrc_port() const {
    if (net_layer == Layer::NETWORK_LAYER) {
        throw Exception("Trying to get port from network layer packet!");
    }
    return src_port;
}

int32_t Link::getDest_port() const {
    if (net_layer == Layer::NETWORK_LAYER) {
        throw Exception("Trying to get port from network layer packet!");
    }
    return dst_port;
}

Link::Layer Link::getNet_layer() const {
    return net_layer;
}


void Link::setSource(const Link::address_t &source) {
    Link::source = source;
}

void Link::setDestination(const Link::address_t &destination) {
    Link::destination = destination;
}

void Link::setSrc_port(int32_t src_port) {
    Link::src_port = src_port;
}

void Link::setDest_port(int32_t dest_port) {
    Link::dst_port = dest_port;
}

bool operator==(const Link &linkA, const Link &linkB) {
    if (linkA.net_layer != linkB.net_layer) {
        return false;
    }

    return linkA.source == linkB.source &&
           linkA.destination == linkB.destination &&
           (linkA.net_layer == Link::Layer::TRANSPORT_LAYER ?
            linkA.src_port == linkB.src_port &&
            linkA.dst_port == linkB.dst_port
                                                            : true);
}

bool operator!=(const Link &linkA, const Link &linkB) {
    return !(linkA == linkB);
}


