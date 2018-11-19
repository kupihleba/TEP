#include "Firewall.h"

int main() {

    // TODO: remove in production
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");

    fw::Firewall::instance().run();

    return 0;
}