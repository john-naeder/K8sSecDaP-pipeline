#pragma once
#include <cstdint>
#include <string>

namespace dsa {

// Shared event type between eBPF collector and DSA library.
// IP/port/pid/timestamp come straight from the kernel; the context strings are
// resolved in the collector's user space (offline /proc) and arrive via JSON.
struct NetworkEvent {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t dst_port = 0;
    uint32_t pid = 0;
    uint64_t timestamp_ns = 0;

    // Runtime / K8s context (optional — empty when unknown / non-K8s source).
    uint32_t    ppid = 0;
    uint32_t    uid = 0;
    std::string comm;          // process name, e.g. "nmap"
    std::string pod_name;      // source pod (best-effort)
    std::string namespace_;    // source pod namespace
    std::string container_id;  // source container id
};

// Helper: pack IPv4 from octets
inline uint32_t ip_from_octets(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8)  |
           static_cast<uint32_t>(d);
}

} // namespace dsa
