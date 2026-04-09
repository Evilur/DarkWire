#pragma once

#include "main.h"
#include "core/config.h"
#include "exception/tun_error.h"
#include "type/string.h"
#include "util/class.h"
#include "util/logger.h"
#include "util/system.h"

#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <ws2tcpip.h>
    extern "C" {
    #include <wintun.h>
    }
#else
    #include <fcntl.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <linux/ip.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
#endif

/**
 * Class for working with virtual network interface
 * @author Evilur <the.evilur@gmail.com>
 */
class TUN final {
public:
    PREVENT_COPY_AND_MOVE(TUN);

    explicit TUN(const char* name);

    ~TUN() noexcept;

    void Up() noexcept;

    [[nodiscard]] bool IsUp() const noexcept;

    int32_t Read(char* buffer, uint32_t mtu) const noexcept;

    void Write(const char* buffer, uint32_t buffer_size) noexcept;

private:
    const String _tun_name;

#ifdef _WIN32
    WINTUN_ADAPTER_HANDLE _adapter = nullptr;
    WINTUN_SESSION_HANDLE _session = nullptr;

    using PFN_WintunCreateAdapter =
        WINTUN_ADAPTER_HANDLE (WINAPI*)(
            LPCWSTR Name,
            LPCWSTR TunnelType,
            const GUID* RequestedGUID
        );

    using PFN_WintunOpenAdapter =
        WINTUN_ADAPTER_HANDLE (WINAPI*)(
            LPCWSTR Name
        );

    using PFN_WintunCloseAdapter =
        void (WINAPI*)(
            WINTUN_ADAPTER_HANDLE Adapter
        );

    using PFN_WintunStartSession =
        WINTUN_SESSION_HANDLE (WINAPI*)(
            WINTUN_ADAPTER_HANDLE Adapter,
            DWORD Capacity
        );

    using PFN_WintunEndSession =
        void (WINAPI*)(
            WINTUN_SESSION_HANDLE Session
        );

    using PFN_WintunGetReadWaitEvent =
        HANDLE (WINAPI*)(
            WINTUN_SESSION_HANDLE Session
        );

    using PFN_WintunReceivePacket =
        BYTE* (WINAPI*)(
            WINTUN_SESSION_HANDLE Session,
            DWORD* PacketSize
        );

    using PFN_WintunReleaseReceivePacket =
        void (WINAPI*)(
            WINTUN_SESSION_HANDLE Session,
            BYTE* Packet
        );

    using PFN_WintunAllocateSendPacket =
        BYTE* (WINAPI*)(
            WINTUN_SESSION_HANDLE Session,
            DWORD PacketSize
        );

    using PFN_WintunSendPacket =
        void (WINAPI*)(
            WINTUN_SESSION_HANDLE Session,
            BYTE* Packet
        );

    inline static HMODULE hWintun = LoadLibrary("wintun.dll");
    inline static PFN_WintunCreateAdapter WintunCreateAdapter =
        (PFN_WintunCreateAdapter)
            GetProcAddress(hWintun, "WintunCreateAdapter");
    inline static PFN_WintunOpenAdapter WintunOpenAdapter =
        (PFN_WintunOpenAdapter)
            GetProcAddress(hWintun, "WintunOpenAdapter");
    inline static PFN_WintunStartSession WintunStartSession =
        (PFN_WintunStartSession)
            GetProcAddress(hWintun, "WintunStartSession");
    inline static PFN_WintunEndSession WintunEndSession =
        (PFN_WintunEndSession)
            GetProcAddress(hWintun, "WintunEndSession");
    inline static PFN_WintunCloseAdapter WintunCloseAdapter =
        (PFN_WintunCloseAdapter)
            GetProcAddress(hWintun, "WintunCloseAdapter");
    inline static PFN_WintunSendPacket WintunSendPacket =
        (PFN_WintunSendPacket)
            GetProcAddress(hWintun, "WintunSendPacket");
    inline static PFN_WintunReceivePacket WintunReceivePacket =
        (PFN_WintunReceivePacket)
            GetProcAddress(hWintun, "WintunReceivePacket");
    inline static PFN_WintunAllocateSendPacket WintunAllocateSendPacket =
        (PFN_WintunAllocateSendPacket)
            GetProcAddress(hWintun, "WintunAllocateSendPacket");
    inline static PFN_WintunReleaseReceivePacket WintunReleaseReceivePacket =
        (PFN_WintunReleaseReceivePacket)
            GetProcAddress(hWintun, "WintunReleaseReceivePacket");
    inline static PFN_WintunGetReadWaitEvent WintunGetReadWaitEvent =
        (PFN_WintunGetReadWaitEvent)
            GetProcAddress(hWintun, "WintunGetReadWaitEvent");
#else
    const int32_t _tun_fd;
#endif

    bool _is_up = false;

#ifdef _WIN32
    static std::wstring Utf8ToWide(const char* str);
#endif
};

#ifdef _WIN32
FORCE_INLINE TUN::TUN(const char* const name) : _tun_name(name) {
    /* Check for .dll import */
    if (hWintun == nullptr) throw TunError("Failed to load wintun.dll");
    /* Try to create a fresh adapter. If it already exists, open it */
    const std::wstring wide_name = Utf8ToWide(name);
    _adapter = WintunCreateAdapter(L"Wintun", wide_name.c_str(), nullptr);
    if (_adapter == nullptr)
        _adapter = WintunOpenAdapter(wide_name.c_str());
    if (_adapter == nullptr)
        throw TunError("Failed to create/open the Wintun adapter");

    /* Create a session */
    _session = WintunStartSession(_adapter, 0x400000);
    if (_session == nullptr) {
        WintunCloseAdapter(_adapter);
        _adapter = nullptr;
        throw TunError("WintunStartSession failed");
    }
}

FORCE_INLINE TUN::~TUN() noexcept {
    if (_session != nullptr) {
        WintunEndSession(_session);
        _session = nullptr;
    }

    if (_adapter != nullptr) {
        WintunCloseAdapter(_adapter);
        _adapter = nullptr;
    }
}

FORCE_INLINE void TUN::Up() noexcept {
    /* Exec pre up commands */
    for (const String& command : Config::Interface::pre_up)
        System::Exec(command);

    /* Set up the interface */
    in_addr addr { .s_addr = local_ip.Netb() };
    System::Exec(
        String::Format(
            "netsh interface ipv4 set address name=\"%s\" "
            "source=static address=%s/%hhu gateway=none store=active",
            _tun_name.CStr(),
            inet_ntoa(addr),
            netmask
        )
    );

    /* Set the MTU */
    System::Exec(
        String::Format(
            "netsh interface ipv4 set subinterface \"%s\" mtu=%d store=active",
            _tun_name.CStr(),
            Config::Interface::mtu
        )
    );

    INFO_LOG("Interface [%s] is up", _tun_name.CStr());
    _is_up = true;

    /* Exec post up commands */
    for (const String& command : Config::Interface::post_up)
        System::Exec(command);
}

FORCE_INLINE int32_t TUN::Read(char* const buffer, const uint32_t buffer_size)
const noexcept {
    HANDLE h_event = WintunGetReadWaitEvent(_session);
    WaitForSingleObject(h_event, INFINITE);

    DWORD packet_size = 0;
    BYTE* packet = WintunReceivePacket(_session, &packet_size);

#if LOG_LEVEL == 0
    if (packet != nullptr)
        TRACE_LOG("Read %llu bytes from the TUN", (uint64_t)packet_size);
    else
        WARN_LOG("Failed to read the data from the TUN");
#endif

    if (packet == nullptr) return -1;

    memcpy(buffer, packet, packet_size);
    WintunReleaseReceivePacket(_session, packet);
    return (int32_t)packet_size;
}

FORCE_INLINE void TUN::Write(const char* const buffer,
                             const uint32_t buffer_size) noexcept {
    TRACE_LOG("Writing %u bytes to the TUN", buffer_size);

    BYTE* packet = WintunAllocateSendPacket(_session, buffer_size);
    if (packet == nullptr) {
        WARN_LOG("Failed to allocate a Wintun send packet");
        return;
    }

    memcpy(packet, buffer, buffer_size);
    WintunSendPacket(_session, packet);
}

FORCE_INLINE std::wstring TUN::Utf8ToWide(const char* const str) {
    const int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (len <= 0)
        throw TunError("Failed to convert tunnel name to UTF-16");

    std::wstring out(static_cast<size_t>(len - 1), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, str, -1, out.data(), len) <= 0)
        throw TunError("Failed to convert tunnel name to UTF-16");

    return out;
}
#else
FORCE_INLINE TUN::TUN(const char* const name) : _tun_name(name),
    /* Open the TUN device */
    _tun_fd(open("/dev/net/tun", O_RDWR | O_CLOEXEC)) {
    if (_tun_fd == -1) throw TunError("Failed to open the TUN device");

    /* Set flags */
    ifreq ifr { };
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    /* Set the name of the new network interface */
    if (name == nullptr)
        throw TunError("Name of the tunnel cannot be nullptr");
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    /* Create a new network interface */
    if (ioctl(_tun_fd, TUNSETIFF, &ifr) == -1) {
        FATAL_LOG("Failed to create the virtual interface\n"
                  "Do you have enough permissions?");
        throw TunError("Ioctl TUNSETIFF failed");
    }

    /* IF all is OK */
    System::Exec(String::Format("sysctl -w net.ipv6.conf.%s.disable_ipv6=1",
                                name));
}

FORCE_INLINE TUN::~TUN() noexcept { close(_tun_fd); }

FORCE_INLINE void TUN::Up() noexcept {
    /* Exec pre up commands */
    for (const String& command : Config::Interface::pre_up)
        System::Exec(command);

    /* Up the interface */
    in_addr addr { .s_addr = local_ip.Netb() };
    System::Exec(String::Format("ip addr add %s/%hhu dev %s",
                                inet_ntoa(addr),
                                netmask,
                                _tun_name.CStr()));
    System::Exec(String::Format("ip link set %s mtu %d",
                                _tun_name.CStr(),
                                Config::Interface::mtu));
    System::Exec(String::Format("ip link set %s up", _tun_name.CStr()));
    INFO_LOG("Interface [%s] is up", _tun_name.CStr());
    _is_up = true;

    /* Exec post up commands */
    for (const String& command : Config::Interface::post_up)
        System::Exec(command);
}

FORCE_INLINE int32_t TUN::Read(char* const buffer, const uint32_t buffer_size)
const noexcept {
#if LOG_LEVEL == 0
    const int32_t result = (int32_t)read(_tun_fd, buffer, buffer_size);
    if (result != -1)
        TRACE_LOG("Read %d bytes from the TUN", result);
    else
        WARN_LOG("Failed to read the data from the TUN");
    return result;
#else
    return (int32_t)read(_tun_fd, buffer, buffer_size);
#endif
}

FORCE_INLINE void TUN::Write(const char* const buffer,
                             const uint32_t buffer_size) noexcept {
    TRACE_LOG("Writing %u bytes to the TUN", buffer_size);
    write(_tun_fd, buffer, buffer_size);
}
#endif

FORCE_INLINE bool TUN::IsUp() const noexcept { return _is_up; }
