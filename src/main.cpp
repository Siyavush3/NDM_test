#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <optional>
#include <memory>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <cstddef>

// RAII-обертка для сокета
class SocketGuard {
private:
    int fd_ = -1;

public:
    // Запрещаем копирование, чтобы избежать двойного закрытия
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    // Конструктор перемещения для передачи владения
    SocketGuard(SocketGuard&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            if (fd_ != -1) close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    explicit SocketGuard(int fd) : fd_(fd) {}

    ~SocketGuard() {
        if (fd_ != -1) {
            close(fd_);
        }
    }

    // Позволяет использовать объект как int в функциях вроде sendto/recv
    operator int() const {
        return fd_;
    }
};

// Функция для расчета контрольной суммы (стандартный алгоритм из RFC 1071)
unsigned short checksum(void *b, int len) {
    unsigned short *buf = reinterpret_cast<unsigned short*>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *reinterpret_cast<unsigned char*>(buf);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Кастомное исключение для сетевых ошибок
class NetworkError : public std::runtime_error {
public:
    NetworkError(const std::string& message)
        : std::runtime_error(message + ": " + std::strerror(errno)) {}
};

void send_ping(int sock, const struct sockaddr_in& dest_addr) {
    std::vector<std::byte> packet(sizeof(struct icmphdr));
    auto* icmp_hdr = reinterpret_cast<struct icmphdr*>(packet.data());

    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(getpid());
    icmp_hdr->un.echo.sequence = htons(1);
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum(packet.data(), packet.size());

    if (sendto(sock, packet.data(), packet.size(), 0,
               reinterpret_cast<const struct sockaddr*>(&dest_addr), sizeof(dest_addr)) < 0) {
        throw NetworkError("Ошибка отправки ICMP пакета");
    }
}

std::optional<std::string> receive_and_get_mac(int sock, const std::string& target_ip_str) {
    std::vector<std::byte> buffer(65536);
    struct in_addr target_ip;
    inet_aton(target_ip_str.c_str(), &target_ip);
    
    pid_t current_pid = getpid();

    while (true) {
        ssize_t bytes_received = recv(sock, buffer.data(), buffer.size(), 0);

        if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return std::nullopt; // Таймаут
            }
            throw NetworkError("Ошибка при получении пакета");
        }

        auto* eth_hdr = reinterpret_cast<struct ethhdr*>(buffer.data());
        auto* ip_hdr = reinterpret_cast<struct iphdr*>(buffer.data() + sizeof(struct ethhdr));

        if (ip_hdr->saddr == target_ip.s_addr && ip_hdr->protocol == IPPROTO_ICMP) {
            int ip_hdr_len = ip_hdr->ihl * 4;
            auto* rcv_icmp_hdr = reinterpret_cast<struct icmphdr*>(buffer.data() + sizeof(struct ethhdr) + ip_hdr_len);

            if (rcv_icmp_hdr->type == ICMP_ECHOREPLY && rcv_icmp_hdr->un.echo.id == htons(current_pid)) {
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                         eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
                         eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
                return std::string(mac_str);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <ipv4_address>" << std::endl;
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "Ошибка: для этой операции требуются права суперпользователя (root)." << std::endl;
        std::cerr << "Попробуйте: sudo " << argv[0] << " " << argv[1] << std::endl;
        return 1;
    }

    std::string target_ip_str = argv[1];

    try {
        // --- Подготовка сокетов и адреса ---
        struct sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = 0;
        if (inet_aton(target_ip_str.c_str(), &dest_addr.sin_addr) == 0) {
            std::cerr << "Ошибка: неверный IPv4 адрес '" << target_ip_str << "'" << std::endl;
            return 1;
        }

        SocketGuard sender_sock(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
        if (sender_sock < 0) throw NetworkError("Ошибка создания сокета для отправки");

        SocketGuard receiver_sock(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));
        if (receiver_sock < 0) throw NetworkError("Ошибка создания сокета для приема");
        
        // Установка таймаута на получение ответа
        using namespace std::chrono_literals;
        auto timeout = 3s;
        struct timeval tv;
        tv.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(timeout).count();
        tv.tv_usec = std::chrono::duration_cast<std::chrono::microseconds>(timeout % 1s).count();
        if (setsockopt(receiver_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            throw NetworkError("Ошибка установки таймаута для сокета");
        }

        // --- Отправка и прием ---
        send_ping(sender_sock, dest_addr);
        std::cout << "Отправлен ICMP запрос на " << target_ip_str << std::endl;

        if (auto mac_address = receive_and_get_mac(receiver_sock, target_ip_str); mac_address) {
            std::cout << "Ответ от " << target_ip_str << ". MAC адрес: " << *mac_address << std::endl;
        } else {
            std::cerr << "Таймаут: ответ не получен." << std::endl;
            return 1;
        }

    } catch (const NetworkError& e) {
        std::cerr << "Сетевая ошибка: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Произошла ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}