#ifndef PPPOE_MODULE_H
#define PPPOE_MODULE_H

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <mysql/mysql.h>

#include "rohc_wrapper.h"

// ==================== Constants ====================

constexpr uint16_t MAC_LEN = 6;
constexpr uint16_t MTU = 1500;
constexpr uint16_t MAX_ETH_PACKET_LEN = 1514;
constexpr uint16_t ETH_HEADER_LEN_WITHOUT_CRC = 14;
constexpr uint16_t PPPOE_HEADER_LEN = 6;
constexpr uint16_t PPP_PROTOCOL_LEN = 2;
constexpr uint16_t PPPOE_COUNT = 2;
constexpr uint16_t GB_LIMIT = (1024 * 1024 * 1024);
constexpr uint16_t SEND_MAX_TIME = 10;

// Ethernet type constants
constexpr uint16_t ETHER_TYPE_DISCOVERY = 0x8863;
constexpr uint16_t ETHER_TYPE_PPP_SESSION = 0x8864;
constexpr uint16_t ETH_P_ALL = 3;

// PPPoE code constants
constexpr uint8_t CODE_OF_PADI = 0x09;
constexpr uint8_t CODE_OF_PADO = 0x07;
constexpr uint8_t CODE_OF_PADR = 0x19;
constexpr uint8_t CODE_OF_PADS = 0x65;
constexpr uint8_t CODE_OF_PADT = 0xa7;
constexpr uint8_t CODE_OF_PPP_SESSION = 0x00;

// Service Tag constants
constexpr uint16_t Service_Name = 0x0101;
constexpr uint16_t Host_Uniq = 0x0103;
constexpr uint16_t AC_Name = 0x0102;
constexpr uint16_t AC_Cookie = 0x0104;

// LCP/Protocol constants
constexpr uint8_t LCP_CONFIG_REQUEST = 0x01;
constexpr uint8_t LCP_CONFIG_ACK = 0x02;
constexpr uint8_t LCP_CONFIG_NAK = 0x03;
constexpr uint8_t LCP_CONFIG_REJECT = 0x04;
constexpr uint8_t LCP_TERMINATION_REQUEST = 0x05;
constexpr uint8_t LCP_TERMINATION_ACK = 0x06;
constexpr uint8_t LCP_PROTOCOL_REJECT = 0x08;
constexpr uint8_t LCP_ECHO_REQUEST = 0x09;
constexpr uint8_t LCP_ECHO_REPLY = 0x0a;

// Protocol identifiers
constexpr uint16_t LCP = 0xc021;
constexpr uint16_t CHAP = 0xc223;
constexpr uint16_t PAP = 0xc023;
constexpr uint16_t IPCP = 0x8021;
constexpr uint16_t IPv4 = 0x0021;   // PPP protocol field for IP (修正: 原值为0x0800是Ethertype)
constexpr uint16_t IPv4_ETH = 0x0800; // 以太网类型中的IPv4

// ==================== ROHC 集成常量 ====================

/// PPPoE帧中IP包的偏移量(以太网头14 + PPPoE头6 + PPP协议字段2 = 22)
constexpr uint16_t PPPOE_IP_PAYLOAD_OFFSET = 22;

/// ROHC工作缓冲区大小
constexpr uint16_t ROHC_GATEWAY_WORK_BUF_SIZE = 2048;

/// ROHC调试打印开关(1=开启, 0=关闭)
constexpr uint8_t ROHC_DEBUG_PRINT = 1;

// Database Configuration
constexpr const char* DB_HOST = "localhost";
constexpr const char* DB_USER = "root";
constexpr const char* DB_PASS = "pml123456";
constexpr const char* DB_NAME = "radius";
constexpr const char* TABLE_NAME = "radacct";
constexpr const char* COL_INPUT = "acctinputoctets";
constexpr const char* COL_OUTPUT = "acctoutputoctets";
constexpr const char* COL_MAC = "callingstationid";

// Session state enum
enum class SessionState : uint8_t {
    IDLE = 0,                      // 0
    PADI_SENT = 1,                 // 1
    PADO_RECEIVED = 2,             // 2
    PADS_RECEIVED = 3,             // 3
    AUTH_IN_PROGRESS = 4,          // 4
    ESTABLISHED = 5,               // 5
    ABNORMAL_TERMINATED = 6        // 6
};

// MAC address type
using MacAddress = std::array<uint8_t, MAC_LEN>;

// ==================== Data Structures ====================

struct ConnectionInfo {
    MacAddress my_mac{};
    MacAddress peer_mac{};
    int session_socket{-1};
    int ifindex{-1};
};

struct SessionData {
    uint64_t rcst_hid{0};
    MacAddress ppp_mac{};
    uint16_t host_uniq{0};
    uint16_t pppoe_session_id{0};
    SessionState ppp_state{SessionState::IDLE};

    // [ROHC集成] 每个会话的ROHC通道启用状态
    bool rohc_enabled{false};

    // [bug-fix] 状态机完备性审查 - 缓存字段 begin
    // PADO缓存: PADO丢包后终端重发PADI时重传, 生命周期: 收到PADO→进入PADS_RECEIVED
    uint8_t cached_pado[MAX_ETH_PACKET_LEN]{};
    uint16_t cached_pado_len{0};
    bool has_cached_pado{false};

    // PADS缓存: PADS丢包后终端重发PADR时重传, 生命周期: 收到PADS→进入ESTABLISHED
    uint8_t cached_pads[MAX_ETH_PACKET_LEN]{};
    uint16_t cached_pads_len{0};
    bool has_cached_pads{false};

    // 认证响应缓存: CHAP Success/PAP Ack丢包后终端重发认证时重传
    // 生命周期: 收到CHAP Success/PAP Ack→进入ESTABLISHED
    uint8_t cached_auth_response[MAX_ETH_PACKET_LEN]{};
    uint16_t cached_auth_response_len{0};
    bool has_cached_auth_response{false};

    // 终止信令缓存: 服务器PADT丢包后终端继续发数据时重传
    // 生命周期: 收到服务器PADT→终端成功重启新PADI时清除
    // 注意: 此缓存不在reset_session中清除, 需跨IDLE状态持续有效
    uint8_t cached_terminate[MAX_ETH_PACKET_LEN]{};
    uint16_t cached_terminate_len{0};
    bool has_cached_terminate{false};
    // [bug-fix] 状态机完备性审查 - 缓存字段 end
};

struct PPPoEFrame {
    MacAddress destination_addr{};
    MacAddress source_addr{};
    uint16_t ether_type{0};
    uint8_t ppoe_type : 4;
    uint8_t ppoe_version : 4;
    uint8_t ppoe_code{0};
    uint16_t pppoe_session_id{0};
    uint16_t pppoe_length{0};
    uint16_t protocol_field{0};
    uint8_t ppp_payload[MTU - 2]{};

    PPPoEFrame() = default;
};

struct LCPPacket {
    uint8_t code{0};
    uint8_t identifier{0};
    uint16_t length{0};
    uint8_t data[MTU - 10]{};

    LCPPacket() = default;
};

struct PADTFrame {
    MacAddress eth_dst_mac{};
    MacAddress eth_src_mac{};
    uint16_t ether_type{0};
    uint16_t protocol{0};
    uint8_t information[MAX_ETH_PACKET_LEN - 14 - 6 - 2]{};

    PADTFrame() = default;
};

// ==================== Session Manager Class ====================

class PPPoESessionManager {
public:
    static constexpr uint16_t MAX_SESSIONS = PPPOE_COUNT;

    PPPoESessionManager();
    ~PPPoESessionManager() = default;

    PPPoESessionManager(const PPPoESessionManager&) = delete;
    PPPoESessionManager& operator=(const PPPoESessionManager&) = delete;

    // Session lookup
    bool find_by_hid(uint64_t hid, uint16_t& out_id) const;
    bool find_by_mac(const MacAddress& mac, uint16_t& out_id) const;
    bool find_by_session_id(uint16_t sid, uint16_t& out_id) const;
    bool find_idle_or_first_idle(uint16_t& out_id) const;

    // Session access
    SessionData* get_session(uint16_t id);
    const SessionData* get_session(uint16_t id) const;

    // Session operations
    bool allocate_or_update(uint16_t id, uint64_t hid, const MacAddress& mac);
    bool set_state(uint16_t id, SessionState state);
    bool update_session_id(uint16_t id, uint16_t session_id);
    SessionState get_state(uint16_t id) const;
    bool reset_session(uint16_t id);
    uint16_t get_online_count() const;

private:
    struct InternalSession {
        SessionData data;
        mutable std::mutex lock;
    };

    std::array<InternalSession, MAX_SESSIONS> sessions_;
    mutable std::mutex manager_lock_;

    bool is_valid_id(uint16_t id) const { return id < MAX_SESSIONS; }
};

// ==================== Utility Functions Class ====================

class PPPoEUtil {
public:
    // MAC/HEX conversions
    static std::optional<MacAddress> hex_string_to_mac(const std::string& hex_str);
    static std::string mac_to_hex_string(const MacAddress& mac);
    static std::string clean_hex_string(const std::string& src);
    static int hex_char_to_value(char c);

    // Memory operations
    static void byte_swap_copy(void* dest, const void* src, uint16_t length);

    // File I/O for configuration
    static std::optional<std::string> read_nic_config(const std::string& path);
    static std::optional<uint32_t> read_timeout_config(const std::string& path);
    static std::optional<std::string> read_bpf_config(const std::string& path);

private:
    PPPoEUtil() = delete;
};

// ==================== Socket Manager Class ====================
class PPPoESocketManager {
public:
    PPPoESocketManager();
    ~PPPoESocketManager();

    PPPoESocketManager(const PPPoESocketManager&) = delete;
    PPPoESocketManager& operator=(const PPPoESocketManager&) = delete;

    // 对应原 init_socket() - 只暴露这一个初始化接口，返回bool判断是否成功
    bool initialize();

    // Accessors
    int get_socket() const { return session_socket_; }
    int get_ifindex() const { return ifindex_; }
    const std::string& get_nic_name() const { return nic_name_; }
    ConnectionInfo& get_connection_info() { return connection_info_; }
    const ConnectionInfo& get_connection_info() const { return connection_info_; }

private:
    int session_socket_{-1};
    int ifindex_{-1};
    std::string nic_name_;
    ConnectionInfo connection_info_;

    // ===== 内部私有函数 - 只在类内部使用 =====
    
    // 读取网卡配置文件 - 对应原 read_netnic_txt()
    bool read_nic_config();

    // 创建socket - 对应原 init_socket() 中的 socket() 调用
    bool create_socket();

    // 配置socket缓冲区 - 对应原 init_socket() 中的缓冲区设置
    bool configure_socket_buffer();

    // 获取网卡index - 对应原 get_ifindex()
    bool get_interface_index();

    // 获取网卡MAC地址 - 对应原 get_macaddr()
    bool get_mac_address();

    // 设置混杂模式 - 对应原 set_promisc()
    bool set_promiscuous_mode();

    // 绑定socket - 对应原 init_socket() 中的 bind() 调用
    bool bind_socket();

    // 关闭socket
    void close_socket();
};

// ==================== Packet Handler Class ====================

class PPPoEPacketHandler {
public:
    PPPoEPacketHandler(PPPoESocketManager& socket_mgr, PPPoESessionManager& session_mgr);
    ~PPPoEPacketHandler() = default;

    PPPoEPacketHandler(const PPPoEPacketHandler&) = delete;
    PPPoEPacketHandler& operator=(const PPPoEPacketHandler&) = delete;

    // Main interface - corresponds to send_message_from_ppp() and server_session()
    int send_message_from_ppp(uint64_t rcst_hid, const uint8_t* content, uint16_t length);
    void server_session_loop();  // Thread function for continuous receiving

    // State accessor
    uint16_t get_online_count() const { return session_mgr_.get_online_count(); }
    SessionState get_session_state(uint16_t id) const { return session_mgr_.get_state(id); }

private:
    PPPoESocketManager& socket_mgr_;
    PPPoESessionManager& session_mgr_;
    uint8_t recv_buffer_[4096];

    // [ROHC集成] 网关侧ROHC工作缓冲区
    uint8_t rohc_work_buf_[ROHC_GATEWAY_WORK_BUF_SIZE];

    // ===== Send Functions - corresponds to send_PPPoE(), send_other(), send_PPPoE_to_PPP(), send_PADT_to_PPP() =====
    int send_pppoe_to_server(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int send_pppoe_to_ppp(const uint8_t* buffer, uint16_t session_id, uint16_t length);
    int send_padt_to_ppp(const PADTFrame* frame, uint16_t session_id, uint16_t length);
    int send_other_to_server(const PADTFrame* frame, uint16_t session_id, uint16_t length);
    int send_raw_packet(const void* buffer, uint16_t length, const MacAddress& dest_mac);

    // ===== PPP to Server: Discovery Phase =====
    int handle_discovery_from_ppp(const PPPoEFrame* frame, uint64_t rcst_hid, uint16_t length);
    int handle_padi_from_ppp(const PPPoEFrame* frame, uint64_t rcst_hid, uint16_t length);

    // ===== PPP to Server: Session Phase =====
    int handle_session_from_ppp(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int handle_lcp_from_ppp(const PPPoEFrame* frame, uint16_t session_id, 
                            const LCPPacket* lcp, uint16_t length);
    int handle_chap_from_ppp(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int handle_pap_from_ppp(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int handle_ipcp_from_ppp(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int handle_ip_from_ppp(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);

    // ===== Server to PPP: Discovery Phase =====
    int handle_pado_from_server(const PPPoEFrame* frame, uint16_t length);
    int handle_pads_from_server(const PPPoEFrame* frame, uint16_t length);
    int handle_padt_from_server(const PPPoEFrame* frame, uint16_t length);

    // ===== Server to PPP: Session Phase =====
    int handle_lcp_from_server(const PPPoEFrame* frame, uint16_t session_id, 
                               const LCPPacket* lcp, uint16_t length);
    int handle_chap_from_server(const PPPoEFrame* frame, uint16_t session_id, 
                                const LCPPacket* chap, uint16_t length);
    int handle_pap_from_server(const PPPoEFrame* frame, uint16_t session_id, 
                               const LCPPacket* pap, uint16_t length);
    int handle_ipcp_from_server(const PPPoEFrame* frame, uint16_t session_id, 
                                const LCPPacket* ipcp, uint16_t length);
    int handle_ip_from_server(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);

    // ===== Virtual Response Functions - corresponds to virtual_send_lcp_ack_to_server() and virtual_send_ipcp_ack_to_server() =====
    int send_virtual_lcp_ack(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);
    int send_virtual_ipcp_ack(const PPPoEFrame* frame, uint16_t session_id, uint16_t length);

    // Utility
    void swap_mac_addresses(PPPoEFrame* frame);
    int notify_pppoe_error(uint64_t rcst_hid, uint8_t reason);

    // ==================== ROHC 内部辅助方法 ====================

    /**
     * @brief 为指定会话创建ROHC通道
     * @param session_id PPPoE会话ID
     * @return 0成功, -1失败
     */
    int rohc_init_channel(uint16_t session_id);

    /**
     * @brief 销毁指定会话的ROHC通道
     * @param session_id PPPoE会话ID
     */
    void rohc_destroy_channel(uint16_t session_id);

    /**
     * @brief 对PPPoE帧中的IP包执行ROHC解压(终端→服务器方向)
     * 终端发送的IP包经过卫星链路时被压缩,网关侧需解压后转发给服务器
     *
     * @param frame_data PPPoE帧数据(可修改)
     * @param frame_len 原始帧长度
     * @param session_id 会话ID
     * @return 新的帧长度(解压后), 或原始长度(非IP/失败)
     */
    uint16_t rohc_decompress_frame(uint8_t *frame_data, uint16_t frame_len, uint16_t session_id);

    /**
     * @brief 对PPPoE帧中的IP包执行ROHC压缩(服务器→终端方向)
     * 服务器发来的IP包在网关侧压缩后经卫星链路发送给终端
     *
     * @param frame_data PPPoE帧数据(可修改)
     * @param frame_len 原始帧长度
     * @param max_frame_len 缓冲区最大容量
     * @param session_id 会话ID
     * @return 新的帧长度(压缩后), 或原始长度(非IP/失败)
     */
    uint16_t rohc_compress_frame(uint8_t *frame_data, uint16_t frame_len,
                                  uint16_t max_frame_len, uint16_t session_id);

    /**
     * @brief 判断PPPoE帧是否为IP数据包
     */
    bool is_ip_frame(const uint8_t *frame_data, uint16_t frame_len) const;

    // ==================== ROHC 调试打印方法 ====================

    /**
     * @brief 打印ROHC流程步骤(带时间戳)
     */
    void rohc_print_flow(const char *step) const;

    /**
     * @brief 打印IP包头详细信息
     */
    void rohc_print_ip_header(const uint8_t *ip_data, size_t ip_len, const char *direction) const;

    /**
     * @brief 打印压缩过程详细信息
     */
    void rohc_print_compress_detail(size_t orig_len, size_t comp_len, uint16_t session_id) const;

    /**
     * @brief 打印解压过程详细信息
     */
    void rohc_print_decompress_detail(size_t comp_len, size_t decomp_len, uint16_t session_id) const;

    /**
     * @brief 十六进制转储数据包
     */
    void rohc_dump_packet(const uint8_t *data, size_t len, const char *prefix, size_t max_bytes = 64) const;

    /**
     * @brief 打印指定会话的ROHC统计信息
     */
    void rohc_print_stats(uint16_t session_id) const;

    /**
     * @brief 打印所有会话的ROHC统计信息
     */
    void rohc_print_all_stats() const;

    // Public interface for traffic manager
public:
    int send_other_to_server_public(const PADTFrame* frame, uint16_t session_id, uint16_t length) {
        return send_other_to_server(frame, session_id, length);
    }
};

// ==================== Traffic Manager Class ====================

class PPPoETrafficManager {
public:
    PPPoETrafficManager(PPPoESessionManager& session_mgr, class PPPoEPacketHandler& handler);
    ~PPPoETrafficManager();

    PPPoETrafficManager(const PPPoETrafficManager&) = delete;
    PPPoETrafficManager& operator=(const PPPoETrafficManager&) = delete;

    // Corresponds to check_ppp_traffic_limit thread function
    bool start_traffic_check_thread();
    void stop_traffic_check_thread();

private:
    PPPoESessionManager& session_mgr_;
    PPPoEPacketHandler& handler_;
    std::unique_ptr<std::thread> traffic_thread_;
    bool thread_running_{false};

    // Traffic check logic
    void traffic_check_loop();
    bool connect_database(MYSQL*& conn);
    void disconnect_database(MYSQL*& conn);
    bool query_online_users(MYSQL* conn);
    int notify_traffic_exceeded(uint16_t session_id, uint64_t total_traffic);
};

#endif // PPPOE_MODULE_H
