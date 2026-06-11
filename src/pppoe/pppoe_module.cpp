#include "pppoe_module.h"
#include "../satellite-log.h"
#include "../satellite-ncc-l2-l1-comm.h"
#include "../satellite-observer-mgr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cctype>
#include <ctime>

// ==================== PPPoESessionManager Implementation ====================

PPPoESessionManager::PPPoESessionManager() : sessions_{} {}

bool PPPoESessionManager::find_by_hid(uint64_t hid, uint16_t& out_id) const {
    std::lock_guard<std::mutex> lock(manager_lock_);
    for (uint16_t i = 0; i < MAX_SESSIONS; ++i) {
        if (sessions_[i].data.rcst_hid == hid) {
            out_id = i;
            return true;
        }
    }
    return false;
}

bool PPPoESessionManager::find_by_mac(const MacAddress& mac, uint16_t& out_id) const {
    std::lock_guard<std::mutex> lock(manager_lock_);
    for (uint16_t i = 0; i < MAX_SESSIONS; ++i) {
        if (sessions_[i].data.ppp_mac == mac) {
            out_id = i;
            return true;
        }
    }
    return false;
}

bool PPPoESessionManager::find_by_session_id(uint16_t sid, uint16_t& out_id) const {
    std::lock_guard<std::mutex> lock(manager_lock_);
    for (uint16_t i = 0; i < MAX_SESSIONS; ++i) {
        if (sessions_[i].data.pppoe_session_id == sid) {
            out_id = i;
            return true;
        }
    }
    return false;
}

bool PPPoESessionManager::find_idle_or_first_idle(uint16_t& out_id) const {
    std::lock_guard<std::mutex> lock(manager_lock_);
    for (uint16_t i = 0; i < MAX_SESSIONS; ++i) {
        if (sessions_[i].data.ppp_state == SessionState::IDLE) {
            out_id = i;
            return true;
        }
    }
    return false;
}

SessionData* PPPoESessionManager::get_session(uint16_t id) {
    if (!is_valid_id(id)) {
        return nullptr;
    }
    return &sessions_[id].data;
}

const SessionData* PPPoESessionManager::get_session(uint16_t id) const {
    if (!is_valid_id(id)) {
        return nullptr;
    }
    return &sessions_[id].data;
}

bool PPPoESessionManager::allocate_or_update(uint16_t id, uint64_t hid,
                                             const MacAddress& mac) {
    if (!is_valid_id(id)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(sessions_[id].lock);
    sessions_[id].data.rcst_hid = hid;
    sessions_[id].data.ppp_mac = mac;
    sessions_[id].data.ppp_state = SessionState::PADI_SENT;
    return true;
}

bool PPPoESessionManager::set_state(uint16_t id, SessionState state) {
    if (!is_valid_id(id)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(sessions_[id].lock);
    sessions_[id].data.ppp_state = state;
    return true;
}

bool PPPoESessionManager::update_session_id(uint16_t id, uint16_t session_id) {
    if (!is_valid_id(id)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(sessions_[id].lock);
    sessions_[id].data.pppoe_session_id = session_id;
    return true;
}

SessionState PPPoESessionManager::get_state(uint16_t id) const {
    if (!is_valid_id(id)) {
        return SessionState::IDLE;
    }

    std::lock_guard<std::mutex> lock(sessions_[id].lock);
    return sessions_[id].data.ppp_state;
}

bool PPPoESessionManager::reset_session(uint16_t id) {
    if (!is_valid_id(id)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(sessions_[id].lock);
    // [bug-fix] bug#5: reset_session时保留terminate缓存,清除其他缓存 begin
    // terminate缓存需要跨IDLE状态持续有效,不能在reset时清除
    uint8_t saved_terminate[MAX_ETH_PACKET_LEN];
    uint16_t saved_terminate_len = sessions_[id].data.cached_terminate_len;
    bool saved_has_terminate = sessions_[id].data.has_cached_terminate;
    if (saved_has_terminate) {
        std::memcpy(saved_terminate, sessions_[id].data.cached_terminate, saved_terminate_len);
    }

    sessions_[id].data = SessionData{};

    // 恢复terminate缓存
    if (saved_has_terminate) {
        std::memcpy(sessions_[id].data.cached_terminate, saved_terminate, saved_terminate_len);
        sessions_[id].data.cached_terminate_len = saved_terminate_len;
        sessions_[id].data.has_cached_terminate = true;
    }

    // [ROHC集成] reset_session时重置rohc_enabled标志
    // 注意: 这里不销毁ROHC通道,因为session对象正在被重置,调用rohc_destroy_channel
    // 会在外部终止流程中处理(LCP Terminate/PADT等处会先销毁通道再reset)
    sessions_[id].data.rohc_enabled = false;

    // [bug-fix] bug#5: reset_session时保留terminate缓存,清除其他缓存 end
    return true;
}

uint16_t PPPoESessionManager::get_online_count() const {
    std::lock_guard<std::mutex> lock(manager_lock_);
    uint16_t count = 0;
    for (const auto& session : sessions_) {
        if (session.data.ppp_state != SessionState::IDLE) {
            ++count;
        }
    }
    return count;
}

// ==================== PPPoEUtil Implementation ====================

// hex_char_to_value() - 对应原 hex_char_to_val()
int PPPoEUtil::hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

// clean_hex_string() - 对应原 clean_hex_string()
std::string PPPoEUtil::clean_hex_string(const std::string& src) {
    std::string dest;
    for (char c : src) {
        if (c != '-' && c != ':' && c != ' ') {
            dest += c;
        }
    }
    return dest;
}

// hex_string_to_mac() - 对应原 hex_to_mac()
std::optional<MacAddress> PPPoEUtil::hex_string_to_mac(const std::string& hex_str) {
    std::string cleaned = clean_hex_string(hex_str);
    if (cleaned.length() != 12) {
        return std::nullopt;
    }

    MacAddress mac{};
    for (size_t i = 0; i < 6; ++i) {
        int high = hex_char_to_value(cleaned[2 * i]);
        int low = hex_char_to_value(cleaned[2 * i + 1]);

        if (high == -1 || low == -1) {
            return std::nullopt;
        }

        mac[i] = static_cast<uint8_t>((high << 4) | low);
    }

    return mac;
}

// mac_to_hex_string() - 辅助函数
std::string PPPoEUtil::mac_to_hex_string(const MacAddress& mac) {
    std::ostringstream oss;
    for (size_t i = 0; i < MAC_LEN; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", mac[i]);
        oss << buf;
        if (i < MAC_LEN - 1) oss << ":";
    }
    return oss.str();
}

// byte_swap_copy() - 对应原 memory_copy2()
void PPPoEUtil::byte_swap_copy(void* dest, const void* src, uint16_t length) {
    auto* d = static_cast<uint8_t*>(dest);
    const auto* s = static_cast<const uint8_t*>(src);

    for (uint16_t i = 0; i < length; ++i) {
        d[length - 1 - i] = s[i];
    }
}

// read_nic_config() - 对应原 read_netnic_txt()
std::optional<std::string> PPPoEUtil::read_nic_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::string nic_name;
    if (std::getline(file, nic_name)) {
        size_t start = nic_name.find_first_not_of(" \t\r\n");
        size_t end = nic_name.find_last_not_of(" \t\r\n");
        if (start != std::string::npos) {
            return nic_name.substr(start, end - start + 1);
        }
    }

    return std::nullopt;
}

// read_timeout_config() - 对应原 read_timeout_txt()
std::optional<uint32_t> PPPoEUtil::read_timeout_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    uint32_t timeout;
    if (file >> timeout) {
        return timeout;
    }

    return std::nullopt;
}

// read_bpf_config() - 对应原 read_bpf_txt()
std::optional<std::string> PPPoEUtil::read_bpf_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        content += line + "\n";
    }

    if (!content.empty()) {
        return content;
    }

    return std::nullopt;
}

// ==================== PPPoESocketManager Implementation ====================

PPPoESocketManager::PPPoESocketManager()
    : session_socket_(-1), ifindex_(-1), nic_name_("") {}

PPPoESocketManager::~PPPoESocketManager() {
    close_socket();
}

// 对应原 init_socket() - 统一的初始化入口
bool PPPoESocketManager::initialize() {
    // 1. 读取网卡配置文件
    if (!read_nic_config()) {
        PML_log(PMLLOG_ERROR, "Failed to read NIC config");
        return false;
    }

    // 2. 创建socket
    if (!create_socket()) {
        return false;
    }

    // 3. 配置socket缓冲区
    if (!configure_socket_buffer()) {
        close_socket();
        return false;
    }

    // 4. 获取网卡index
    if (!get_interface_index()) {
        close_socket();
        return false;
    }
    printf("read get_ifindex=%d\n", ifindex_);

    // 5. 获取网卡MAC地址
    if (!get_mac_address()) {
        close_socket();
        return false;
    }

    // 6. 设置混杂模式
    if (!set_promiscuous_mode()) {
        close_socket();
        return false;
    }

    // 7. 绑定socket
    if (!bind_socket()) {
        close_socket();
        return false;
    }

    connection_info_.session_socket = session_socket_;
    connection_info_.ifindex = ifindex_;

    PML_log(PMLLOG_INFO, "Socket initialized successfully on %s (ifindex=%d)",
           nic_name_.c_str(), ifindex_);
    return true;
}

// 读取网卡配置文件 - 对应原 read_netnic_txt()
bool PPPoESocketManager::read_nic_config() {
    auto nic_name_opt = PPPoEUtil::read_nic_config("../data/PPPoE/netnic.txt");
    if (nic_name_opt.has_value()) {
        nic_name_ = nic_name_opt.value();
        PML_log(PMLLOG_INFO, "sz_NIC_name=%s", nic_name_.c_str());
        return true;
    }

    PML_log(PMLLOG_ERROR, "Failed to read netnic.txt, using default eth0");
    nic_name_ = "eth0";
    return true;  // 使用默认值，不算失败
}

// 创建socket - 对应原 init_socket() 中的 socket() 调用
bool PPPoESocketManager::create_socket() {
    session_socket_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (session_socket_ < 0) {
        PML_log(PMLLOG_ERROR, "send_message_from_ppp to server session_sock error");
        return false;
    }

    PML_log(PMLLOG_INFO, "send from ppp to server session sock ok!");
    return true;
}

// 配置socket缓冲区 - 对应原 init_socket() 中的缓冲区设置
bool PPPoESocketManager::configure_socket_buffer() {
    if (session_socket_ < 0) {
        return false;
    }

    int32_t i_socket_read_buffer_size = 0;
    socklen_t i_sock_option_length = sizeof(i_socket_read_buffer_size);

    getsockopt(session_socket_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<char*>(&i_socket_read_buffer_size), &i_sock_option_length);

    int32_t i_rcvbuf_size = 1024 * 1024 * 20;  // 20MB

    if (setsockopt(session_socket_, SOL_SOCKET, SO_RCVBUF,
                   &i_rcvbuf_size, sizeof(i_rcvbuf_size)) == -1) {
        PML_log(PMLLOG_ERROR, "Failed to set socket buffer: %s", strerror(errno));
        return false;
    }

    PML_log(PMLLOG_INFO, "init_socket setsockopt SO_RCVBUF i_rcvbuf_size = %d", i_rcvbuf_size);
    return true;
}

// 获取网卡index - 对应原 get_ifindex()
bool PPPoESocketManager::get_interface_index() {
    if (session_socket_ < 0) {
        return false;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, nic_name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(session_socket_, SIOCGIFINDEX, &ifr) == -1) {
        PML_log(PMLLOG_ERROR, "%s\n", strerror(errno));
        return false;
    }

    ifindex_ = ifr.ifr_ifindex;
    return true;
}

// 获取网卡MAC地址 - 对应原 get_macaddr()
bool PPPoESocketManager::get_mac_address() {
    if (session_socket_ < 0) {
        return false;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, nic_name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(session_socket_, SIOCGIFHWADDR, &ifr) == -1) {
        PML_log(PMLLOG_ERROR, "%s\n", strerror(errno));
        return false;
    }

    std::memcpy(connection_info_.my_mac.data(), ifr.ifr_hwaddr.sa_data, MAC_LEN);
    return true;
}

// 设置混杂模式 - 对应原 set_promisc()
bool PPPoESocketManager::set_promiscuous_mode() {
    if (session_socket_ < 0) {
        return false;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, nic_name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(session_socket_, SIOCGIFFLAGS, &ifr) == -1) {
        PML_log(PMLLOG_ERROR, "Failed to get interface flags: %s", strerror(errno));
        return false;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(session_socket_, SIOCSIFFLAGS, &ifr) == -1) {
        PML_log(PMLLOG_ERROR, "Failed to set promiscuous mode: %s", strerror(errno));
        return false;
    }

    return true;
}

// 绑定socket - 对应原 init_socket() 中的 bind() 调用
bool PPPoESocketManager::bind_socket() {
    if (session_socket_ < 0 || ifindex_ < 0) {
        return false;
    }

    struct sockaddr_ll sll {};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex_;
    sll.sll_protocol = htons(ETH_P_ALL);

    int err = bind(session_socket_, reinterpret_cast<const struct sockaddr*>(&sll), sizeof(sll));
    if (err != 0) {
        perror("bind failed");
        return false;
    }

    return true;
}

// 关闭socket
void PPPoESocketManager::close_socket() {
    if (session_socket_ >= 0) {
        close(session_socket_);
        session_socket_ = -1;
    }
}

// ==================== PPPoEPacketHandler Implementation ====================

PPPoEPacketHandler::PPPoEPacketHandler(PPPoESocketManager& socket_mgr,
                                       PPPoESessionManager& session_mgr)
    : socket_mgr_(socket_mgr), session_mgr_(session_mgr), recv_buffer_{},
      rohc_work_buf_{} {}

void PPPoEPacketHandler::swap_mac_addresses(PPPoEFrame* frame) {
    auto temp = frame->destination_addr;
    frame->destination_addr = frame->source_addr;
    frame->source_addr = temp;
}

// 对应原 send_raw_packet() - 辅助函数，从 send_PPPoE() 抽取
int PPPoEPacketHandler::send_raw_packet(const void* buffer, uint16_t length,
                                        const MacAddress& dest_mac) {
    if (!buffer || length == 0) {
        return -1;
    }

    struct sockaddr_ll dest_addr {};
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = socket_mgr_.get_connection_info().ifindex;
    dest_addr.sll_halen = MAC_LEN;
    std::memcpy(dest_addr.sll_addr, dest_mac.data(), MAC_LEN);

    int sent = sendto(socket_mgr_.get_socket(), buffer, length, 0,
                      reinterpret_cast<const struct sockaddr*>(&dest_addr),
                      sizeof(dest_addr));

    if (sent < 0) {
        PML_log(PMLLOG_ERROR, "sendto failed: %s", strerror(errno));
    }

    return sent;
}

// 对应原 send_PPPoE()
int PPPoEPacketHandler::send_pppoe_to_server(const PPPoEFrame* frame,
                                              uint16_t session_id, uint16_t length) {
    if (!frame || length == 0) {
        return -1;
    }

    const auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    return send_raw_packet(frame, length, session->ppp_mac);
}

// 对应原 send_other()
int PPPoEPacketHandler::send_other_to_server(const PADTFrame* frame, uint16_t session_id,
                                             uint16_t length) {
    if (!frame || length == 0) {
        return -1;
    }

    auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    PADTFrame padt = *frame;
    padt.eth_dst_mac = socket_mgr_.get_connection_info().peer_mac;
    padt.eth_src_mac = session->ppp_mac;

    printf("send PADT to server[%u]\n", session_id);

    return send_raw_packet(&padt, length, socket_mgr_.get_connection_info().peer_mac);
}

// 对应原 send_PPPoE_to_PPP()
int PPPoEPacketHandler::send_pppoe_to_ppp(const uint8_t* buffer, uint16_t session_id,
                                          uint16_t length) {
    if (!buffer || length == 0) {
        return -1;
    }

    const auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    auto* comm = PML::SatNccL2L1Comm::instance();
    if (!comm) {
        return -1;
    }

    const auto* frame = reinterpret_cast<const PPPoEFrame*>(buffer);
    // [ROHC集成] 使用修正后的IPv4=0x0021(PPP协议字段)而非旧值0x0800(Ethertype)
    uint16_t protocol = (frame->protocol_field == htons(IPv4)) ?
                       g_us_protocol_type_ipv4 : g_us_protocol_type_data_af;

    PML_log(PMLLOG_INFO, "ncc send to PPPD[%u]", session_id);
    PML_mem_log(PMLLOG_INFO, buffer, length);

    return comm->send_msg(session->rcst_hid, protocol,
                         const_cast<uint8_t*>(buffer), length);
}

// 对应原 send_PADT_to_PPP()
int PPPoEPacketHandler::send_padt_to_ppp(const PADTFrame* frame, uint16_t session_id,
                                         uint16_t length) {
    if (!frame || length == 0) {
        return -1;
    }

    auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    PADTFrame padt = *frame;
    padt.eth_dst_mac = session->ppp_mac;
    padt.eth_src_mac = socket_mgr_.get_connection_info().peer_mac;

    auto* comm = PML::SatNccL2L1Comm::instance();
    if (!comm) {
        return -1;
    }

    uint8_t* padt_buffer = reinterpret_cast<uint8_t*>(&padt);
    PML_log(PMLLOG_INFO, "ncc send to PPPD[%u]", session_id);
    PML_mem_log(PMLLOG_INFO, padt_buffer, length);
    printf("send PADT to ppp[%u]\n", session_id);

    return comm->send_msg(session->rcst_hid, g_us_protocol_type_data_af,
                         padt_buffer, length);
}

// 对应原 virtual_send_lcp_ack_to_server()
int PPPoEPacketHandler::send_virtual_lcp_ack(const PPPoEFrame* frame,
                                             uint16_t session_id, uint16_t length) {
    if (!frame || length == 0) {
        return -1;
    }

    PPPoEFrame response = *frame;
    auto* lcp = reinterpret_cast<LCPPacket*>(response.ppp_payload);
    lcp->code = LCP_CONFIG_ACK;
    swap_mac_addresses(&response);

    int ret = send_pppoe_to_server(&response, session_id, length);
    PML_log(PMLLOG_INFO, "ncc send virtual lcp ack to server!");
    PML_mem_log(PMLLOG_INFO, reinterpret_cast<uint8_t*>(&response), length);

    return ret;
}

// 对应原 virtual_send_ipcp_ack_to_server()
int PPPoEPacketHandler::send_virtual_ipcp_ack(const PPPoEFrame* frame,
                                              uint16_t session_id, uint16_t length) {
    if (!frame || length == 0) {
        return -1;
    }

    PPPoEFrame response = *frame;
    auto* ipcp = reinterpret_cast<LCPPacket*>(response.ppp_payload);
    ipcp->code = LCP_CONFIG_ACK;
    swap_mac_addresses(&response);

    int ret = send_pppoe_to_server(&response, session_id, length);
    PML_log(PMLLOG_INFO, "ncc send virtual ipcp ack to server!");
    PML_mem_log(PMLLOG_INFO, reinterpret_cast<uint8_t*>(&response), length);

    return ret;
}

int PPPoEPacketHandler::notify_pppoe_error(uint64_t rcst_hid, uint8_t reason) {
    auto* observer_mgr = PML::SatObserverMgr::instance();
    if (!observer_mgr) {
        return -1;
    }

    struct pppoe_error_info error_info {};
    error_info.m_ul_rcst_hid = rcst_hid;
    error_info.m_uc_error_reason = reason;

    observer_mgr->notify_observer_msg(g_ui_ncc_observer_type_pppoe_process,
                                      g_ui_ncc_observer_subtype_pppoe_link_error,
                                      &error_info);
    return 0;
}

// ==================== PPP to Server: Discovery ====================

int PPPoEPacketHandler::handle_padi_from_ppp(const PPPoEFrame* frame, uint64_t rcst_hid,
                                             uint16_t length) {
    uint16_t session_id = PPPOE_COUNT;
    uint16_t first_idle = PPPOE_COUNT;

    for (uint16_t loop_idx = 0; loop_idx < PPPOE_COUNT; ++loop_idx) {
        auto* session = session_mgr_.get_session(loop_idx);
        if (!session) continue;

        if (session->ppp_state == SessionState::IDLE && first_idle == PPPOE_COUNT) {
            first_idle = loop_idx;
        }

        if (session->rcst_hid == rcst_hid) {
            session_id = loop_idx;
            if (session->ppp_state == SessionState::IDLE ||
                session->ppp_state == SessionState::PADI_SENT ||
                session->ppp_state == SessionState::PADO_RECEIVED ||
                session->ppp_state == SessionState::PADS_RECEIVED ||
                session->ppp_state == SessionState::AUTH_IN_PROGRESS) {
                break;
            }
        }
    }

    if (session_id >= PPPOE_COUNT) {
        if (first_idle < PPPOE_COUNT) {
            session_id = first_idle;
        } else {
            PML_log(PMLLOG_ERROR, "no available element!");
            return 0;
        }
    }

    if (session_mgr_.get_online_count() + 1 > PPPOE_COUNT) {
        PML_log(PMLLOG_ERROR, "the number of PPP terminals has reached its limit! ppp_online = %u",
               session_mgr_.get_online_count());
        return 0;
    }

    if (frame->source_addr[0] % 2 != 0) {
        printf("MAC illegal!!!!!!!\n");
        return 0;
    }

    session_mgr_.allocate_or_update(session_id, rcst_hid, frame->source_addr);

    // [bug-fix] 新PADI会话分配后清除Discovery/Auth缓存(terminate缓存保留) begin
    // 终端重发PADI时如果PADO缓存未被重试逻辑拦截, 说明是全新连接或服务器未响应PADO
    // 此时需清除旧的Discovery/Auth缓存, 但terminate缓存需保留以支持PADT丢包重发
    {
        auto* new_session = session_mgr_.get_session(session_id);
        if (new_session) {
            new_session->has_cached_pado = false;
            new_session->cached_pado_len = 0;
            new_session->has_cached_pads = false;
            new_session->cached_pads_len = 0;
            new_session->has_cached_auth_response = false;
            new_session->cached_auth_response_len = 0;
            // 注意: has_cached_terminate 不清除, 需跨IDLE状态持续有效
        }
    }
    // [bug-fix] 新PADI会话分配后清除Discovery/Auth缓存(terminate缓存保留) end

    int sent_count = send_pppoe_to_server(frame, session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending PADI,%s", strerror(errno));
        return 0;
    }

    printf("send PADI, i_id=%u\n", session_id);
    PML_log(PMLLOG_INFO, "send PADI, session_id=%u", session_id);
    printf("ppp_online = %u\n", session_mgr_.get_online_count());

    return 1;
}

int PPPoEPacketHandler::handle_discovery_from_ppp(const PPPoEFrame* frame,
                                                  uint64_t rcst_hid, uint16_t length) {
    switch (frame->ppoe_code) {
        case CODE_OF_PADI: {
            PML_log(PMLLOG_INFO, "recv PADI first\n");
            printf("recv PADI first\n");

            // [bug-fix] bug#4/P1-PADO丢包: PADI重试检测,重发缓存的PADO begin
            // 场景: NCC收到PADO并转发给终端,但PADO在NCC→终端链路上丢包
            // 终端因超时重发PADI, NCC检测到PADI重试后直接重发缓存的PADO
            // 而不是再次转发PADI到服务器(避免服务器重复处理)
            {
                uint16_t exist_id;
                if (session_mgr_.find_by_hid(rcst_hid, exist_id)) {
                    auto* exist_session = session_mgr_.get_session(exist_id);
                    if (exist_session && exist_session->has_cached_pado &&
                        (exist_session->ppp_state == SessionState::PADI_SENT ||
                         exist_session->ppp_state == SessionState::PADO_RECEIVED)) {
                        PML_log(PMLLOG_INFO, "PADI retry detected for session[%u], resending cached PADO", exist_id);
                        printf("PADI retry detected, resending cached PADO[%u]\n", exist_id);
                        send_pppoe_to_ppp(exist_session->cached_pado, exist_id, exist_session->cached_pado_len);
                        return 1;
                    }
                }
            }
            // [bug-fix] bug#4/P1-PADO丢包: PADI重试检测,重发缓存的PADO end

            // [bug-fix] P2-PADT丢包: 终端发起新PADI时,清除terminate缓存 begin
            // 场景: 服务器发PADT给终端,但PADT丢失,终端不知道已被断开
            // 终端重新开机或重连时发起新PADI,此时应清除旧的terminate缓存
            {
                uint16_t exist_id;
                if (session_mgr_.find_by_hid(rcst_hid, exist_id)) {
                    auto* exist_session = session_mgr_.get_session(exist_id);
                    if (exist_session && exist_session->ppp_state == SessionState::IDLE &&
                        exist_session->has_cached_terminate) {
                        exist_session->has_cached_terminate = false;
                        exist_session->cached_terminate_len = 0;
                        PML_log(PMLLOG_INFO, "Terminal starts new PADI, terminate cache cleared for session[%u]", exist_id);
                        printf("New PADI from terminal, terminate cache cleared[%u]\n", exist_id);
                    }
                }
            }
            // [bug-fix] P2-PADT丢包: 终端发起新PADI时,清除terminate缓存 end

            return handle_padi_from_ppp(frame, rcst_hid, length);
        }

        case CODE_OF_PADR: {
            uint16_t session_id;
            if (!session_mgr_.find_by_hid(rcst_hid, session_id)) {
                return 0;
            }

            // [bug-fix] PADS丢包: PADR重试检测,重发缓存的PADS begin
            // 场景: NCC收到PADS并转发给终端,但PADS在NCC→终端链路上丢包
            // 终端因超时重发PADR, NCC检测到PADR重试后直接重发缓存的PADS
            // 而不是再次转发PADR到服务器(避免服务器重复分配session)
            {
                auto* session = session_mgr_.get_session(session_id);
                if (session && session->has_cached_pads) {
                    PML_log(PMLLOG_INFO, "PADR retry detected for session[%u], resending cached PADS", session_id);
                    printf("PADR retry detected, resending cached PADS[%u]\n", session_id);
                    send_pppoe_to_ppp(session->cached_pads, session_id, session->cached_pads_len);
                    return 1;
                }
            }
            // [bug-fix] PADS丢包: PADR重试检测,重发缓存的PADS end

            printf("\nsend PADR\n");
            PML_log(PMLLOG_INFO, "send PADR");
            return send_pppoe_to_server(frame, session_id, length);
        }

        case CODE_OF_PADT: {
            uint16_t session_id;
            if (!session_mgr_.find_by_hid(rcst_hid, session_id)) {
                return 0;
            }

            // [ROHC集成] 终端发起PADT断开,销毁ROHC通道
            rohc_destroy_channel(session_id);

            // [bug-fix] bug#5: 终端发起PADT时清除Discovery/Auth缓存(保留terminate缓存) begin
            // 终端主动发PADT断开连接,需清除该会话的所有缓存
            // terminate缓存保留: 如果之前服务器也发了PADT但终端未收到,终止缓存仍需保留
            {
                auto* session = session_mgr_.get_session(session_id);
                if (session) {
                    session->has_cached_pado = false;
                    session->cached_pado_len = 0;
                    session->has_cached_pads = false;
                    session->cached_pads_len = 0;
                    session->has_cached_auth_response = false;
                    session->cached_auth_response_len = 0;
                    PML_log(PMLLOG_INFO, "PADT from terminal, Discovery/Auth cache cleared for session[%u]", session_id);
                }
            }
            // [bug-fix] bug#5: 终端发起PADT时清除Discovery/Auth缓存(保留terminate缓存) end

            printf("\nsend PADT\n");
            PML_log(PMLLOG_INFO, "\nsend PADT\n");
            return send_pppoe_to_server(frame, session_id, length);
        }

        default:
            return 0;
    }
}

// ==================== PPP to Server: Session ====================

int PPPoEPacketHandler::handle_lcp_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                            const LCPPacket* lcp, uint16_t length) {
    switch (lcp->code) {
        case LCP_CONFIG_REQUEST:
            printf("recv LCP config req from PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_ACK:
            printf("recv LCP config (CHAP) ACK from PPP client[%u]\n", session_id);
            break;
        case LCP_ECHO_REQUEST:
            printf("recv LCP echo request from PPP client[%u]\n", session_id);
            break;
        case LCP_ECHO_REPLY:
            printf("recv LCP echo reply from PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_NAK:
            printf("recv LCP config Nak from PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_REJECT:
            printf("recv LCP config reject from PPP client[%u]\n", session_id);
            break;
        case LCP_TERMINATION_REQUEST: {
            printf("recv LCP termination req from PPP[%u]\n", session_id);

            auto* session = session_mgr_.get_session(session_id);
            if (!session) {
                return -1;
            }

            if (session->ppp_state != SessionState::ESTABLISHED) {
                if (session->ppp_state == SessionState::AUTH_IN_PROGRESS) {
                    notify_pppoe_error(session->rcst_hid, 0);
                } else if (session->ppp_state == SessionState::PADS_RECEIVED) {
                    notify_pppoe_error(session->rcst_hid, 1);
                }
            } else {
                notify_pppoe_error(session->rcst_hid, 2);
            }

            // [ROHC集成] 终端发起LCP Terminate,销毁ROHC通道
            rohc_destroy_channel(session_id);

            // [bug-fix] bug#5: 终端发起LCP Terminate时清除Discovery/Auth缓存(保留terminate) begin
            // 终端主动断开连接,清除Discovery和Auth阶段的缓存
            // terminate缓存保留: 如果服务器之前也发了PADT, 终止缓存仍需保留直到终端重新上线
            {
                session->has_cached_pado = false;
                session->cached_pado_len = 0;
                session->has_cached_pads = false;
                session->cached_pads_len = 0;
                session->has_cached_auth_response = false;
                session->cached_auth_response_len = 0;
                PML_log(PMLLOG_INFO, "LCP Terminate from terminal, Discovery/Auth cache cleared for session[%u]", session_id);
            }
            // [bug-fix] bug#5: 终端发起LCP Terminate时清除Discovery/Auth缓存(保留terminate) end

            session_mgr_.set_state(session_id, SessionState::IDLE);
            printf("\n--ppp_online = %u\n", session_mgr_.get_online_count());
            break;
        }
        case LCP_TERMINATION_ACK:
            printf("recv LCP termination ack from PPP client[%u]\n", session_id);
            PML_log(PMLLOG_INFO, "ppp_state=%u",
                   static_cast<uint8_t>(session_mgr_.get_state(session_id)));
            break;
        case LCP_PROTOCOL_REJECT:
            printf("recv LCP protocol reject from PPP client[%u]\n", session_id);
            break;
        default:
            printf("other LCP type from PPP client:0x%02x!\n", lcp->code);
            break;
    }

    return send_pppoe_to_server(frame, session_id, length);
}

int PPPoEPacketHandler::handle_chap_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                             uint16_t length) {
    auto* lcp = reinterpret_cast<const LCPPacket*>(frame->ppp_payload);

    // [bug-fix] bug#7/P1-CHAP Success丢包: CHAP Response重试检测,重发缓存的认证响应 begin
    // 场景: 服务器发送CHAP Success给终端,但在NCC→终端链路上丢包
    // 终端因未收到CHAP Success而重发CHAP Response
    // NCC检测到CHAP Response重试后直接重发缓存的CHAP Success
    // 而不是再次转发CHAP Response到服务器(避免服务器重复处理认证)
    {
        auto* session = session_mgr_.get_session(session_id);
        if (session && session->has_cached_auth_response &&
            session->ppp_state == SessionState::AUTH_IN_PROGRESS &&
            lcp->code == LCP_CONFIG_ACK) {
            PML_log(PMLLOG_INFO, "CHAP Response retry detected for session[%u], resending cached auth response", session_id);
            printf("CHAP Response retry detected, resending cached auth response[%u]\n", session_id);
            send_pppoe_to_ppp(session->cached_auth_response, session_id, session->cached_auth_response_len);
            return 1;
        }
    }
    // [bug-fix] bug#7/P1-CHAP Success丢包: CHAP Response重试检测,重发缓存的认证响应 end

    if (lcp->code == LCP_CONFIG_ACK) {
        printf("recv CHAP response from PPP client[%u]\n", session_id);
    } else {
        printf("other CHAP type:0x%02x!\n", lcp->code);
    }

    return send_pppoe_to_server(frame, session_id, length);
}

int PPPoEPacketHandler::handle_pap_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                            uint16_t length) {
    auto* lcp = reinterpret_cast<const LCPPacket*>(frame->ppp_payload);

    // [bug-fix] bug#8/P1-PAP Ack丢包: PAP Request重试检测,重发缓存的认证响应 begin
    // 场景: 服务器发送PAP Ack给终端,但在NCC→终端链路上丢包
    // 终端因未收到PAP Ack而重发PAP Request
    // NCC检测到PAP Request重试后直接重发缓存的PAP Ack
    // 而不是再次转发PAP Request到服务器(避免服务器重复处理认证)
    {
        auto* session = session_mgr_.get_session(session_id);
        if (session && session->has_cached_auth_response &&
            session->ppp_state == SessionState::AUTH_IN_PROGRESS &&
            lcp->code == LCP_CONFIG_REQUEST) {
            PML_log(PMLLOG_INFO, "PAP Request retry detected for session[%u], resending cached auth response", session_id);
            printf("PAP Request retry detected, resending cached auth response[%u]\n", session_id);
            send_pppoe_to_ppp(session->cached_auth_response, session_id, session->cached_auth_response_len);
            return 1;
        }
    }
    // [bug-fix] bug#8/P1-PAP Ack丢包: PAP Request重试检测,重发缓存的认证响应 end

    if (lcp->code == LCP_CONFIG_REQUEST) {
        printf("recv PAP req from PPP client[%u]\n", session_id);
    } else {
        printf("other PAP type:0x%02x!\n", lcp->code);
    }

    return send_pppoe_to_server(frame, session_id, length);
}

int PPPoEPacketHandler::handle_ipcp_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                             uint16_t length) {
    auto* lcp = reinterpret_cast<const LCPPacket*>(frame->ppp_payload);

    switch (lcp->code) {
        case LCP_CONFIG_REQUEST:
            printf("recv IPCP req from PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_ACK:
            printf("recv IPCP ACK from PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_NAK:
            printf("recv IPCP NAK from PPP client[%u]\n", session_id);
            break;
        default:
            printf("other IPCP type:0x%02x!\n", lcp->code);
            break;
    }

    return send_pppoe_to_server(frame, session_id, length);
}

int PPPoEPacketHandler::handle_ip_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                           uint16_t length) {
    // [ROHC集成] 终端→服务器方向: 网关侧执行ROHC解压
    // 终端在发送前已对IP包执行ROHC压缩(经卫星链路传输),网关收到后需解压再转发给服务器
    auto* session = session_mgr_.get_session(session_id);
    if (session && session->rohc_enabled) {
        // 拷贝到工作缓冲区(frame是const,不可原地修改)
        if (length > ROHC_GATEWAY_WORK_BUF_SIZE) {
            RohcLog(RohcLogLevel::ERROR, "[Gateway] ROHC work buffer too small: need=%u, have=%d",
                    length, ROHC_GATEWAY_WORK_BUF_SIZE);
            // 缓冲区不足,直接转发原始帧
            return send_pppoe_to_server(frame, session_id, length);
        }

        std::memcpy(rohc_work_buf_, reinterpret_cast<const uint8_t*>(frame), length);

        // 打印解压前的信息
        rohc_print_flow("[ROHC-FLOW] Gateway RX from terminal: applying ROHC decompression after satellite RX");

        // 打印压缩后数据摘要
        if (length > PPPOE_IP_PAYLOAD_OFFSET) {
            uint8_t *comp_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
            size_t comp_len = length - PPPOE_IP_PAYLOAD_OFFSET;
            rohc_dump_packet(comp_ptr, comp_len, "DECOMP-BEFORE(ROHC compressed from terminal)", 32);
        }

        // 执行解压
        uint16_t new_len = rohc_decompress_frame(rohc_work_buf_, length, session_id);

        if (new_len != length) {
            // 解压成功
            size_t decomp_ip_len = new_len - PPPOE_IP_PAYLOAD_OFFSET;
            size_t comp_ip_len = length - PPPOE_IP_PAYLOAD_OFFSET;
            rohc_print_decompress_detail(comp_ip_len, decomp_ip_len, session_id);

            // 打印解压后的IP包头
            uint8_t *ip_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
            rohc_print_ip_header(ip_ptr, decomp_ip_len, "DECOMP-AFTER(Original IP)");

            // 使用解压后的工作缓冲区转发给服务器
            const auto* decompressed_frame = reinterpret_cast<const PPPoEFrame*>(rohc_work_buf_);
            return send_pppoe_to_server(decompressed_frame, session_id, new_len);
        } else {
            rohc_print_flow("[ROHC-FLOW] Gateway RX from terminal: decompression skipped or failed, forwarding original");
        }
    }

    return send_pppoe_to_server(frame, session_id, length);
}

int PPPoEPacketHandler::handle_session_from_ppp(const PPPoEFrame* frame, uint16_t session_id,
                                                uint16_t length) {
    auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return 0;
    }

    // [bug-fix] bug#9/P2-PADT丢包(服务器→终端): 终端继续发数据时重发缓存的PADT begin
    // 场景: 服务器发送PADT给终端,但PADT在NCC→终端链路上丢包
    // 终端不知道已被断开,继续发送数据包
    // NCC检测到终端在PADT缓存有效时仍发数据,重发缓存的PADT通知终端断开
    if (session->has_cached_terminate) {
        PML_log(PMLLOG_INFO, "Session data from terminal[%u] after PADT cached, resending PADT", session_id);
        printf("Resending cached PADT to terminal[%u] - PADT was lost\n", session_id);
        send_pppoe_to_ppp(session->cached_terminate, session_id, session->cached_terminate_len);
        return 0;
    }
    // [bug-fix] bug#9/P2-PADT丢包(服务器→终端): 终端继续发数据时重发缓存的PADT end

    if (session->ppp_state != SessionState::AUTH_IN_PROGRESS &&
        session->ppp_state != SessionState::ESTABLISHED &&
        session->ppp_state != SessionState::PADS_RECEIVED) {
        return 0;
    }

    const auto* lcp = reinterpret_cast<const LCPPacket*>(frame->ppp_payload);

    // [ROHC集成] 使用修正后的IPv4=0x0021(PPP协议字段)
    switch (frame->protocol_field) {
        case htons(LCP):
            return handle_lcp_from_ppp(frame, session_id, lcp, length);
        case htons(CHAP):
            return handle_chap_from_ppp(frame, session_id, length);
        case htons(PAP):
            return handle_pap_from_ppp(frame, session_id, length);
        case htons(IPCP):
            return handle_ipcp_from_ppp(frame, session_id, length);
        case htons(IPv4):
            return handle_ip_from_ppp(frame, session_id, length);
        default:
            printf("recv other message from PPP client[%u]\n", session_id);
            return 1;
    }
}

// ==================== Server to PPP: Discovery ====================

int PPPoEPacketHandler::handle_pado_from_server(const PPPoEFrame* frame, uint16_t length) {
    uint16_t session_id = PPPOE_COUNT;

    for (uint16_t i = 0; i < PPPOE_COUNT; ++i) {
        auto* session = session_mgr_.get_session(i);
        if (session && session->ppp_mac == frame->destination_addr) {
            session_id = i;
            break;
        }
    }

    if (session_id >= PPPOE_COUNT) {
        PML_log(PMLLOG_ERROR, "can't find this rcst_HID in record");
        return 0;
    }

    socket_mgr_.get_connection_info().peer_mac = frame->source_addr;

    printf("recv PADO from server\n");

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending PADO,%s", strerror(errno));
        return 0;
    }

    PML_log(PMLLOG_INFO, "send PADO to PPP client\n");
    printf("send PADO to PPP client\n");

    // [bug-fix] P1-PADO丢包: 缓存PADO用于PADI重试重发 begin
    // 收到服务器PADO并成功转发给终端后,缓存该PADO帧
    // 如果PADO在NCC→终端链路上丢包,终端会重发PADI
    // NCC检测到PADI重试后可直接重发缓存的PADO,无需再转发PADI到服务器
    {
        auto* session_pado = session_mgr_.get_session(session_id);
        if (session_pado) {
            std::memcpy(session_pado->cached_pado, reinterpret_cast<const uint8_t*>(frame), length);
            session_pado->cached_pado_len = length;
            session_pado->has_cached_pado = true;
            PML_log(PMLLOG_INFO, "PADO cached for session[%u] in case of PADI retry", session_id);
        }
    }
    // [bug-fix] P1-PADO丢包: 缓存PADO用于PADI重试重发 end

    auto* session = session_mgr_.get_session(session_id);
    if (session && session->ppp_state == SessionState::PADI_SENT) {
        session_mgr_.set_state(session_id, SessionState::PADO_RECEIVED);
    }

    return 0;
}

int PPPoEPacketHandler::handle_pads_from_server(const PPPoEFrame* frame, uint16_t length) {
    uint16_t session_id = PPPOE_COUNT;

    for (uint16_t i = 0; i < PPPOE_COUNT; ++i) {
        auto* session = session_mgr_.get_session(i);
        if (session && session->ppp_mac == frame->destination_addr) {
            session_id = i;
            break;
        }
    }

    if (session_id >= PPPOE_COUNT) {
        PML_log(PMLLOG_ERROR, "can't find this rcst_HID in record");
        return 0;
    }

    printf("\nrecv PADS from server\n");

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending PADS,%s", strerror(errno));
        return 0;
    }

    PML_log(PMLLOG_INFO, "send PADS to PPP client\n");
    printf("send PADS to PPP client\n");

    // [bug-fix] PADS丢包: 缓存PADS用于PADR重试重发 begin
    // 收到服务器PADS并成功转发给终端后,缓存该PADS帧
    // 如果PADS在NCC→终端链路上丢包,终端会重发PADR
    // NCC检测到PADR重试后可直接重发缓存的PADS,无需再转发PADR到服务器
    // (避免服务器重复分配session或报错)
    {
        auto* session_pads = session_mgr_.get_session(session_id);
        if (session_pads) {
            std::memcpy(session_pads->cached_pads, reinterpret_cast<const uint8_t*>(frame), length);
            session_pads->cached_pads_len = length;
            session_pads->has_cached_pads = true;
            PML_log(PMLLOG_INFO, "PADS cached for session[%u] in case of PADR retry", session_id);
        }
    }
    // [bug-fix] PADS丢包: 缓存PADS用于PADR重试重发 end

    auto* session = session_mgr_.get_session(session_id);
    if (session && session->ppp_state == SessionState::PADO_RECEIVED) {
        session->pppoe_session_id = ntohs(frame->pppoe_session_id);
        session_mgr_.set_state(session_id, SessionState::PADS_RECEIVED);

        // [bug-fix] P1-PADO丢包: 进入PADS_RECEIVED(LCP阶段),清除PADO缓存 begin
        // PADS已成功转发且终端已进入LCP阶段,PADO缓存不再需要
        session->has_cached_pado = false;
        session->cached_pado_len = 0;
        PML_log(PMLLOG_INFO, "PADO cache cleared for session[%u], entering PADS_RECEIVED", session_id);
        // [bug-fix] P1-PADO丢包: 进入PADS_RECEIVED(LCP阶段),清除PADO缓存 end
    }

    return 0;
}

int PPPoEPacketHandler::handle_padt_from_server(const PPPoEFrame* frame, uint16_t length) {
    uint16_t session_id = PPPOE_COUNT;

    for (uint16_t i = 0; i < PPPOE_COUNT; ++i) {
        auto* session = session_mgr_.get_session(i);
        if (session && session->pppoe_session_id == ntohs(frame->pppoe_session_id)) {
            session_id = i;
            break;
        }
    }

    if (session_id >= PPPOE_COUNT) {
        return 0;
    }

    printf("\n[%u]recv PADT from server, terminated\n", session_id);
    PML_log(PMLLOG_INFO, "\n[%u]recv PADT from server, terminated\n", session_id);

    auto* session = session_mgr_.get_session(session_id);
    if (session && session->ppp_state == SessionState::IDLE) {
        PML_log(PMLLOG_INFO, "the user has offed already, ppp_online= %u\n",
               session_mgr_.get_online_count());
        return 0;
    }

    // [ROHC集成] 收到服务器PADT,销毁ROHC通道
    rohc_destroy_channel(session_id);

    // [bug-fix] P2-PADT丢包(服务器→终端): 缓存终止信令用于重发 begin
    // 收到服务器PADT后,缓存该PADT帧
    // 如果PADT在NCC→终端链路上丢包,终端不知道已被断开
    // 终端继续发数据包时,NCC检测到terminate缓存有效,重发缓存的PADT通知终端断开
    // 注意: terminate缓存不在reset/session重置时清除,仅在终端成功重启新PADI时清除
    {
        auto* session_term = session_mgr_.get_session(session_id);
        if (session_term) {
            std::memcpy(session_term->cached_terminate,
                       reinterpret_cast<const uint8_t*>(frame), length);
            session_term->cached_terminate_len = length;
            session_term->has_cached_terminate = true;
            PML_log(PMLLOG_INFO, "PADT(terminate) cached for session[%u] in case of resend", session_id);
        }
    }
    // [bug-fix] P2-PADT丢包(服务器→终端): 缓存终止信令用于重发 end

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending PADT,%s", strerror(errno));
        return 0;
    }

    PML_log(PMLLOG_INFO, "send PADT to PPP client\n");
    printf("send PADT to PPP client\n");

    // [bug-fix] bug#5: 服务器PADT终止时清除Discovery/Auth缓存(保留terminate缓存) begin
    // 服务器主动断开连接,清除Discovery和Auth阶段的缓存
    // terminate缓存保留: 需要持续有效直到终端确认收到PADT或重新上线
    {
        auto* session_clear = session_mgr_.get_session(session_id);
        if (session_clear) {
            session_clear->has_cached_pado = false;
            session_clear->cached_pado_len = 0;
            session_clear->has_cached_pads = false;
            session_clear->cached_pads_len = 0;
            session_clear->has_cached_auth_response = false;
            session_clear->cached_auth_response_len = 0;
            PML_log(PMLLOG_INFO, "PADT from server, Discovery/Auth cache cleared for session[%u]", session_id);
        }
    }
    // [bug-fix] bug#5: 服务器PADT终止时清除Discovery/Auth缓存(保留terminate缓存) end

    session_mgr_.set_state(session_id, SessionState::IDLE);
    printf("\n--ppp_online= %u\n", session_mgr_.get_online_count());

    return 0;
}

// ==================== Server to PPP: Session ====================

int PPPoEPacketHandler::handle_lcp_from_server(const PPPoEFrame* frame, uint16_t session_id,
                                               const LCPPacket* lcp, uint16_t length) {
    switch (lcp->code) {
        case LCP_ECHO_REQUEST:
            printf("[%u] send echo req to ppp client\n", session_id);
            break;
        case LCP_ECHO_REPLY:
            printf("[%u] send LCP echo reply to ppp client\n", session_id);
            break;
        case LCP_TERMINATION_REQUEST: {
            printf("[%u] send LCP terminate req to ppp client\n", session_id);

            auto* session = session_mgr_.get_session(session_id);
            if (!session) {
                return -1;
            }

            if (session->ppp_state != SessionState::ESTABLISHED) {
                if (session->ppp_state == SessionState::AUTH_IN_PROGRESS) {
                    notify_pppoe_error(session->rcst_hid, 0);
                } else if (session->ppp_state == SessionState::PADS_RECEIVED) {
                    notify_pppoe_error(session->rcst_hid, 1);
                }
            } else {
                notify_pppoe_error(session->rcst_hid, 2);
            }

            // [ROHC集成] 服务器发起LCP Terminate,销毁ROHC通道
            rohc_destroy_channel(session_id);

            // [bug-fix] bug#5: 服务器发起LCP Terminate时清除Discovery/Auth缓存(保留terminate) begin
            {
                session->has_cached_pado = false;
                session->cached_pado_len = 0;
                session->has_cached_pads = false;
                session->cached_pads_len = 0;
                session->has_cached_auth_response = false;
                session->cached_auth_response_len = 0;
                PML_log(PMLLOG_INFO, "LCP Terminate from server, Discovery/Auth cache cleared for session[%u]", session_id);
            }
            // [bug-fix] bug#5: 服务器发起LCP Terminate时清除Discovery/Auth缓存(保留terminate) end

            PADTFrame padt{};
            padt.ether_type = htons(ETHER_TYPE_DISCOVERY);
            padt.protocol = htons(0x11a7);
            PPPoEUtil::byte_swap_copy(padt.information, &session->pppoe_session_id, 2);
            send_other_to_server(&padt, session_id, 18);

            session_mgr_.set_state(session_id, SessionState::IDLE);
            printf("\n--ppp_online= %u\n", session_mgr_.get_online_count());
            break;
        }
        case LCP_TERMINATION_ACK:
            printf("[%u] send LCP terminate ack to ppp client\n", session_id);
            break;
        case LCP_CONFIG_REQUEST:
            printf("send LCP config (CHAP) request to ppp client[%u]\n", session_id);
            #ifdef USE_PML_IOT_MODEM_SS
            send_virtual_lcp_ack(frame, session_id, length);
            #endif
            printf("send virtual LCP config ack to server[%u]\n", session_id);
            break;
        case LCP_CONFIG_ACK:
            printf("send LCP configure ACK(CHAP) to PPP client[%u]\n", session_id);
            break;
        case LCP_CONFIG_NAK:
            printf("send LCP reject to ppp client[%u]\n", session_id);
            break;
        default:
            printf("other LCP type from server:0x%02x\n", lcp->code);
            break;
    }

    return send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
}

int PPPoEPacketHandler::handle_chap_from_server(const PPPoEFrame* frame, uint16_t session_id,
                                                const LCPPacket* chap, uint16_t length) {
    printf("\n[%u] recv CHAP from server\n", session_id);

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending CHAP,%s", strerror(errno));
        return 0;
    }

    if (chap->code == 0x03) {
        // [bug-fix] P1-CHAP Success丢包: 缓存CHAP Success用于认证重试重发 begin
        // 服务器发送CHAP Success(code=0x03)并成功转发给终端后,缓存该帧
        // 如果CHAP Success在NCC→终端链路上丢包,终端会重发CHAP Response
        // NCC检测到CHAP Response重试后可直接重发缓存的CHAP Success
        {
            auto* session_chap = session_mgr_.get_session(session_id);
            if (session_chap) {
                std::memcpy(session_chap->cached_auth_response,
                           reinterpret_cast<const uint8_t*>(frame), length);
                session_chap->cached_auth_response_len = length;
                session_chap->has_cached_auth_response = true;
                PML_log(PMLLOG_INFO, "CHAP Success cached for session[%u] in case of retry", session_id);
            }
        }
        // [bug-fix] P1-CHAP Success丢包: 缓存CHAP Success用于认证重试重发 end

        session_mgr_.set_state(session_id, SessionState::AUTH_IN_PROGRESS);
        PML_log(PMLLOG_INFO, "[%u] CHAP successfully complete!\n", session_id);
        printf("[%u] CHAP successfully complete!\n", session_id);
    } else if (chap->code == 0x01) {
        printf("send CHAP challenge to PPP client[%u]\n", session_id);
    } else if (chap->code == 0x04) {
        PML_log(PMLLOG_ERROR, "[%u] CHAP failed!", session_id);
    }

    return 0;
}

int PPPoEPacketHandler::handle_pap_from_server(const PPPoEFrame* frame, uint16_t session_id,
                                               const LCPPacket* pap, uint16_t length) {
    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending PAP,%s", strerror(errno));
        return 0;
    }

    if (pap->code == 0x02) {
        // [bug-fix] P1-PAP Ack丢包: 缓存PAP Ack用于认证重试重发 begin
        // 服务器发送PAP Ack(code=0x02)并成功转发给终端后,缓存该帧
        // 如果PAP Ack在NCC→终端链路上丢包,终端会重发PAP Request
        // NCC检测到PAP Request重试后可直接重发缓存的PAP Ack
        {
            auto* session_pap = session_mgr_.get_session(session_id);
            if (session_pap) {
                std::memcpy(session_pap->cached_auth_response,
                           reinterpret_cast<const uint8_t*>(frame), length);
                session_pap->cached_auth_response_len = length;
                session_pap->has_cached_auth_response = true;
                PML_log(PMLLOG_INFO, "PAP Ack cached for session[%u] in case of retry", session_id);
            }
        }
        // [bug-fix] P1-PAP Ack丢包: 缓存PAP Ack用于认证重试重发 end

        session_mgr_.set_state(session_id, SessionState::AUTH_IN_PROGRESS);
        printf("send PAP ack to PPP client[%u]\n", session_id);
        PML_log(PMLLOG_INFO, "[%u] PAP successfully complete!\n", session_id);
    } else if (pap->code == 0x03) {
        printf("send PAP Nack to PPP client[%u]\n", session_id);
        PML_log(PMLLOG_ERROR, "[%u] PAP failed!", session_id);
    }

    return 0;
}

int PPPoEPacketHandler::handle_ipcp_from_server(const PPPoEFrame* frame, uint16_t session_id,
                                                const LCPPacket* ipcp, uint16_t length) {
    printf("\n[%u] recv IPCP from server\n", session_id);

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending IPCP,%s", strerror(errno));
        return 0;
    }

    if (ipcp->code == LCP_CONFIG_ACK) {
        session_mgr_.set_state(session_id, SessionState::ESTABLISHED);

        // [ROHC集成] IPCP ACK - 会话进入ESTABLISHED状态,创建ROHC通道
        // IP地址分配成功后,后续IP数据包将进行ROHC头部压缩/解压
        rohc_init_channel(session_id);

        // [bug-fix] PADS/Auth缓存生命周期: 进入ESTABLISHED时清除PADS和Auth缓存 begin
        // IPCP ACK表示IP地址分配成功,连接进入ESTABLISHED状态
        // 此时PADS缓存和Auth缓存不再需要,清除以释放内存
        // (PADO缓存在进入PADS_RECEIVED时已清除)
        {
            auto* session = session_mgr_.get_session(session_id);
            if (session) {
                session->has_cached_pads = false;
                session->cached_pads_len = 0;
                session->has_cached_auth_response = false;
                session->cached_auth_response_len = 0;
                PML_log(PMLLOG_INFO, "PADS and Auth cache cleared for session[%u], entering ESTABLISHED", session_id);
            }
        }
        // [bug-fix] PADS/Auth缓存生命周期: 进入ESTABLISHED时清除PADS和Auth缓存 end

        PML_log(PMLLOG_INFO, "[%u] IP allocate to PPP success!\n", session_id);
        printf("\n[%u] IP allocate to PPP success!\n", session_id);
    } else if (ipcp->code == LCP_CONFIG_REQUEST) {
        printf("send IPCP REQ to PPP client[%u]\n", session_id);
        #ifdef USE_PML_IOT_MODEM_SS
        send_virtual_ipcp_ack(frame, session_id, length);
        printf("send virtual IPCP config ack to server[%u]\n", session_id);
        #endif
    } else if (ipcp->code == LCP_CONFIG_NAK) {
        printf("send IPCP Nak to PPP client[%u]\n", session_id);
    }

    return 0;
}

int PPPoEPacketHandler::handle_ip_from_server(const PPPoEFrame* frame, uint16_t session_id,
                                              uint16_t length) {
    // [ROHC集成] 服务器→终端方向: 网关侧执行ROHC压缩
    // 服务器发来的IP包在网关侧压缩后经卫星链路发送给终端
    auto* session = session_mgr_.get_session(session_id);
    if (session && session->rohc_enabled) {
        // 拷贝到工作缓冲区(frame是const,不可原地修改)
        if (length > ROHC_GATEWAY_WORK_BUF_SIZE) {
            RohcLog(RohcLogLevel::ERROR, "[Gateway] ROHC work buffer too small: need=%u, have=%d",
                    length, ROHC_GATEWAY_WORK_BUF_SIZE);
            // 缓冲区不足,直接转发原始帧
            int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
            if (sent_count < 0) {
                PML_log(PMLLOG_ERROR, "error in sending IP,%s", strerror(errno));
                return 0;
            }
            return 0;
        }

        std::memcpy(rohc_work_buf_, reinterpret_cast<const uint8_t*>(frame), length);

        // 打印压缩前的信息
        rohc_print_flow("[ROHC-FLOW] Gateway TX to terminal: applying ROHC compression before satellite TX");

        // 打印压缩前的IP包头
        if (length > PPPOE_IP_PAYLOAD_OFFSET) {
            uint8_t *ip_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
            size_t ip_len = length - PPPOE_IP_PAYLOAD_OFFSET;
            rohc_print_ip_header(ip_ptr, ip_len, "COMP-BEFORE(Original IP)");
        }

        // 执行压缩
        uint16_t new_len = rohc_compress_frame(rohc_work_buf_, length, ROHC_GATEWAY_WORK_BUF_SIZE, session_id);

        if (new_len != length) {
            // 压缩成功
            size_t orig_ip_len = length - PPPOE_IP_PAYLOAD_OFFSET;
            size_t comp_ip_len = new_len - PPPOE_IP_PAYLOAD_OFFSET;
            rohc_print_compress_detail(orig_ip_len, comp_ip_len, session_id);

            // 打印压缩后的数据摘要
            uint8_t *comp_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
            rohc_dump_packet(comp_ptr, comp_ip_len, "COMP-AFTER(ROHC compressed)", 32);

            // 使用压缩后的工作缓冲区发送给终端
            int sent_count = send_pppoe_to_ppp(rohc_work_buf_, session_id, new_len);
            if (sent_count < 0) {
                PML_log(PMLLOG_ERROR, "error in sending compressed IP,%s", strerror(errno));
                return 0;
            }
            return 0;
        } else {
            rohc_print_flow("[ROHC-FLOW] Gateway TX to terminal: compression skipped or failed, sending original");
        }
    }

    int sent_count = send_pppoe_to_ppp(reinterpret_cast<const uint8_t*>(frame), session_id, length);
    if (sent_count < 0) {
        PML_log(PMLLOG_ERROR, "error in sending IP,%s", strerror(errno));
        return 0;
    }

    return 0;
}

// ==================== Main Entry Points ====================

// 对应原 send_message_from_ppp()
int PPPoEPacketHandler::send_message_from_ppp(uint64_t rcst_hid, const uint8_t* content,
                                              uint16_t length) {
    if (!content || length == 0) {
        return -1;
    }

    PML_log(PMLLOG_INFO, " recv message from ppp:");
    PML_mem_log(PMLLOG_INFO, content, length);

    const auto* frame = reinterpret_cast<const PPPoEFrame*>(content);

    // Discovery phase
    if (frame->ether_type == htons(ETHER_TYPE_DISCOVERY)) {
        return handle_discovery_from_ppp(frame, rcst_hid, length);
    }

    // Session phase
    uint16_t session_id;
    if (!session_mgr_.find_by_hid(rcst_hid, session_id)) {
        PML_log(PMLLOG_ERROR, "NCC wrong, after discovery, but can't find HID 0x%llx", rcst_hid);
        printf("%llx\n", rcst_hid);
        return 0;
    }

    return handle_session_from_ppp(frame, session_id, length);
}

// 对应原 server_session() - 持续运行的线程函数
void PPPoEPacketHandler::server_session_loop() {
    while (true) {
        // 接收来自server的消息
        ssize_t recv_count = recv(socket_mgr_.get_socket(), recv_buffer_, sizeof(recv_buffer_), 0);

        if (recv_count == -1) {
            PML_log(PMLLOG_INFO, "error in receiving packets from session socket\n%s", strerror(errno));
            continue;
        }

        if (recv_count <= 0) {
            continue;
        }

        uint16_t us_length = static_cast<uint16_t>(recv_count);

        if (us_length < 18) {
            continue;
        }

        const auto* frame = reinterpret_cast<const PPPoEFrame*>(recv_buffer_);
        const auto* lcp = reinterpret_cast<const LCPPacket*>(frame->ppp_payload);

        // Discovery phase
        if (frame->ether_type == htons(ETHER_TYPE_DISCOVERY)) {
            switch (frame->ppoe_code) {
                case CODE_OF_PADO:
                    printf("recv PADO from server\n");
                    handle_pado_from_server(frame, us_length);
                    continue;

                case CODE_OF_PADS:
                    printf("\nrecv PADS from server\n");
                    handle_pads_from_server(frame, us_length);
                    continue;

                case CODE_OF_PADT:
                    handle_padt_from_server(frame, us_length);
                    continue;

                default:
                    PML_log(PMLLOG_ERROR, "!recv other PPPOE discovery message from server\n");
                    printf("pppoe_code=0x%02x\n", frame->ppoe_code);
                    continue;
            }
        }
        else if (frame->ether_type == htons(ETHER_TYPE_PPP_SESSION)) {
            // Session phase
            uint16_t session_id = PPPOE_COUNT;

            for (uint16_t i = 0; i < PPPOE_COUNT; ++i) {
                auto* session = session_mgr_.get_session(i);
                if (session && session->pppoe_session_id == ntohs(frame->pppoe_session_id)) {
                    session_id = i;
                    break;
                }
            }

            if (session_id >= PPPOE_COUNT) {
                PML_log(PMLLOG_ERROR, "can't find this session id in record");
                continue;
            }

            auto* session = session_mgr_.get_session(session_id);
            if (!session || (session->ppp_state != SessionState::PADS_RECEIVED &&
                            session->ppp_state != SessionState::AUTH_IN_PROGRESS &&
                            session->ppp_state != SessionState::ESTABLISHED)) {
                printf("recv from server, but ppp_state[%u]=%u\n", session_id,
                       static_cast<uint8_t>(session->ppp_state));
                continue;
            }

            // [ROHC集成] 使用修正后的IPv4=0x0021(PPP协议字段)
            switch (frame->protocol_field) {
                case htons(LCP):
                    printf("\n[%u] recv LCP from server\n", session_id);
                    handle_lcp_from_server(frame, session_id, lcp, us_length);
                    continue;

                case htons(CHAP):
                    printf("\n[%u] recv CHAP from server\n", session_id);
                    handle_chap_from_server(frame, session_id, lcp, us_length);
                    continue;

                case htons(PAP):
                    handle_pap_from_server(frame, session_id, lcp, us_length);
                    continue;

                case htons(IPCP):
                    printf("\n[%u] recv IPCP from server\n", session_id);
                    handle_ipcp_from_server(frame, session_id, lcp, us_length);
                    continue;

                case htons(IPv4):
                    handle_ip_from_server(frame, session_id, us_length);
                    continue;

                default:
                    printf("\n[%u] recv other PPPOE session message from server, not send\n", session_id);
                    continue;
            }
        }
        else
        {
            continue;
        }
    }
}

// ==================== PPPoETrafficManager Implementation ====================

PPPoETrafficManager::PPPoETrafficManager(PPPoESessionManager& session_mgr,
                                         PPPoEPacketHandler& handler)
    : session_mgr_(session_mgr), handler_(handler), thread_running_(false) {}

PPPoETrafficManager::~PPPoETrafficManager() {
    stop_traffic_check_thread();
}

bool PPPoETrafficManager::start_traffic_check_thread() {
    if (thread_running_) {
        return false;
    }

    thread_running_ = true;
    traffic_thread_ = std::make_unique<std::thread>(&PPPoETrafficManager::traffic_check_loop, this);

    if (!traffic_thread_) {
        thread_running_ = false;
        return false;
    }

    PML_log(PMLLOG_INFO, "Traffic check thread started");
    return true;
}

void PPPoETrafficManager::stop_traffic_check_thread() {
    if (!thread_running_) {
        return;
    }

    thread_running_ = false;
    if (traffic_thread_ && traffic_thread_->joinable()) {
        traffic_thread_->join();
    }

    PML_log(PMLLOG_INFO, "Traffic check thread stopped");
}

bool PPPoETrafficManager::connect_database(MYSQL*& conn) {
    conn = mysql_init(nullptr);
    if (!conn) {
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_init failed: error = %s",
               mysql_error(conn));
        return false;
    }

    if (!mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, nullptr, 0)) {
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_real_connect failed: error = %s",
               mysql_error(conn));
        mysql_close(conn);
        conn = nullptr;
        return false;
    }

    return true;
}

void PPPoETrafficManager::disconnect_database(MYSQL*& conn) {
    if (conn) {
        mysql_close(conn);
        conn = nullptr;
    }
}

int PPPoETrafficManager::notify_traffic_exceeded(uint16_t session_id, uint64_t total_traffic) {
    auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    PADTFrame padt{};
    padt.ether_type = htons(ETHER_TYPE_DISCOVERY);
    padt.protocol = htons(0x11a7);
    PPPoEUtil::byte_swap_copy(padt.information, &session->pppoe_session_id, 2);

    // 断开pppoe连接
    handler_.send_other_to_server_public(&padt, session_id, 18);
    handler_.send_padt_to_ppp(&padt, session_id, 18);

    // [ROHC集成] 流量超限断开时销毁ROHC通道
    handler_.rohc_destroy_channel(session_id);

    // [bug-fix] bug#5: 流量超限断开时清除Discovery/Auth缓存(保留terminate缓存) begin
    {
        session->has_cached_pado = false;
        session->cached_pado_len = 0;
        session->has_cached_pads = false;
        session->cached_pads_len = 0;
        session->has_cached_auth_response = false;
        session->cached_auth_response_len = 0;
        PML_log(PMLLOG_INFO, "Traffic exceeded, Discovery/Auth cache cleared for session[%u]", session_id);
    }
    // [bug-fix] bug#5: 流量超限断开时清除Discovery/Auth缓存(保留terminate缓存) end

    // 更新session状态
    session_mgr_.set_state(session_id, SessionState::IDLE);

    PML_log(PMLLOG_WARNING, "user[%u] traffic exceeds the limit, ppp_online = %u",
           session_id, session_mgr_.get_online_count());

    return 0;
}

bool PPPoETrafficManager::query_online_users(MYSQL* conn) {
    if (!conn) {
        return false;
    }

    uint16_t online_count = session_mgr_.get_online_count();
    if (online_count == 0) {
        return true;
    }

    char sz_sql[256] = {0};
    snprintf(sz_sql, sizeof(sz_sql),
             "SELECT %s,%s,%s FROM %s ORDER BY radacctid DESC LIMIT %u",
             COL_INPUT, COL_OUTPUT, COL_MAC, TABLE_NAME, online_count);

    int i_ret = mysql_query(conn, sz_sql);
    if (i_ret != 0) {
        // 查询失败
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_query failed: sql = %s, error = %s",
               sz_sql, mysql_error(conn));
        mysql_close(conn);
        conn = nullptr;
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (nullptr == result) {
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_store_result failed: sql = %s, error = %s",
               sz_sql, mysql_error(conn));
        mysql_close(conn);
        conn = nullptr;
        return false;
    }

    int i_ppp_online_user = mysql_num_rows(result);
    PML_log(PMLLOG_WARNING, "check_ppp_traffic_limit online user: %d", i_ppp_online_user);

    // ===== 关键：必须检查conn != nullptr 才能fetch row =====
    if (nullptr != conn) {
        MYSQL_ROW row = mysql_fetch_row(result);
        while (nullptr != row) {
            // 解析traffic数据
            unsigned long long tra1 = strtoull(row[0], nullptr, 10);
            unsigned long long tra2 = strtoull(row[1], nullptr, 10);
            const char* ppp_mac_sqlstr = row[2];

            unsigned long long total = tra1 + tra2;

            // 清理hex字符串
            std::string cleaned_hex = PPPoEUtil::clean_hex_string(ppp_mac_sqlstr);

            // 转换为MAC地址
            auto mac_opt = PPPoEUtil::hex_string_to_mac(cleaned_hex);
            if (!mac_opt.has_value()) {
                PML_log(PMLLOG_WARNING, "check_ppp_traffic_limit 无效字符串");
                row = mysql_fetch_row(result);
                continue;
            }

            MacAddress mysql_mac = mac_opt.value();

            // 查找对应的session
            int i = 0;
            int user_id = 0;
            for (i = 0; i < PPPoESessionManager::MAX_SESSIONS; ++i) {
                auto* session = session_mgr_.get_session(i);
                if (session && session->ppp_mac == mysql_mac) {
                    user_id = i;
                    // printf("ppp mac找到,user_id=%d\n",user_id);
                    break;
                }
            }

            if (i == PPPoESessionManager::MAX_SESSIONS) {
                PML_log(PMLLOG_WARNING, "check_ppp_traffic_limit ppp mac no found!");
                for (int a = 0; a < 6; ++a) {
                    printf("mysql_mac=%02x", mysql_mac[a]);
                    printf("\n");
                }
            }

            PML_log(PMLLOG_WARNING, "user[%d] input = %llu, output =%llu, total =%llu",
                   user_id, tra1, tra2, total);

            // 检查流量限制
            if (total > GB_LIMIT) {
                notify_traffic_exceeded(user_id, total);
            }

            row = mysql_fetch_row(result);
        }
        mysql_free_result(result);
    }

    return true;
}

// 对应原 check_ppp_traffic_limit() 线程函数 - 完全按照原逻辑实现
void PPPoETrafficManager::traffic_check_loop() {
    // 初始化并连接数据库
    MYSQL* conn = mysql_init(nullptr);
    if (nullptr == conn) {
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_init failed: error = %s",
               mysql_error(conn));
        return;
    }

    MYSQL* p_real_connect = mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, nullptr, 0);
    if (nullptr == p_real_connect) {
        PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_real_connect failed: error = %s",
               mysql_error(conn));
        mysql_close(conn);
        return;
    }

    PML_log(PMLLOG_WARNING, "check_ppp_traffic_limit mysql connect succeed");

    while (thread_running_) {
        if (session_mgr_.get_online_count() > 0) {
            // 先判断是否需要重连
            if (nullptr == conn) {
                conn = mysql_init(nullptr);
                if (nullptr == conn) {
                    PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_init failed: error = %s",
                           mysql_error(conn));
                }
                p_real_connect = mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, nullptr, 0);
                if (nullptr == p_real_connect) {
                    PML_log(PMLLOG_ERROR, "check_ppp_traffic_limit mysql_real_connect failed: error = %s",
                           mysql_error(conn));
                    mysql_close(conn);
                    conn = nullptr;
                }
            }

            if (nullptr != conn) {
                query_online_users(conn);
            }
        }

        // 获取当前时间 - 原有逻辑：毫秒级
        uint64_t ul_current_time_ms = std::time(nullptr) * 1000;  // 转换为毫秒
        uint16_t us_sleep_60s = (ul_current_time_ms / 1000) % 60;  // 秒级的余数

        // 如果余数为0，意味着恰好在整分钟，sleep 60秒到下一分钟
        // 否则sleep到下一分钟
        uint16_t sleep_seconds = (us_sleep_60s == 0) ? 60 : (60 - us_sleep_60s);
        sleep(sleep_seconds);
    }

    // 清理资源
    if (nullptr != conn) {
        mysql_close(conn);
        conn = nullptr;
    }
}

// ==================== ROHC 通道管理 ====================

int PPPoEPacketHandler::rohc_init_channel(uint16_t session_id)
{
    auto* session = session_mgr_.get_session(session_id);
    if (!session) {
        return -1;
    }

    if (session->rohc_enabled) {
        RohcLog(RohcLogLevel::INFO, "[Gateway] ROHC channel already initialized for session %u",
                session_id);
        return 0;
    }

    // 网关侧使用GATEWAY角色, session_id作为通道索引
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::GATEWAY);

    int ret = rohc.create_channel(session_id);
    if (ret != 0) {
        RohcLog(RohcLogLevel::ERROR, "[Gateway] Failed to create ROHC channel for session %u",
                session_id);
        session->rohc_enabled = false;
        return -1;
    }

    session->rohc_enabled = true;

    rohc_print_flow("[ROHC-FLOW] ========================================");
    rohc_print_flow("[ROHC-FLOW] Gateway ROHC channel CREATED");
    RohcLog(RohcLogLevel::INFO, "[Gateway] ROHC channel created: session_id=%u, role=GATEWAY",
            session_id);
    RohcLog(RohcLogLevel::INFO, "[Gateway] ROHC profiles: IP/UDP/RTP enabled, O-mode, Piggyback feedback");
    rohc_print_flow("[ROHC-FLOW] ========================================");

    return 0;
}

void PPPoEPacketHandler::rohc_destroy_channel(uint16_t session_id)
{
    auto* session = session_mgr_.get_session(session_id);
    if (!session || !session->rohc_enabled) {
        return;
    }

    rohc_print_flow("[ROHC-FLOW] ========================================");
    rohc_print_flow("[ROHC-FLOW] Gateway ROHC channel DESTROYING");

    // 打印最终统计
    rohc_print_stats(session_id);

    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::GATEWAY);
    rohc.destroy_channel(session_id);

    session->rohc_enabled = false;

    RohcLog(RohcLogLevel::INFO, "[Gateway] ROHC channel destroyed: session_id=%u",
            session_id);
    rohc_print_flow("[ROHC-FLOW] ========================================");
}

// ==================== ROHC 帧级压缩/解压 ====================

uint16_t PPPoEPacketHandler::rohc_decompress_frame(uint8_t *frame_data, uint16_t frame_len, uint16_t session_id)
{
    // 检查是否为IP包
    if (!is_ip_frame(frame_data, frame_len)) {
        return frame_len;
    }

    // 检查帧长度是否足够包含IP头
    if (frame_len <= PPPOE_IP_PAYLOAD_OFFSET) {
        return frame_len;
    }

    // 提取压缩数据在帧中的位置和长度
    uint8_t *rohc_data = frame_data + PPPOE_IP_PAYLOAD_OFFSET;
    size_t rohc_len = frame_len - PPPOE_IP_PAYLOAD_OFFSET;

    if (rohc_len == 0) {
        return frame_len;
    }

    // 检查缓冲区是否有足够空间(解压后IP包可能比压缩包大很多)
    if (PPPOE_IP_PAYLOAD_OFFSET + 1500 > ROHC_GATEWAY_WORK_BUF_SIZE) {
        RohcLog(RohcLogLevel::WARNING, "[Gateway] Buffer too small for decompression: max=%u, need>=%u",
                ROHC_GATEWAY_WORK_BUF_SIZE, PPPOE_IP_PAYLOAD_OFFSET + 1500);
        return frame_len;
    }

    // 调用ROHC解压(网关侧使用GATEWAY角色)
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::GATEWAY);
    size_t decompressed_len = 0;
    int ret = rohc.decompress_packet(session_id, rohc_data, rohc_len, decompressed_len);

    if (ret != 0 || decompressed_len == 0) {
        RohcLog(RohcLogLevel::WARNING, "[Gateway] ROHC decompression failed (comp_len=%zu), dropping packet", rohc_len);
        return frame_len;
    }

    // 更新PPPoE长度字段(偏移18-19)
    // PPPoE Length = 解压后IP数据长度 + PPP协议字段(2字节)
    uint16_t new_pppoe_length = decompressed_len + 2;
    frame_data[18] = (new_pppoe_length >> 8) & 0xFF;
    frame_data[19] = new_pppoe_length & 0xFF;

    // 返回新的帧总长度
    uint16_t new_frame_len = PPPOE_IP_PAYLOAD_OFFSET + decompressed_len;

    RohcLog(RohcLogLevel::DEBUG, "[Gateway] Frame decompressed: comp=%zu, decomp_ip=%zu, frame: %u->%u, expanded=%zu bytes",
            rohc_len, decompressed_len, frame_len, new_frame_len,
            decompressed_len - rohc_len);

    return new_frame_len;
}

uint16_t PPPoEPacketHandler::rohc_compress_frame(uint8_t *frame_data, uint16_t frame_len,
                                                   uint16_t max_frame_len, uint16_t session_id)
{
    // 检查是否为IP包
    if (!is_ip_frame(frame_data, frame_len)) {
        return frame_len;
    }

    // 检查帧长度是否足够包含IP头
    if (frame_len <= PPPOE_IP_PAYLOAD_OFFSET) {
        return frame_len;
    }

    // 提取IP包在帧中的位置和长度
    uint8_t *ip_data = frame_data + PPPOE_IP_PAYLOAD_OFFSET;
    size_t ip_len = frame_len - PPPOE_IP_PAYLOAD_OFFSET;

    // 检查IP包最小长度(20字节IPv4头)
    if (ip_len < 20) {
        RohcLog(RohcLogLevel::WARNING, "[Gateway] IP packet too short for compression: %zu bytes", ip_len);
        return frame_len;
    }

    // 检查压缩后是否有足够空间
    if (max_frame_len <= PPPOE_IP_PAYLOAD_OFFSET) {
        return frame_len;
    }

    // 调用ROHC压缩(网关侧使用GATEWAY角色)
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::GATEWAY);
    size_t compressed_len = 0;
    int ret = rohc.compress_ip_packet(session_id, ip_data, ip_len, compressed_len);

    if (ret != 0 || compressed_len == 0) {
        RohcLog(RohcLogLevel::WARNING, "[Gateway] ROHC compression failed, sending original IP packet");
        return frame_len;
    }

    // 更新PPPoE长度字段(偏移18-19)
    // PPPoE Length = 压缩后IP数据长度 + PPP协议字段(2字节)
    uint16_t new_pppoe_length = compressed_len + 2;
    frame_data[18] = (new_pppoe_length >> 8) & 0xFF;
    frame_data[19] = new_pppoe_length & 0xFF;

    // 返回新的帧总长度
    uint16_t new_frame_len = PPPOE_IP_PAYLOAD_OFFSET + compressed_len;

    RohcLog(RohcLogLevel::DEBUG, "[Gateway] Frame compressed: orig_ip=%zu, comp=%zu, frame: %u->%u, saved=%zu bytes (%.1f%%)",
            ip_len, compressed_len, frame_len, new_frame_len,
            ip_len - compressed_len,
            ip_len > 0 ? (100.0 * (ip_len - compressed_len) / ip_len) : 0.0);

    return new_frame_len;
}

bool PPPoEPacketHandler::is_ip_frame(const uint8_t *frame_data, uint16_t frame_len) const
{
    if (!frame_data || frame_len < PPPOE_IP_PAYLOAD_OFFSET) {
        return false;
    }

    // 通过PPPoEFrame结构体访问,与switch语句保持一致
    const auto* frame = reinterpret_cast<const PPPoEFrame*>(frame_data);

    // 检查以太网类型
    if (frame->ether_type != htons(ETHER_TYPE_PPP_SESSION)) {
        return false;
    }

    // 检查PPP协议字段(IPv4=0x0021, 修正后的PPP协议字段,非Ethertype 0x0800)
    if (frame->protocol_field != htons(IPv4)) {
        return false;
    }

    return true;
}

// ==================== ROHC 调试打印函数 ====================

void PPPoEPacketHandler::rohc_print_flow(const char *step) const
{
#if ROHC_DEBUG_PRINT
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
    printf("[%s.%03ld] %s\n", time_buf, tv.tv_usec / 1000, step);
#else
    (void)step;
#endif
}

void PPPoEPacketHandler::rohc_print_ip_header(const uint8_t *ip_data, size_t ip_len, const char *direction) const
{
#if ROHC_DEBUG_PRINT
    if (!ip_data || ip_len < 20) {
        printf("[ROHC-DBG] %s: IP packet too short (%zu bytes)\n", direction, ip_len);
        return;
    }

    // 解析IPv4头
    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    uint8_t ihl = ip_data[0] & 0x0F;
    uint16_t total_length = (ip_data[2] << 8) | ip_data[3];
    uint8_t protocol = ip_data[9];

    // 源/目的IP
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    std::memcpy(&src_addr, ip_data + 12, 4);
    std::memcpy(&dst_addr, ip_data + 16, 4);
    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    const char *proto_name = "UNKNOWN";
    switch (protocol) {
        case 1:  proto_name = "ICMP"; break;
        case 6:  proto_name = "TCP"; break;
        case 17: proto_name = "UDP"; break;
        case 47: proto_name = "GRE"; break;
        case 50: proto_name = "ESP"; break;
        case 51: proto_name = "AH"; break;
        default: break;
    }

    printf("[ROHC-DBG] %s: IPv%d IHL=%d TotalLen=%u Proto=%s(%d) Src=%s Dst=%s\n",
           direction, version, ihl, total_length, proto_name, protocol, src_ip, dst_ip);

    // 如果是UDP/TCP, 打印端口号
    if ((protocol == 6 || protocol == 17) && ip_len >= (size_t)(ihl * 4 + 4)) {
        uint16_t src_port = (ip_data[ihl * 4] << 8) | ip_data[ihl * 4 + 1];
        uint16_t dst_port = (ip_data[ihl * 4 + 2] << 8) | ip_data[ihl * 4 + 3];
        printf("[ROHC-DBG] %s: %s port %u -> %u\n",
               direction, proto_name, src_port, dst_port);
    }
#else
    (void)ip_data;
    (void)ip_len;
    (void)direction;
#endif
}

void PPPoEPacketHandler::rohc_print_compress_detail(size_t orig_len, size_t comp_len, uint16_t session_id) const
{
#if ROHC_DEBUG_PRINT
    double ratio = orig_len > 0 ? (100.0 * comp_len / orig_len) : 0.0;
    double saving = orig_len > comp_len ? (100.0 * (orig_len - comp_len) / orig_len) : 0.0;

    printf("[ROHC-DBG] COMPRESS session[%u]: orig=%zu comp=%zu ratio=%.1f%% saving=%.1f%% (%s)\n",
           session_id, orig_len, comp_len, ratio, saving,
           comp_len < orig_len ? "COMPRESSED" :
           comp_len == orig_len ? "NO_CHANGE" : "EXPANDED(IR)");
#else
    (void)orig_len;
    (void)comp_len;
    (void)session_id;
#endif
}

void PPPoEPacketHandler::rohc_print_decompress_detail(size_t comp_len, size_t decomp_len, uint16_t session_id) const
{
#if ROHC_DEBUG_PRINT
    double expansion = comp_len > 0 ? (100.0 * decomp_len / comp_len) : 0.0;

    printf("[ROHC-DBG] DECOMPRESS session[%u]: comp=%zu decomp=%zu expansion=%.1f%% (recovered %zu bytes)\n",
           session_id, comp_len, decomp_len, expansion, decomp_len - comp_len);
#else
    (void)comp_len;
    (void)decomp_len;
    (void)session_id;
#endif
}

void PPPoEPacketHandler::rohc_dump_packet(const uint8_t *data, size_t len, const char *prefix, size_t max_bytes) const
{
#if ROHC_DEBUG_PRINT
    if (!data || len == 0) {
        printf("[ROHC-DBG] %s: (empty)\n", prefix);
        return;
    }

    size_t dump_len = (max_bytes > 0 && len > max_bytes) ? max_bytes : len;
    printf("[ROHC-DBG] %s (%zu/%zu bytes): ", prefix, dump_len, len);
    for (size_t i = 0; i < dump_len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < dump_len) {
            printf("\n[ROHC-DBG]   ");
        }
    }
    printf("\n");
#else
    (void)data;
    (void)len;
    (void)prefix;
    (void)max_bytes;
#endif
}

void PPPoEPacketHandler::rohc_print_stats(uint16_t session_id) const
{
#if ROHC_DEBUG_PRINT
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::GATEWAY);
    uint64_t comp_packets = 0, decomp_packets = 0;
    uint64_t comp_failures = 0, decomp_failures = 0;
    rohc.get_stats(session_id, comp_packets, decomp_packets, comp_failures, decomp_failures);

    auto* session = session_mgr_.get_session(session_id);

    printf("[ROHC-STATS] ==================== Gateway ROHC Stats ====================\n");
    printf("[ROHC-STATS] Channel: session_id=%u, role=GATEWAY, enabled=%s\n",
           session_id, (session && session->rohc_enabled) ? "YES" : "NO");
    printf("[ROHC-STATS] Compress:   packets=%llu  failures=%llu\n",
           (unsigned long long)comp_packets, (unsigned long long)comp_failures);
    printf("[ROHC-STATS] Decompress: packets=%llu  failures=%llu\n",
           (unsigned long long)decomp_packets, (unsigned long long)decomp_failures);
    printf("[ROHC-STATS] =============================================================\n");
#else
    (void)session_id;
#endif
}

void PPPoEPacketHandler::rohc_print_all_stats() const
{
#if ROHC_DEBUG_PRINT
    rohc_print_flow("[ROHC-FLOW] === All Sessions ROHC Stats ===");
    for (uint16_t i = 0; i < PPPOE_COUNT; ++i) {
        auto* session = session_mgr_.get_session(i);
        if (session && session->rohc_enabled) {
            rohc_print_stats(i);
        }
    }
#endif
}
