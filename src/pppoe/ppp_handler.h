#ifndef PPP_HANDLER_H
#define PPP_HANDLER_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <sys/time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>

#include "ppp_queue.h"
#include "rohc_wrapper.h"

// 常量定义
#define ETHER_TYPE_DISCOVERY 0x8863
#define ETHER_TYPE_PPP_SESSION 0x8864
#define IP 0x0021

#define CODE_OF_PADI 0x09
#define CODE_OF_PADO 0x07
#define CODE_OF_PADR 0x19
#define CODE_OF_PADS 0x65
#define CODE_OF_PADT 0xa7

#define LCP 0xc021
#define CHAP 0xc223
#define PAP 0xc023
#define IPCP 0x8021

#define PTS_PATH "/dev/net/tun"
#define IFNAMSIZ 16

#define PMLLOG_ERROR 0
#define PMLLOG_WARNING 1
#define PMLLOG_INFO 2

// ==================== ROHC 集成常量 ====================

/// PPPoE帧中IP包的偏移量(以太网头14 + PPPoE头6 + PPP协议字段2 = 22)
#define PPPOE_IP_PAYLOAD_OFFSET 22

/// ROHC工作缓冲区大小(需要容纳完整PPPoE帧+解压后的IP数据)
#define ROHC_WORK_BUF_SIZE 2048

/// ROHC调试打印开关(1=开启, 0=关闭)
#define ROHC_DEBUG_PRINT 1

// LCP包结构
struct LCP_packet
{
    uint8_t Code;
    // 其他字段...
};

// 流量管理器回调接口
class TrafficManager
{
public:
    virtual ~TrafficManager() {}
    virtual int ppp_send(uint8_t index, const char *buff, int length) = 0;
};

// 日志函数
void PML_log(int level, const char *format, ...);
void PML_mem_log(int level, const unsigned char *data, int length);

class PPPHandler
{
private:
    // PPP 状态管理
    int ppp_state;          // PPP 连接状态
    int ppp_on;             // PPP 开启标志
    int termtime;           // 终止时间
    int allip_count;        // IP 计数

    // 错误处理
    int echo_failure_times;
    uint8_t m_uc_error_reason;

    // 文件和线程管理
    int fd_slave;
    PPPQueue ppp_queue_obj;
    sem_t m_sig_send_return_link_ppp;
    // pthread_t thread_read_ppp;
    // pthread_t thread_send_ppp;
    bool running;

    // 流量管理器指针
    TrafficManager *p_rcst_traffic_mgr;
    uint8_t g_uc_rc_index_af;
    uint8_t g_uc_rc_index_be;

    // ==================== ROHC 相关成员 ====================

    /// ROHC是否已启用(PPPoE会话ESTABLISHED后启用)
    bool rohc_enabled_;

    /// ROHC通道会话ID(终端侧固定为0)
    uint16_t rohc_session_id_;

    /// ROHC工作缓冲区(用于压缩/解压缩时的数据拷贝)
    uint8_t rohc_work_buf_[ROHC_WORK_BUF_SIZE];

    /// ROHC压缩统计: 总原始字节数
    uint64_t rohc_comp_total_orig_bytes_;

    /// ROHC压缩统计: 总压缩后字节数
    uint64_t rohc_comp_total_comp_bytes_;

    /// ROHC解压统计: 总压缩包字节数
    uint64_t rohc_decomp_total_comp_bytes_;

    /// ROHC解压统计: 总解压后字节数
    uint64_t rohc_decomp_total_decomp_bytes_;

    // 内部辅助函数 - 初始化
    void init_pty();

    // 内部辅助函数 - 线程处理
    void thread_run_read_ppp();
    void thread_run_send_ppp();
    static void* thread_read_ppp_wrapper(void *arg);
    static void* thread_send_ppp_wrapper(void *arg);

    // 内部辅助函数 - 读取PPP数据处理
    void process_discovery_packet_read(const ppp_frame_for_PPPoE *PPPoE_buff);
    void process_ppp_session_packet_read(const ppp_frame_for_PPPoE *PPPoE_buff, int length);
    void process_lcp_packet_read(const LCP_packet *lcp_packet);
    void handle_lcp_terminate_request_read();
    void notify_ppp_error_read();
    void handle_chap_packet_read(const LCP_packet *lcp_packet);
    void handle_pap_packet_read(const LCP_packet *lcp_packet);
    void handle_ipcp_packet_read(const LCP_packet *lcp_packet);

    // 内部辅助函数 - 写入PPP数据处理
    int process_write_discovery_packet(const ppp_frame_for_PPPoE *buff);
    int process_write_ppp_session_packet(const ppp_frame_for_PPPoE *buff, const LCP_packet *lcp_packet);
    int process_write_lcp_packet(const LCP_packet *lcp_packet);
    int process_write_chap_packet(const LCP_packet *lcp_packet);
    int process_write_pap_packet(const LCP_packet *lcp_packet);
    int process_write_ipcp_packet(const LCP_packet *lcp_packet);
    int process_write_ip_packet();
    void handle_write_lcp_echo_request();
    void handle_write_lcp_echo_reply();
    void handle_write_lcp_terminate_req();
    void handle_write_lcp_terminate_ack();
    void handle_write_lcp_config_request();
    void handle_write_lcp_config_ack();

    // 发送PPP数据处理
    int sendPPP(const ppp_frame_for_PPPoE *PPPoE_buff, int length);
    uint16_t get_protocol_field(const ppp_frame_for_PPPoE *PPPoE_buff);
    bool is_icmp_packet(const ppp_frame_for_PPPoE *PPPoE_buff, int length);

    // ==================== ROHC 内部辅助方法 ====================

    /**
     * @brief 初始化ROHC通道(PPPoE会话ESTABLISHED时调用)
     * @return 0成功, -1失败
     */
    int rohc_init_channel();

    /**
     * @brief 销毁ROHC通道(会话终止时调用)
     */
    void rohc_destroy_channel();

    /**
     * @brief 对PPPoE帧中的IP包执行ROHC压缩(终端发送方向)
     *
     * 在PPPoE帧缓冲区中定位IP包,调用RohcWrapper压缩,
     * 更新PPPoE长度字段,返回新的帧长度.
     * 如果不是IP包或压缩失败,返回原始帧长度.
     *
     * @param frame_data PPPoE帧数据(可修改)
     * @param frame_len 原始帧长度
     * @return 新的帧长度(压缩后), 或原始长度(非IP/失败)
     */
    uint16_t rohc_compress_frame(uint8_t *frame_data, uint16_t frame_len);

    /**
     * @brief 对PPPoE帧中的ROHC压缩包执行解压(终端接收方向)
     *
     * 在PPPoE帧缓冲区中定位压缩数据,调用RohcWrapper解压,
     * 更新PPPoE长度字段,返回新的帧长度.
     * 如果不是IP包或解压失败,返回原始帧长度.
     *
     * @param frame_data PPPoE帧数据(可修改,需有足够空间容纳解压后数据)
     * @param frame_len 原始帧长度
     * @param max_frame_len 缓冲区最大容量
     * @return 新的帧长度(解压后), 或原始长度(非IP/失败)
     */
    uint16_t rohc_decompress_frame(uint8_t *frame_data, uint16_t frame_len, uint16_t max_frame_len);

    /**
     * @brief 判断PPPoE帧是否为IP数据包
     * @param frame_data 帧数据
     * @param frame_len 帧长度
     * @return true=IP包, false=非IP包
     */
    bool is_ip_frame(const uint8_t *frame_data, uint16_t frame_len) const;

public:
    PPPHandler();
    ~PPPHandler();

    // 公共接口
    int initialize();
    void shutdown();
    int write_ppp(const unsigned char *psz_buff, const uint16_t us_length);
    void handle_pon();
    void handle_poff();
    void print_with_timestamp(const char *message);

    // 设置流量管理器
    void set_traffic_manager(TrafficManager *mgr) { p_rcst_traffic_mgr = mgr; }
    void set_rc_index_af(uint8_t index) { g_uc_rc_index_af = index; }
    void set_rc_index_be(uint8_t index) { g_uc_rc_index_be = index; }

    // Getter 方法 - 状态查询
    int get_ppp_state() const { return ppp_state; }
    int get_ppp_on() const { return ppp_on; }
    int get_termtime() const { return termtime; }
    int get_allip_count() const { return allip_count; }
    int get_echo_failure_times() const { return echo_failure_times; }

    // Setter 方法 - 状态设置
    void set_ppp_state(int state) { ppp_state = state; }
    void set_ppp_on(int on) { ppp_on = on; }
    void set_termtime(int time) { termtime = time; }
    void set_allip_count(int count) { allip_count = count; }
    void set_echo_failure_times(int times) { echo_failure_times = times; }

    // 专用操作方法
    void increment_allip_count() { allip_count++; }
    void decrement_allip_count() { if (allip_count > 0) allip_count--; }
    void increment_echo_failure_times() { echo_failure_times++; }
    void reset_echo_failure_times() { echo_failure_times = 0; }

    // ==================== ROHC 公共调试接口 ====================

    /**
     * @brief 打印ROHC通道统计信息
     * 包含压缩/解压包数、失败数、压缩率等
     */
    void rohc_print_stats();

    /**
     * @brief 打印IP包头详细信息(调试用)
     * @param ip_data IP包数据(含IP头)
     * @param ip_len IP包长度
     * @param direction 方向描述("COMP-OUT"/"DECOMP-IN"等)
     */
    void rohc_print_ip_header(const uint8_t *ip_data, size_t ip_len, const char *direction);

    /**
     * @brief 打印压缩过程详细信息
     * @param orig_len 原始IP包长度
     * @param comp_len 压缩后长度
     * @param session_id 会话ID
     */
    void rohc_print_compress_detail(size_t orig_len, size_t comp_len, uint16_t session_id);

    /**
     * @brief 打印解压过程详细信息
     * @param comp_len 压缩包长度
     * @param decomp_len 解压后长度
     * @param session_id 会话ID
     */
    void rohc_print_decompress_detail(size_t comp_len, size_t decomp_len, uint16_t session_id);

    /**
     * @brief 十六进制转储数据包(深度调试用)
     * @param data 数据指针
     * @param len 数据长度
     * @param prefix 前缀描述
     * @param max_bytes 最多打印字节数(0=全部)
     */
    void rohc_dump_packet(const uint8_t *data, size_t len, const char *prefix, size_t max_bytes = 64);

    /**
     * @brief 打印ROHC流程步骤(带时间戳)
     * @param step 流程步骤描述
     */
    void rohc_print_flow(const char *step);

    /**
     * @brief 重置ROHC统计计数器
     */
    void rohc_reset_stats();

    /**
     * @brief 查询ROHC是否已启用
     * @return true=已启用, false=未启用
     */
    bool is_rohc_enabled() const { return rohc_enabled_; }
};

#endif // PPP_HANDLER_H
