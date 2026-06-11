#include "ppp_handler.h"
#include <cstdarg>
#include <cstdlib>
#include <sys/wait.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// 简单的日志实现
void PML_log(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void PML_mem_log(int level, const unsigned char *data, int length)
{
    for (int i = 0; i < length && i < 256; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// ====================== 构造函数和析构函数 ======================

PPPHandler::PPPHandler()
    : ppp_state(0),
      ppp_on(0),
      termtime(0),
      allip_count(0),
      echo_failure_times(0),
      m_uc_error_reason(0),
      fd_slave(-1),
      running(false),
    //   thread_read_ppp(0),
    //   thread_send_ppp(0),
      p_rcst_traffic_mgr(NULL),
      g_uc_rc_index_af(0),
      g_uc_rc_index_be(0),
      rohc_enabled_(false),
      rohc_session_id_(0),
      rohc_comp_total_orig_bytes_(0),
      rohc_comp_total_comp_bytes_(0),
      rohc_decomp_total_comp_bytes_(0),
      rohc_decomp_total_decomp_bytes_(0)
{
    sem_init(&m_sig_send_return_link_ppp, 0, 0);
    std::memset(rohc_work_buf_, 0, sizeof(rohc_work_buf_));
}

PPPHandler::~PPPHandler()
{
    shutdown();
    rohc_destroy_channel();
    sem_destroy(&m_sig_send_return_link_ppp);
}

// ====================== 公共接口 ======================

int PPPHandler::initialize()
{
    init_pty();
    running = true;

    // 创建读线程
    int ret = pthread_create(&thread_read_ppp, NULL, thread_read_ppp_wrapper, this);
    if (ret != 0)
    {
        PML_log(PMLLOG_ERROR, "Failed to create read thread");
        running = false;
        return -1;
    }

    // 创建发送线程
    ret = pthread_create(&thread_send_ppp, NULL, thread_send_ppp_wrapper, this);
    if (ret != 0)
    {
        PML_log(PMLLOG_ERROR, "Failed to create send thread");
        running = false;
        return -1;
    }

    return 0;
}

void PPPHandler::shutdown()
{
    running = false;

    if (fd_slave != -1)
    {
        close(fd_slave);
        fd_slave = -1;
    }

    // 会话关闭时销毁ROHC通道
    rohc_destroy_channel();
}

void PPPHandler::print_with_timestamp(const char *message)
{
    time_t now;
    struct tm *timeinfo;
    char time_str[20];

    time(&now);
    timeinfo = localtime(&now);

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("[%s] %s\n", time_str, message);
}

// ====================== 初始化和线程管理 ======================

void PPPHandler::init_pty()
{
    const char *pts_path_slave = PTS_PATH;
    fd_slave = open(pts_path_slave, O_RDWR);
    if (fd_slave == -1)
    {
        perror("open");
        return;
    }
    printf("open fd_slave=%d\n", fd_slave);

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "tap0", IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (ioctl(fd_slave, TUNSETIFF, (void *)&ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
    }
}

void* PPPHandler::thread_read_ppp_wrapper(void *arg)
{
    PPPHandler *this_ptr = static_cast<PPPHandler *>(arg);
    this_ptr->thread_run_read_ppp();
    return NULL;
}

void* PPPHandler::thread_send_ppp_wrapper(void *arg)
{
    PPPHandler *this_ptr = static_cast<PPPHandler *>(arg);
    this_ptr->thread_run_send_ppp();
    return NULL;
}

// ====================== 读取PPP数据处理 ======================
void PPPHandler::thread_run_read_ppp() {
        uint16_t max_data_length = 0;
        char * af_dst = NULL;
        char * be_dst = NULL;
        uint16_t length = 0;
        uint8_t uc_ret = 1;

        SatRcstSchedulerQueues * p_queues = SatRcstSchedulerQueues::instance();
        if (NULL == p_queues) {
                return;
        }

        while (running) {
                be_dst = p_queues -> get_data_buffer_addr(g_uc_rc_index_be, max_data_length);
                if (NULL == be_dst) {
                        PML_log(PMLLOG_ERROR, "be_dst null, wait for queue release.");
                        usleep(g_u1_superframe_duration);
                        continue;
                }
                ssize_t bytes_read = read(fd_slave, be_dst, MAX_PPP_DATA_LEN);

                if (-1 == bytes_read) {
                        PML_log(PMLLOG_ERROR, "thread run_read_ppp read error!");
                        break;
                }

                length = bytes_read;
                ppp_frame_for_PPPoE * PPPoE_buff = (ppp_frame_for_PPPoE *)(be_dst);

                uint16_t us_ether_type = ntohs(PPPoE_buff -> ETHER_TYPE);
                if (ETHER_TYPE_DISCOVERY == us_ether_type) {
                        process_discovery_packet_read(PPPoE_buff);
                } else if (ETHER_TYPE_PPP_SESSION == us_ether_type) {
                        process_ppp_session_packet_read(PPPoE_buff, length);
                } else {
                        continue;
                }

                // [ROHC集成] 终端发送方向: 对IP包执行ROHC压缩后再入队列
                // 仅在PPPoE会话ESTABLISHED且ROHC通道已创建时压缩
                if (rohc_enabled_ && (PPPoE_buff->Protocol_Field == htons(IP))) {
                        rohc_print_flow("[ROHC-FLOW] Terminal TX: applying ROHC compression before satellite TX");

                        // 打印压缩前的IP包头
                        uint8_t *ip_ptr = (uint8_t *)be_dst + PPPOE_IP_PAYLOAD_OFFSET;
                        size_t ip_len = length - PPPOE_IP_PAYLOAD_OFFSET;
                        if (ip_len > 0 && length > PPPOE_IP_PAYLOAD_OFFSET) {
                                rohc_print_ip_header(ip_ptr, ip_len, "COMP-BEFORE(Original IP)");
                        }

                        uint16_t new_len = rohc_compress_frame((uint8_t *)be_dst, length);
                        if (new_len != length) {
                                rohc_print_compress_detail(ip_len, new_len - PPPOE_IP_PAYLOAD_OFFSET, rohc_session_id_);
                                length = new_len;

                                // 打印压缩后的数据摘要
                                uint8_t *comp_ptr = (uint8_t *)be_dst + PPPOE_IP_PAYLOAD_OFFSET;
                                size_t comp_len = length - PPPOE_IP_PAYLOAD_OFFSET;
                                rohc_dump_packet(comp_ptr, comp_len, "COMP-AFTER(ROHC compressed)", 32);
                        } else {
                                rohc_print_flow("[ROHC-FLOW] Terminal TX: compression skipped or failed, sending original");
                        }
                }

                if ((PPPoE_buff->Protocol_Field == htons(IP)) && (!is_icmp_packet(PPPoE_buff, length))) {
                        uc_ret = p_queues -> add_data(g_uc_rc_index_be, length);
                } else {
                        af_dst = p_queues -> get_data_buffer_addr(g_uc_rc_index_af, max_data_length);
                        if (NULL != af_dst) {
                                memcpy(af_dst, PPPoE_buff, length);
                        }
                        uc_ret = p_queues -> add_data(g_uc_rc_index_af, length);
                }
        }
}

void PPPHandler::process_discovery_packet_read(const ppp_frame_for_PPPoE *PPPoE_buff)
{
    if (PPPoE_buff->pppoe_code == CODE_OF_PADI)
    {
        struct timeval time_;
        gettimeofday(&time_, NULL);
        static long int time_temp = 0;
        long int time_ms1 = time_.tv_sec * 1000 + time_.tv_usec / 1000;
        if (time_temp != 0 && time_ms1 - time_temp < 10000)
        {
            return;
        }
        time_temp = time_ms1;
        PML_log(PMLLOG_WARNING, "send PADI");
    }
    else if (PPPoE_buff->pppoe_code == CODE_OF_PADR)
    {
        struct timeval time_;
        gettimeofday(&time_, NULL);
        static long int time_temp1 = 0;
        long int time_ms2 = time_.tv_sec * 1000 + time_.tv_usec / 1000;
        if (time_temp1 != 0 && time_ms2 - time_temp1 < 10000)
        {
            return;
        }
        time_temp1 = time_ms2;
        PML_log(PMLLOG_WARNING, "send PADR");
    }
    else if (PPPoE_buff->pppoe_code == CODE_OF_PADT)
    {
        PML_log(PMLLOG_WARNING, "send PADT");
        ppp_state = 0;

        // [ROHC集成] PADT断开时销毁ROHC通道
        rohc_destroy_channel();
    }
}

void PPPHandler::process_ppp_session_packet_read(const ppp_frame_for_PPPoE *PPPoE_buff, int length)
{
    uint16_t proto_field = (PPPoE_buff->Protocol_Field[0] << 8) | PPPoE_buff->Protocol_Field[1];
    LCP_packet *lcp_packet = (LCP_packet *)PPPoE_buff->PPP;

    if (proto_field == LCP)
    {
        process_lcp_packet_read(lcp_packet);
    }
    else if (proto_field == CHAP)
    {
        handle_chap_packet_read(lcp_packet);
    }
    else if (proto_field == PAP)
    {
        handle_pap_packet_read(lcp_packet);
    }
    else if (proto_field == IPCP)
    {
        handle_ipcp_packet_read(lcp_packet);
    }
}

void PPPHandler::process_lcp_packet_read(const LCP_packet *lcp_packet)
{
    switch (lcp_packet->Code)
    {
        case 0x01:
            PML_log(PMLLOG_WARNING, "send LCP config (CHAP)request to NCC");
            break;
        case 0x02:
            PML_log(PMLLOG_WARNING, "send LCP configure ACK(CHAP) to NCC");
            break;
        case 0x03:
            PML_log(PMLLOG_WARNING, "send LCP reject to NCC");
            break;
        case 0x09:
            PML_log(PMLLOG_WARNING, "send echo req to NCC");
            break;
        case 0x0a:
            PML_log(PMLLOG_WARNING, "send LCP echo reply to NCC");
            echo_failure_times = 0;
            break;
        case 0x05:
            PML_log(PMLLOG_WARNING, "send LCP terminate req to NCC");
            handle_lcp_terminate_request_read();
            break;
        case 0x06:
            PML_log(PMLLOG_WARNING, "send LCP terminate ack to NCC");
            break;
        default:
            PML_log(PMLLOG_WARNING, "other LCP type from PPP:0x%2x", lcp_packet->Code);
            break;
    }
}

void PPPHandler::handle_lcp_terminate_request_read()
{
    // [ROHC集成] LCP Terminate时销毁ROHC通道
    rohc_destroy_channel();

    if (ppp_state != 5)
    {
        if (ppp_state == 3)
        {
            m_uc_error_reason = 0;
        }
        else if (ppp_state == 4)
        {
            m_uc_error_reason = 1;
        }
        notify_ppp_error_read();
    }
    else if (ppp_state == 5)
    {
        if (echo_failure_times >= 3)
        {
            m_uc_error_reason = 2;
        }
        notify_ppp_error_read();
        ppp_state = 0;
    }
}

void PPPHandler::notify_ppp_error_read()
{
    PML_log(PMLLOG_WARNING, "PPP error notified, state=%d, reason=%d", ppp_state, m_uc_error_reason);
}

void PPPHandler::handle_chap_packet_read(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv chap! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x03)
    {
        ppp_state = 4;
    }
    else if (lcp_packet->Code == 0x04)
    {
        PML_log(PMLLOG_WARNING, "CHAP failed!!");
    }
}

void PPPHandler::handle_pap_packet_read(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv PAP! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x02)
    {
        PML_log(PMLLOG_WARNING, "PPP recv pap ack");
    }
}

void PPPHandler::handle_ipcp_packet_read(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv IPCP! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x02)
    {
        ppp_state = 5;
        PML_log(PMLLOG_WARNING, "IP allocate to me!");

        // [ROHC集成] IPCP ACK表示IP地址分配成功,PPPoE会话进入ESTABLISHED状态
        // 此时创建ROHC通道,后续IP数据包将进行头部压缩/解压
        rohc_init_channel();
    }
}

// ====================== 发送PPP数据处理 ======================

uint16_t PPPHandler::get_protocol_field(const ppp_frame_for_PPPoE *PPPoE_buff)
{
    return (PPPoE_buff->Protocol_Field[0] << 8) | PPPoE_buff->Protocol_Field[1];
}

bool PPPHandler::is_icmp_packet(const ppp_frame_for_PPPoE *PPPoE_buff, int length)
{
    // 检查长度是否足够（以太网头+IP头最少20字节+ICMP头8字节）
    if ((length >= 32) && (PPPoE_buff->pppoe_length >= 12))
    {
        uint8_t uc_ip_protocol = PPPoE_buff->PPP[9];
        if (1 == uc_ip_protocol)  // ICMP协议号为1
        {
            return true;
        }
    }
    return false;
}

// ====================== 写入PPP数据处理 ======================

int PPPHandler::process_write_discovery_packet(const ppp_frame_for_PPPoE *buff)
{
    if (buff->pppoe_code == CODE_OF_PADO)
    {
        PML_log(PMLLOG_WARNING, "recv PADO");
        ppp_state = 2;
        return 1;
    }
    else if (buff->pppoe_code == CODE_OF_PADS)
    {
        PML_log(PMLLOG_WARNING, "recv PADS");
        ppp_state = 3;
        return 1;
    }
    else if (buff->pppoe_code == CODE_OF_PADT)
    {
        PML_log(PMLLOG_WARNING, "recv PADT");
        handle_poff();

        // [ROHC集成] 收到PADT断开时销毁ROHC通道
        rohc_destroy_channel();

        return 0;
    }
    else
    {
        PML_log(PMLLOG_WARNING, "recv ETHER_TYPE_DISCOVERY unknown message type! buff->pppoe_code = 0x%02hhx", buff->pppoe_code);
        return 1;
    }
}

void PPPHandler::handle_write_lcp_echo_request()
{
    PML_log(PMLLOG_WARNING, "write LCP echo req");
    echo_failure_times++;
}

void PPPHandler::handle_write_lcp_echo_reply()
{
    PML_log(PMLLOG_WARNING, "write LCP echo reply");
}

void PPPHandler::handle_write_lcp_terminate_req()
{
    PML_log(PMLLOG_WARNING, "write LCP terminate req");

    // [ROHC集成] LCP Terminate时销毁ROHC通道
    rohc_destroy_channel();

    if (ppp_state != 5)
    {
        if (ppp_state == 3)
        {
            m_uc_error_reason = 0;
        }
        else if (ppp_state == 4)
        {
            m_uc_error_reason = 1;
        }
        notify_ppp_error_read();
    }
    else
    {
        if (echo_failure_times >= 3)
        {
            m_uc_error_reason = 2;
            notify_ppp_error_read();
            ppp_state = 0;
        }
    }
}

void PPPHandler::handle_write_lcp_terminate_ack()
{
    PML_log(PMLLOG_WARNING, "write LCP terminate ack");
}

void PPPHandler::handle_write_lcp_config_request()
{
    PML_log(PMLLOG_WARNING, "write LCP req");
}

void PPPHandler::handle_write_lcp_config_ack()
{
    PML_log(PMLLOG_WARNING, "write LCP ack");
}

int PPPHandler::process_write_lcp_packet(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv LCP! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    
    switch (lcp_packet->Code)
    {
        case 0x09:
            handle_write_lcp_echo_request();
            break;
        case 0x0a:
            handle_write_lcp_echo_reply();
            break;
        case 0x05:
            handle_write_lcp_terminate_req();
            break;
        case 0x06:
            handle_write_lcp_terminate_ack();
            break;
        case 0x01:
            handle_write_lcp_config_request();
            break;
        case 0x02:
            handle_write_lcp_config_ack();
            break;
        default:
            break;
    }
    return 1;
}

int PPPHandler::process_write_chap_packet(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv chap! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x03)
    {
        ppp_state = 4;
    }
    else if (lcp_packet->Code == 0x04)
    {
        PML_log(PMLLOG_WARNING, "CHAP failed!!");
    }
    return 1;
}

int PPPHandler::process_write_pap_packet(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv PAP! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x02)
    {
        PML_log(PMLLOG_WARNING, "PPP recv pap ack");
    }
    return 1;
}

int PPPHandler::process_write_ipcp_packet(const LCP_packet *lcp_packet)
{
    PML_log(PMLLOG_WARNING, "PPP recv IPCP! lcp_packet->Code = 0x%02hhx", lcp_packet->Code);
    if (lcp_packet->Code == 0x02)
    {
        ppp_state = 5;
        PML_log(PMLLOG_WARNING, "IP allocate to me!");

        // [ROHC集成] IPCP ACK - 创建ROHC通道
        rohc_init_channel();
    }
    else if (lcp_packet->Code == 0x01)
    {
        PML_log(PMLLOG_WARNING, "send IPCP REQ to NCC");
    }
    else if (lcp_packet->Code == 0x09)
    {
        PML_log(PMLLOG_WARNING, "send IPCP link to NCC");
    }
    return 1;
}

int PPPHandler::process_write_ip_packet()
{
    // IP数据包处理 - 该分支在原代码中为空
    return 1;
}

int PPPHandler::process_write_ppp_session_packet(const ppp_frame_for_PPPoE *buff, const LCP_packet *lcp_packet)
{
    uint16_t proto_field = (buff->Protocol_Field[0] << 8) | buff->Protocol_Field[1];

    if (proto_field == LCP)
    {
        return process_write_lcp_packet(lcp_packet);
    }
    else if (proto_field == CHAP)
    {
        return process_write_chap_packet(lcp_packet);
    }
    else if (proto_field == PAP)
    {
        return process_write_pap_packet(lcp_packet);
    }
    else if (proto_field == IPCP)
    {
        return process_write_ipcp_packet(lcp_packet);
    }
    else if (proto_field == IP)
    {
        return process_write_ip_packet();
    }
    else
    {
        PML_log(PMLLOG_WARNING, "recv unknown message type! buff->Protocol_Field = 0x%04hx", proto_field);
        return 0;
    }
}

int PPPHandler::write_ppp(const unsigned char *psz_buff, const uint16_t us_length)
{
    PML_log(PMLLOG_INFO, "recv from ncc:");
    PML_mem_log(PMLLOG_INFO, psz_buff, us_length);

    // [ROHC集成] 终端接收方向: 需要先拷贝到工作缓冲区,因为psz_buff是const
    // 对IP包执行ROHC解压后再写入TAP设备
    uint16_t final_length = us_length;
    bool need_decompress = false;

    // 检查是否为IP包且ROHC已启用
    if (rohc_enabled_ && is_ip_frame(psz_buff, us_length)) {
        need_decompress = true;

        // 拷贝到工作缓冲区
        if (us_length > ROHC_WORK_BUF_SIZE) {
            PML_log(PMLLOG_ERROR, "[ROHC] Work buffer too small: need=%u, have=%d",
                    us_length, ROHC_WORK_BUF_SIZE);
            need_decompress = false;
        } else {
            std::memcpy(rohc_work_buf_, psz_buff, us_length);

            rohc_print_flow("[ROHC-FLOW] Terminal RX: applying ROHC decompression after satellite RX");

            // 打印解压前的数据摘要
            uint8_t *comp_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
            size_t comp_len = us_length - PPPOE_IP_PAYLOAD_OFFSET;
            rohc_dump_packet(comp_ptr, comp_len, "DECOMP-BEFORE(ROHC compressed)", 32);

            // 执行解压
            uint16_t new_len = rohc_decompress_frame(rohc_work_buf_, us_length, ROHC_WORK_BUF_SIZE);
            if (new_len != us_length) {
                size_t decomp_ip_len = new_len - PPPOE_IP_PAYLOAD_OFFSET;
                rohc_print_decompress_detail(comp_len, decomp_ip_len, rohc_session_id_);

                // 打印解压后的IP包头
                uint8_t *ip_ptr = rohc_work_buf_ + PPPOE_IP_PAYLOAD_OFFSET;
                rohc_print_ip_header(ip_ptr, decomp_ip_len, "DECOMP-AFTER(Original IP)");

                final_length = new_len;
            } else {
                rohc_print_flow("[ROHC-FLOW] Terminal RX: decompression skipped or failed, using original");
            }
        }
    }

    const ppp_frame_for_PPPoE *buff;
    const LCP_packet *lcp_packet;

    if (need_decompress) {
        // 使用解压后的工作缓冲区
        buff = (const ppp_frame_for_PPPoE *)(rohc_work_buf_);
        lcp_packet = (const LCP_packet *)buff->PPP;
    } else {
        // 使用原始缓冲区
        buff = (const ppp_frame_for_PPPoE *)(psz_buff);
        lcp_packet = (const LCP_packet *)buff->PPP;
    }

    uint16_t ether_type = (buff->ETHER_TYPE[0] << 8) | buff->ETHER_TYPE[1];

    // 处理以太网类型
    int process_result = 1;
    
    if (ether_type == ETHER_TYPE_DISCOVERY)
    {
        process_result = process_write_discovery_packet(buff);
    }
    else if (ether_type == ETHER_TYPE_PPP_SESSION)
    {
        process_result = process_write_ppp_session_packet(buff, lcp_packet);
    }
    else
    {
        PML_log(PMLLOG_WARNING, "recv unknown ETHER_TYPE = 0x%04hx", ether_type);
        process_result = 0;
    }

    // 如果处理失败，直接返回
    if (process_result == 0)
    {
        return 0;
    }

    // 写入数据 - 根据是否解压选择数据源
    ssize_t bytes_written;
    if (need_decompress) {
        bytes_written = write(fd_slave, rohc_work_buf_, final_length);
    } else {
        bytes_written = write(fd_slave, psz_buff, us_length);
    }

    if (bytes_written == -1)
    {
        return 0;
    }
    return 1;
}

// ====================== PON/POFF 处理 ======================

void PPPHandler::handle_pon()
{
    int pon_state = system("pon dsl-provider");
    if (pon_state == -1)
    {
        PML_log(PMLLOG_ERROR, "pon error!");
    }
    else
    {
        if (WIFEXITED(pon_state))
        {
            if (WEXITSTATUS(pon_state) == 0)
            {
                PML_log(PMLLOG_INFO, "pon success!");
            }
            else
            {
                PML_log(PMLLOG_ERROR, "pon fail!");
            }
        }
        else
        {
            PML_log(PMLLOG_ERROR, "pon exit =%d!", WEXITSTATUS(pon_state));
        }
    }
}

void PPPHandler::handle_poff()
{
    FILE *fp = popen("pidof /usr/sbin/pppd call dsl-provider", "r");
    if (!fp)
    {
        PML_log(PMLLOG_ERROR, "pidof error!");
        return;
    }

    pid_t pid = -1;
    fscanf(fp, "%d", &pid);
    pclose(fp);

    if (pid > 0)
    {
        int poff_state = kill(pid, SIGKILL);
        if (poff_state == 0)
        {
            PML_log(PMLLOG_INFO, "poff kill success!");
            printf("poff kill success\n");
        }
        else
        {
            PML_log(PMLLOG_ERROR, "poff kill error!");
        }
    }
    else
    {
        printf("ppp进程未在运行!\n");
    }

    // [ROHC集成] poff断开时销毁ROHC通道
    rohc_destroy_channel();
}

// ====================== ROHC 通道管理 ======================

int PPPHandler::rohc_init_channel()
{
    if (rohc_enabled_) {
        RohcLog(RohcLogLevel::INFO, "[Terminal] ROHC channel already initialized for session %u",
                rohc_session_id_);
        return 0;
    }

    // 终端侧使用TERMINAL角色, session_id固定为0
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);

    int ret = rohc.create_channel(rohc_session_id_);
    if (ret != 0) {
        RohcLog(RohcLogLevel::ERROR, "[Terminal] Failed to create ROHC channel for session %u",
                rohc_session_id_);
        rohc_enabled_ = false;
        return -1;
    }

    rohc_enabled_ = true;
    rohc_reset_stats();

    rohc_print_flow("[ROHC-FLOW] ========================================");
    rohc_print_flow("[ROHC-FLOW] Terminal ROHC channel CREATED");
    RohcLog(RohcLogLevel::INFO, "[Terminal] ROHC channel created: session_id=%u, role=TERMINAL",
            rohc_session_id_);
    RohcLog(RohcLogLevel::INFO, "[Terminal] ROHC profiles: IP/UDP/RTP enabled, O-mode, Piggyback feedback");
    rohc_print_flow("[ROHC-FLOW] ========================================");

    return 0;
}

void PPPHandler::rohc_destroy_channel()
{
    if (!rohc_enabled_) {
        return;
    }

    rohc_print_flow("[ROHC-FLOW] ========================================");
    rohc_print_flow("[ROHC-FLOW] Terminal ROHC channel DESTROYING");

    // 打印最终统计
    rohc_print_stats();

    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);
    rohc.destroy_channel(rohc_session_id_);

    rohc_enabled_ = false;

    RohcLog(RohcLogLevel::INFO, "[Terminal] ROHC channel destroyed: session_id=%u",
            rohc_session_id_);
    rohc_print_flow("[ROHC-FLOW] ========================================");
}

// ====================== ROHC 帧级压缩/解压 ======================

uint16_t PPPHandler::rohc_compress_frame(uint8_t *frame_data, uint16_t frame_len)
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
        RohcLog(RohcLogLevel::WARNING, "[Terminal] IP packet too short for compression: %zu bytes", ip_len);
        return frame_len;
    }

    // 调用ROHC压缩
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);
    size_t compressed_len = 0;
    int ret = rohc.compress_ip_packet(rohc_session_id_, ip_data, ip_len, compressed_len);

    if (ret != 0 || compressed_len == 0) {
        RohcLog(RohcLogLevel::WARNING, "[Terminal] ROHC compression failed, sending original IP packet");
        return frame_len;
    }

    // 更新统计
    rohc_comp_total_orig_bytes_ += ip_len;
    rohc_comp_total_comp_bytes_ += compressed_len;

    // 更新PPPoE长度字段
    // PPPoE Length = 压缩后IP数据长度 + PPP协议字段(2字节)
    uint16_t new_pppoe_length = compressed_len + 2;
    // PPPoE Length字段在偏移20-21处(6+6+2+1+1+2=18, 加上length 2字节=offset 18)
    // 实际: Ethernet(14) + version+type(1) + code(1) + session_id(2) + length(2) = 20
    // PPPoE length字段在offset 18-19 (从0开始)
    frame_data[18] = (new_pppoe_length >> 8) & 0xFF;
    frame_data[19] = new_pppoe_length & 0xFF;

    // 返回新的帧总长度
    uint16_t new_frame_len = PPPOE_IP_PAYLOAD_OFFSET + compressed_len;

    RohcLog(RohcLogLevel::DEBUG, "[Terminal] Frame compressed: orig_ip=%zu, comp=%zu, frame: %u->%u, saved=%zu bytes (%.1f%%)",
            ip_len, compressed_len, frame_len, new_frame_len,
            ip_len - compressed_len,
            ip_len > 0 ? (100.0 * (ip_len - compressed_len) / ip_len) : 0.0);

    return new_frame_len;
}

uint16_t PPPHandler::rohc_decompress_frame(uint8_t *frame_data, uint16_t frame_len, uint16_t max_frame_len)
{
    // 检查是否为IP包
    if (!is_ip_frame(frame_data, frame_len)) {
        return frame_len;
    }

    // 检查帧长度
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
    if (PPPOE_IP_PAYLOAD_OFFSET + 1500 > max_frame_len) {
        RohcLog(RohcLogLevel::WARNING, "[Terminal] Buffer too small for decompression: max=%u, need>=%u",
                max_frame_len, PPPOE_IP_PAYLOAD_OFFSET + 1500);
        return frame_len;
    }

    // 调用ROHC解压
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);
    size_t decompressed_len = 0;
    int ret = rohc.decompress_packet(rohc_session_id_, rohc_data, rohc_len, decompressed_len);

    if (ret != 0 || decompressed_len == 0) {
        RohcLog(RohcLogLevel::WARNING, "[Terminal] ROHC decompression failed (comp_len=%zu), dropping packet", rohc_len);
        return frame_len;
    }

    // 更新统计
    rohc_decomp_total_comp_bytes_ += rohc_len;
    rohc_decomp_total_decomp_bytes_ += decompressed_len;

    // 更新PPPoE长度字段
    uint16_t new_pppoe_length = decompressed_len + 2;
    frame_data[18] = (new_pppoe_length >> 8) & 0xFF;
    frame_data[19] = new_pppoe_length & 0xFF;

    // 返回新的帧总长度
    uint16_t new_frame_len = PPPOE_IP_PAYLOAD_OFFSET + decompressed_len;

    RohcLog(RohcLogLevel::DEBUG, "[Terminal] Frame decompressed: comp=%zu, decomp_ip=%zu, frame: %u->%u, expanded=%zu bytes",
            rohc_len, decompressed_len, frame_len, new_frame_len,
            decompressed_len - rohc_len);

    return new_frame_len;
}

bool PPPHandler::is_ip_frame(const uint8_t *frame_data, uint16_t frame_len) const
{
    if (!frame_data || frame_len < PPPOE_IP_PAYLOAD_OFFSET) {
        return false;
    }

    // 检查以太网类型(偏移12-13)
    uint16_t ether_type = (frame_data[12] << 8) | frame_data[13];
    if (ether_type != ETHER_TYPE_PPP_SESSION) {
        return false;
    }

    // 检查PPP协议字段(偏移20-21, 即PPPoE header之后的2字节)
    uint16_t proto = (frame_data[20] << 8) | frame_data[21];
    if (proto != IP) {
        return false;
    }

    return true;
}

// ====================== ROHC 调试打印函数 ======================

void PPPHandler::rohc_print_flow(const char *step)
{
#if ROHC_DEBUG_PRINT
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);
    printf("[%s.%03ld] %s\n", time_buf, tv.tv_usec / 1000, step);
#endif
}

void PPPHandler::rohc_print_ip_header(const uint8_t *ip_data, size_t ip_len, const char *direction)
{
#if ROHC_DEBUG_PRINT
    if (!ip_data || ip_len < 20) {
        printf("[ROHC-DBG] %s: IP packet too short (%zu bytes)\n", direction, ip_len);
        return;
    }

    // 解析IPv4头(不考虑选项和扩展头)
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

void PPPHandler::rohc_print_compress_detail(size_t orig_len, size_t comp_len, uint16_t session_id)
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

void PPPHandler::rohc_print_decompress_detail(size_t comp_len, size_t decomp_len, uint16_t session_id)
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

void PPPHandler::rohc_dump_packet(const uint8_t *data, size_t len, const char *prefix, size_t max_bytes)
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

void PPPHandler::rohc_print_stats()
{
#if ROHC_DEBUG_PRINT
    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);
    uint64_t comp_packets = 0, decomp_packets = 0;
    uint64_t comp_failures = 0, decomp_failures = 0;
    rohc.get_stats(rohc_session_id_, comp_packets, decomp_packets, comp_failures, decomp_failures);

    printf("[ROHC-STATS] ==================== Terminal ROHC Stats ====================\n");
    printf("[ROHC-STATS] Channel: session_id=%u, role=TERMINAL, enabled=%s\n",
           rohc_session_id_, rohc_enabled_ ? "YES" : "NO");
    printf("[ROHC-STATS] Compress:   packets=%llu  failures=%llu  orig_bytes=%llu  comp_bytes=%llu\n",
           (unsigned long long)comp_packets, (unsigned long long)comp_failures,
           (unsigned long long)rohc_comp_total_orig_bytes_,
           (unsigned long long)rohc_comp_total_comp_bytes_);
    if (rohc_comp_total_orig_bytes_ > 0) {
        double avg_ratio = 100.0 * rohc_comp_total_comp_bytes_ / rohc_comp_total_orig_bytes_;
        printf("[ROHC-STATS]   Avg compress ratio: %.1f%% (saved %.1f%%)\n",
               avg_ratio, 100.0 - avg_ratio);
    }
    printf("[ROHC-STATS] Decompress: packets=%llu  failures=%llu  comp_bytes=%llu  decomp_bytes=%llu\n",
           (unsigned long long)decomp_packets, (unsigned long long)decomp_failures,
           (unsigned long long)rohc_decomp_total_comp_bytes_,
           (unsigned long long)rohc_decomp_total_decomp_bytes_);
    printf("[ROHC-STATS] =============================================================\n");
#endif
}

void PPPHandler::rohc_reset_stats()
{
    rohc_comp_total_orig_bytes_ = 0;
    rohc_comp_total_comp_bytes_ = 0;
    rohc_decomp_total_comp_bytes_ = 0;
    rohc_decomp_total_decomp_bytes_ = 0;

    RohcWrapper& rohc = RohcWrapper::instance(RohcWrapper::RohcRole::TERMINAL);
    rohc.reset_stats(rohc_session_id_);
}
