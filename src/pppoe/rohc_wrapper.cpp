/**
 * @file rohc_wrapper.cpp
 * @brief ROHC (Robust Header Compression) 封装层 - 实现
 *
 * 基于rohc库 (https://github.com/viveris/rohc) 实现头部压缩/解压缩功能。
 * 所有API调用严格对齐 rohc_comp.h / rohc_decomp.h / rohc_buf.h 中的声明。
 */

#include "rohc_wrapper.h"
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>

// ==================== 日志函数实现 ====================

void RohcLog(RohcLogLevel level, const char* format, ...)
{
    va_list args;
    va_start(args, format);

    const char* prefix = "";
    switch (level) {
        case RohcLogLevel::DEBUG:   prefix = "[ROHC-DBG] "; break;
        case RohcLogLevel::INFO:    prefix = "[ROHC-INF] "; break;
        case RohcLogLevel::WARNING: prefix = "[ROHC-WRN] "; break;
        case RohcLogLevel::ERROR:   prefix = "[ROHC-ERR] "; break;
    }

    fprintf(stdout, "%s", prefix);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    va_end(args);
}

// ==================== rohc_buf 辅助函数 ====================

/**
 * @brief 构造输入用的 rohc_buf（包裹已有数据，不拥有内存）
 *
 * 使用 rohc 库提供的 rohc_buf_init_full 宏初始化。
 * 用于 rohc_compress4() 的 uncomp_packet 参数和
 * rohc_decompress3() 的 rohc_packet 参数。
 *
 * @param data   数据指针
 * @param len    数据长度
 * @return struct rohc_buf
 */
static struct rohc_buf rohc_buf_wrap(const uint8_t* data, size_t len)
{
    const struct rohc_ts zero_time = { .sec = 0, .nsec = 0 };
    /* rohc_buf_init_full 宏中 data 参数是 uint8_t*，
     * 输入场景需做 const_cast（rohc库内部不会修改uncomp_packet数据） */
    return (struct rohc_buf) rohc_buf_init_full(const_cast<uint8_t*>(data), len, zero_time);
}

/**
 * @brief 构造输出用的 rohc_buf（指定缓冲区，len 初始为0）
 *
 * 使用 rohc 库提供的 rohc_buf_init_empty 宏初始化。
 * 用于 rohc_compress4() 的 rohc_packet 输出参数和
 * rohc_decompress3() 的 uncomp_packet / rcvd_feedback / feedback_send 输出参数。
 *
 * @param data     缓冲区指针
 * @param max_len  缓冲区最大容量
 * @return struct rohc_buf
 */
static struct rohc_buf rohc_buf_output(uint8_t* data, size_t max_len)
{
    return (struct rohc_buf) rohc_buf_init_empty(data, max_len);
}

// ==================== 单例实现 ====================

static RohcWrapper* g_terminal_instance = nullptr;
static RohcWrapper* g_gateway_instance = nullptr;
static std::mutex g_instance_mutex;

RohcWrapper& RohcWrapper::instance(RohcRole role)
{
    // 双重检查锁定模式
    if (role == RohcRole::TERMINAL) {
        if (!g_terminal_instance) {
            std::lock_guard<std::mutex> lock(g_instance_mutex);
            if (!g_terminal_instance) {
                static RohcWrapper terminal_instance(RohcRole::TERMINAL);
                g_terminal_instance = &terminal_instance;
            }
        }
        return *g_terminal_instance;
    } else {
        if (!g_gateway_instance) {
            std::lock_guard<std::mutex> lock(g_instance_mutex);
            if (!g_gateway_instance) {
                static RohcWrapper gateway_instance(RohcRole::GATEWAY);
                g_gateway_instance = &gateway_instance;
            }
        }
        return *g_gateway_instance;
    }
}

// ==================== 构造/析构 ====================

RohcWrapper::RohcWrapper(RohcRole role)
    : role_(role),
      channels_{},
      comp_buffer_{},
      decomp_buffer_{},
      piggyback_buffer_{},
      extract_rohc_buffer_{},
      extract_feedback_buffer_{}
{
    RohcLog(RohcLogLevel::INFO, "RohcWrapper initialized as %s",
            role == RohcRole::TERMINAL ? "TERMINAL" : "GATEWAY");
}

RohcWrapper::~RohcWrapper()
{
    destroy_all_channels();
    RohcLog(RohcLogLevel::INFO, "RohcWrapper destroyed (%s)",
            role_ == RohcRole::TERMINAL ? "TERMINAL" : "GATEWAY");
}

// ==================== 通道管理 ====================

int RohcWrapper::create_channel(uint16_t session_id)
{
    // [bug-fix] ROHC双向流上下文隔离: 每个会话创建两个独立通道 begin
    if (session_id >= ROHC_MAX_CHANNELS) {
        RohcLog(RohcLogLevel::ERROR, "Invalid session_id=%u (max=%u)",
                session_id, ROHC_MAX_CHANNELS);
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // 1. 初始化压缩通道（只含comp，用于正向流出站压缩）
    RohcChannel& comp_channel = channels_[session_id];
    if (comp_channel.initialized) {
        RohcLog(RohcLogLevel::WARNING, "Comp channel %u already initialized, re-creating",
                session_id);
        cleanup_channel(&comp_channel);
    }
    comp_channel.session_id = session_id;
    if (init_compressor(&comp_channel) != 0) {
        RohcLog(RohcLogLevel::ERROR, "Failed to init compressor for channel %u",
                session_id);
        cleanup_channel(&comp_channel);
        return -1;
    }
    comp_channel.initialized = true;
    comp_channel.comp_packets = 0;
    comp_channel.comp_failures = 0;
    comp_channel.feedback_len = 0;

    // 2. 初始化解压通道（只含decomp，用于反向流入站解压）
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    RohcChannel& decomp_channel = channels_[decomp_id];
    if (decomp_channel.initialized) {
        RohcLog(RohcLogLevel::WARNING, "Decomp channel %u already initialized, re-creating",
                decomp_id);
        cleanup_channel(&decomp_channel);
    }
    decomp_channel.session_id = decomp_id;
    if (init_decompressor(&decomp_channel) != 0) {
        RohcLog(RohcLogLevel::ERROR, "Failed to init decompressor for channel %u",
                decomp_id);
        cleanup_channel(&decomp_channel);
        // 清理已创建的压缩通道
        cleanup_channel(&comp_channel);
        return -1;
    }
    decomp_channel.initialized = true;
    decomp_channel.decomp_packets = 0;
    decomp_channel.decomp_failures = 0;

    RohcLog(RohcLogLevel::INFO,
            "Channel %u created successfully (comp=%u, decomp=%u, independent contexts)",
            session_id, session_id, decomp_id);
    // [bug-fix] ROHC双向流上下文隔离 end
    return 0;
}

void RohcWrapper::destroy_channel(uint16_t session_id)
{
    if (session_id >= ROHC_MAX_CHANNELS) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 销毁两个独立通道 begin
    // 销毁压缩通道
    cleanup_channel(&channels_[session_id]);
    // 销毁解压通道
    cleanup_channel(&channels_[rohc_decomp_channel_id(session_id)]);
    // [bug-fix] ROHC双向流上下文隔离 end
}

bool RohcWrapper::has_channel(uint16_t session_id) const
{
    if (session_id >= ROHC_MAX_CHANNELS) {
        return false;
    }

    // [bug-fix] ROHC双向流上下文隔离: 检查两个通道是否都初始化 begin
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    return channels_[session_id].initialized && channels_[decomp_id].initialized;
    // [bug-fix] ROHC双向流上下文隔离 end
}

void RohcWrapper::destroy_all_channels()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint16_t i = 0; i < ROHC_MAX_CHANNELS; ++i) {
        cleanup_channel(&channels_[i]);
    }
}

// ==================== 压缩操作 ====================

int RohcWrapper::compress_ip_packet(uint16_t session_id,
                                     uint8_t* ip_data,
                                     size_t ip_len,
                                     size_t& compressed_len)
{
    if (!ip_data || ip_len == 0) {
        RohcLog(RohcLogLevel::ERROR, "Invalid input: ip_data=%p, ip_len=%zu",
                ip_data, ip_len);
        return -1;
    }

    if (session_id >= ROHC_MAX_CHANNELS) {
        RohcLog(RohcLogLevel::ERROR, "Invalid session_id=%u", session_id);
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 使用独立的压缩通道 begin
    RohcChannel& comp_channel = channels_[session_id];
    if (!comp_channel.initialized || !comp_channel.comp) {
        RohcLog(RohcLogLevel::ERROR, "Comp channel %u not initialized for compression",
                session_id);
        return -1;
    }

    // 步骤1：将待发送的反馈投递给压缩器
    //   反馈来自解压通道（反向流解压器产生的反馈），保存在压缩通道的feedback_buf中
    //   调用 rohc_comp_deliver_feedback2() 后，压缩器在下次 rohc_compress4()
    //   时会自动将反馈 Piggyback 到压缩包中
    if (comp_channel.feedback_len > 0) {
        struct rohc_buf feedback_buf = rohc_buf_wrap(comp_channel.feedback_buf,
                                                     comp_channel.feedback_len);
        if (!rohc_comp_deliver_feedback2(comp_channel.comp, feedback_buf)) {
            RohcLog(RohcLogLevel::WARNING,
                    "Failed to deliver feedback to compressor for channel %u",
                    session_id);
            // 投递失败不中断压缩流程，仅记录警告
        } else {
            RohcLog(RohcLogLevel::DEBUG,
                    "Delivered %zu bytes feedback to compressor for channel %u",
                    comp_channel.feedback_len, session_id);
            comp_channel.feedback_len = 0;
        }
    }

    // 步骤2：使用 rohc_compress4 压缩 IP 包
    //   声明：rohc_status_t rohc_compress4(comp, const rohc_buf, rohc_buf*)
    //   压缩器会自动携带之前通过 deliver_feedback2 投递的反馈数据
    struct rohc_buf uncomp_packet = rohc_buf_wrap(ip_data, ip_len);
    struct rohc_buf rohc_packet   = rohc_buf_output(comp_buffer_,
                                                     sizeof(comp_buffer_));

    rohc_status_t status = rohc_compress4(comp_channel.comp, uncomp_packet,
                                           &rohc_packet);
    if (status != ROHC_STATUS_OK) {
        comp_channel.comp_failures++;
        RohcLog(RohcLogLevel::WARNING,
                "Compression failed for channel %u: status=%d",
                session_id, static_cast<int>(status));
        return -1;
    }

    // 步骤3：从 rohc_packet 中获取压缩后的数据长度
    //   注意：rohc_buf 的有效数据从 data + offset 开始，长度为 len
    //   使用 rohc_buf_data() 获取有效数据起始指针
    size_t comp_len = rohc_packet.len;

    if (comp_len == 0) {
        comp_channel.comp_failures++;
        RohcLog(RohcLogLevel::WARNING,
                "Compression produced 0 bytes for channel %u", session_id);
        return -1;
    }

    // 步骤4：将压缩数据拷回原缓冲区（就地处理）
    //   rohc_buf_data() 返回 data + offset
    //   注意：IR包（初始化刷新包）可能比原始IP包大，这是协议正常行为，
    //   解压器必须收到IR包才能建立上下文，因此始终发送压缩后的ROHC数据
    const uint8_t* comp_data_ptr = rohc_buf_data(rohc_packet);
    if (comp_len <= sizeof(comp_buffer_)) {
        std::memcpy(ip_data, comp_data_ptr, comp_len);
        compressed_len = comp_len;
    } else {
        // 压缩数据超出内部缓冲区大小，属于异常情况
        RohcLog(RohcLogLevel::ERROR,
                "Compressed data(%zu) exceeds buffer size(%zu), this should not happen",
                comp_len, sizeof(comp_buffer_));
        return -1;
    }

    comp_channel.comp_packets++;
    // [bug-fix] ROHC双向流上下文隔离 end
    return 0;
}

// ==================== 解压操作 ====================

int RohcWrapper::decompress_packet(uint16_t session_id,
                                    uint8_t* rohc_data,
                                    size_t rohc_len,
                                    size_t& decompressed_len)
{
    if (!rohc_data || rohc_len == 0) {
        RohcLog(RohcLogLevel::ERROR, "Invalid input: rohc_data=%p, rohc_len=%zu",
                rohc_data, rohc_len);
        return -1;
    }

    if (session_id >= ROHC_MAX_CHANNELS) {
        RohcLog(RohcLogLevel::ERROR, "Invalid session_id=%u", session_id);
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 使用独立的解压通道和压缩通道投递feedback begin
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    RohcChannel& decomp_channel = channels_[decomp_id];
    if (!decomp_channel.initialized || !decomp_channel.decomp) {
        RohcLog(RohcLogLevel::ERROR, "Decomp channel %u not initialized for decompression",
                decomp_id);
        return -1;
    }

    // 获取对应的压缩通道（用于投递rcvd_feedback和保存feedback_send）
    RohcChannel& comp_channel = channels_[session_id];

    // 使用 rohc_decompress3 解压
    //   声明：rohc_status_t rohc_decompress3(decomp, const rohc_buf,
    //                                        rohc_buf*, rohc_buf*, rohc_buf*)
    //   - uncomp_packet : 输出解压后的IP包
    //   - rcvd_feedback: 输出对端发来的反馈（给本端压缩器用）—— 通过Piggyback收到
    //   - feedback_send: 输出本端解压器产生的反馈（需发给对端压缩器）
    struct rohc_buf comp_packet    = rohc_buf_wrap(rohc_data, rohc_len);
    struct rohc_buf uncomp_packet  = rohc_buf_output(decomp_buffer_,
                                                      sizeof(decomp_buffer_));
    struct rohc_buf rcvd_feedback  = rohc_buf_output(extract_feedback_buffer_,
                                                      sizeof(extract_feedback_buffer_));
    struct rohc_buf feedback_send  = rohc_buf_output(piggyback_buffer_,
                                                      sizeof(piggyback_buffer_));

    rohc_status_t status = rohc_decompress3(decomp_channel.decomp, comp_packet,
                                             &uncomp_packet,
                                             &rcvd_feedback,
                                             &feedback_send);

    // 步骤1：处理 Piggyback 收到的对端反馈 —— 投递给本端压缩器（通过comp通道）
    //   无论解压是否成功，都应处理反馈数据，以确保压缩器上下文能及时更新
    //   注意：rcvd_feedback 的有效数据从 data + offset 开始
    //   关键：必须投递给comp通道的压缩器，因为comp通道拥有独立的上下文
    if (rcvd_feedback.len > 0 && comp_channel.comp) {
        const uint8_t* rcvd_fb_ptr = rohc_buf_data(rcvd_feedback);
        struct rohc_buf fb = rohc_buf_wrap(rcvd_fb_ptr, rcvd_feedback.len);
        if (!rohc_comp_deliver_feedback2(comp_channel.comp, fb)) {
            RohcLog(RohcLogLevel::WARNING,
                    "Failed to deliver rcvd_feedback to compressor for channel %u",
                    session_id);
        } else {
            RohcLog(RohcLogLevel::DEBUG,
                    "Delivered %zu bytes piggyback feedback to comp channel %u",
                    rcvd_feedback.len, session_id);
        }
    }

    // 步骤2：保存本端解压器产生的反馈数据
    //   这些反馈将在下次 compress_ip_packet() 时通过 deliver_feedback2 + Piggyback 发送给对端
    //   即使解压失败（如CRC错误），解压器仍可能产生有效的NACK反馈，不应丢弃
    //   注意：feedback_send 的有效数据从 data + offset 开始
    //   关键：保存到comp通道的feedback_buf，因为下次压缩时从comp通道读取feedback
    if (feedback_send.len > 0) {
        size_t available = ROHC_MAX_FEEDBACK_LEN - comp_channel.feedback_len;
        size_t copy_len  = (feedback_send.len <= available)
                           ? feedback_send.len : available;
        if (copy_len > 0) {
            const uint8_t* fb_data_ptr = rohc_buf_data(feedback_send);
            std::memcpy(comp_channel.feedback_buf + comp_channel.feedback_len,
                        fb_data_ptr, copy_len);
            comp_channel.feedback_len += copy_len;
            RohcLog(RohcLogLevel::DEBUG,
                    "Collected %zu bytes feedback_send from decomp channel %u "
                    "to comp channel %u (total=%zu)",
                    copy_len, decomp_id, session_id, comp_channel.feedback_len);
        }
    }

    // 步骤3：判断解压状态，非OK状态返回错误（但反馈已在上方处理）
    if (status != ROHC_STATUS_OK) {
        decomp_channel.decomp_failures++;
        RohcLog(RohcLogLevel::WARNING,
                "Decompression status=%d for decomp channel %u, but feedback processed",
                static_cast<int>(status), decomp_id);
        return -1;
    }

    // 步骤4：将解压后的数据拷回原缓冲区（就地处理）
    //   注意：uncomp_packet 的有效数据从 data + offset 开始
    size_t decomp_len = uncomp_packet.len;
    if (decomp_len == 0) {
        decomp_channel.decomp_failures++;
        RohcLog(RohcLogLevel::WARNING,
                "Decompression produced 0 bytes for decomp channel %u", decomp_id);
        return -1;
    }

    const uint8_t* decomp_data_ptr = rohc_buf_data(uncomp_packet);
    if (decomp_len <= ROHC_MAX_PACKET_LEN) {
        std::memcpy(rohc_data, decomp_data_ptr, decomp_len);
        decompressed_len = decomp_len;
    } else {
        RohcLog(RohcLogLevel::ERROR, "Decompressed data too large: %zu", decomp_len);
        return -1;
    }

    decomp_channel.decomp_packets++;
    // [bug-fix] ROHC双向流上下文隔离 end
    return 0;
}

// ==================== 反馈机制 ====================

int RohcWrapper::get_feedback(uint16_t session_id,
                               uint8_t* feedback_buf,
                               size_t& feedback_len)
{
    if (session_id >= ROHC_MAX_CHANNELS || !feedback_buf) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 从压缩通道获取feedback begin
    RohcChannel& comp_channel = channels_[session_id];

    if (!comp_channel.initialized || comp_channel.feedback_len == 0) {
        feedback_len = 0;
        return -1;
    }

    size_t copy_len = comp_channel.feedback_len;
    if (copy_len > ROHC_MAX_FEEDBACK_LEN) {
        copy_len = ROHC_MAX_FEEDBACK_LEN;
    }

    std::memcpy(feedback_buf, comp_channel.feedback_buf, copy_len);
    feedback_len = copy_len;
    comp_channel.feedback_len = 0;
    // [bug-fix] ROHC双向流上下文隔离 end

    return 0;
}

int RohcWrapper::submit_feedback(uint16_t session_id,
                                  const uint8_t* feedback_data,
                                  size_t feedback_len)
{
    if (session_id >= ROHC_MAX_CHANNELS || !feedback_data || feedback_len == 0) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 提交给压缩通道的压缩器 begin
    RohcChannel& comp_channel = channels_[session_id];
    if (!comp_channel.initialized || !comp_channel.comp) {
        return -1;
    }

    // 声明：bool rohc_comp_deliver_feedback2(comp, const struct rohc_buf feedback)
    struct rohc_buf fb = rohc_buf_wrap(feedback_data, feedback_len);
    if (!rohc_comp_deliver_feedback2(comp_channel.comp, fb)) {
        RohcLog(RohcLogLevel::WARNING,
                "Failed to deliver feedback to compressor for channel %u",
                session_id);
        return -1;
    }

    RohcLog(RohcLogLevel::DEBUG,
            "Submitted %zu bytes feedback to compressor for channel %u",
            feedback_len, session_id);
    // [bug-fix] ROHC双向流上下文隔离 end
    return 0;
}

// ==================== 统计信息 ====================

int RohcWrapper::get_stats(uint16_t session_id,
                            uint64_t& comp_packets,
                            uint64_t& decomp_packets,
                            uint64_t& comp_failures,
                            uint64_t& decomp_failures) const
{
    if (session_id >= ROHC_MAX_CHANNELS) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 分别从压缩通道和解压通道获取统计 begin
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    const RohcChannel& comp_channel = channels_[session_id];
    const RohcChannel& decomp_channel = channels_[decomp_id];

    if (!comp_channel.initialized || !decomp_channel.initialized) {
        return -1;
    }

    comp_packets = comp_channel.comp_packets;
    decomp_packets = decomp_channel.decomp_packets;
    comp_failures = comp_channel.comp_failures;
    decomp_failures = decomp_channel.decomp_failures;
    // [bug-fix] ROHC双向流上下文隔离 end

    return 0;
}

void RohcWrapper::reset_stats(uint16_t session_id)
{
    if (session_id >= ROHC_MAX_CHANNELS) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 分别重置两个通道的统计 begin
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    RohcChannel& comp_channel = channels_[session_id];
    RohcChannel& decomp_channel = channels_[decomp_id];

    comp_channel.comp_packets = 0;
    comp_channel.comp_failures = 0;
    decomp_channel.decomp_packets = 0;
    decomp_channel.decomp_failures = 0;
    // [bug-fix] ROHC双向流上下文隔离 end
}

// ==================== 配置 ====================

void RohcWrapper::set_profile_enabled(rohc_profile_t profile_id, bool enable)
{
    std::lock_guard<std::mutex> lock(mutex_);

    switch (profile_id) {
        case ROHC_PROFILE_UNCOMPRESSED:
            // 始终启用
            break;
        case ROHC_PROFILE_IP:
            profile_ip_enabled_ = enable;
            break;
        case ROHC_PROFILE_UDP:
            profile_udp_enabled_ = enable;
            break;
        case ROHC_PROFILE_RTP:
            profile_rtp_enabled_ = enable;
            break;
        case ROHC_PROFILE_ESP:
            profile_esp_enabled_ = enable;
            break;
        case ROHC_PROFILE_TCP:
            profile_tcp_enabled_ = enable;
            break;
        default:
            break;
    }
}

int RohcWrapper::set_compression_mode(uint16_t session_id, rohc_mode_t mode)
{
    if (session_id >= ROHC_MAX_CHANNELS) {
        return -1;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // [bug-fix] ROHC双向流上下文隔离: 操作独立的解压通道 begin
    uint16_t decomp_id = rohc_decomp_channel_id(session_id);
    RohcChannel& decomp_channel = channels_[decomp_id];

    if (!decomp_channel.initialized || !decomp_channel.decomp) {
        return -1;
    }

    // rohc库没有 rohc_comp_set_mode() 函数
    // 压缩器的工作模式由对端解压器的反馈自动驱动切换
    // 若需更改模式，需要重新创建解压器
    // 此处实现：销毁旧解压器，以新模式创建
    if (decomp_channel.decomp) {
        rohc_decomp_free(decomp_channel.decomp);
        decomp_channel.decomp = nullptr;
    }

    // 声明：rohc_decomp_new2(cid_type, max_cid, mode)
    decomp_channel.decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_DEFAULT_MAX_CID, mode);
    if (!decomp_channel.decomp) {
        RohcLog(RohcLogLevel::ERROR,
                "Failed to recreate decompressor with new mode for decomp channel %u",
                decomp_id);
        decomp_channel.initialized = false;
        return -1;
    }

    // 重新启用Profile
    if (profile_ip_enabled_) {
        rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_IP);
    }
    if (profile_udp_enabled_) {
        rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_UDP);
    }
    if (profile_rtp_enabled_) {
        rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_RTP);
    }
    if (profile_esp_enabled_) {
        rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_ESP);
    }
    if (profile_tcp_enabled_) {
        rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_TCP);
    }
    rohc_decomp_enable_profile(decomp_channel.decomp, ROHC_PROFILE_UNCOMPRESSED);

    // 设置MRRU > 0 以启用解压器的反馈通道
    if (!rohc_decomp_set_mrru(decomp_channel.decomp, ROHC_MAX_FEEDBACK_LEN)) {
        RohcLog(RohcLogLevel::WARNING,
                "Failed to set MRRU for recreated decompressor for decomp channel %u",
                decomp_id);
    }

    // 启用CRC修复特性
    if (!rohc_decomp_set_features(decomp_channel.decomp, ROHC_DECOMP_FEATURE_CRC_REPAIR)) {
        RohcLog(RohcLogLevel::WARNING,
                "Failed to enable CRC repair feature for recreated decompressor for decomp channel %u",
                decomp_id);
    }

    // 设置日志回调
    rohc_decomp_set_traces_cb2(decomp_channel.decomp, rohc_log_callback, this);

    RohcLog(RohcLogLevel::INFO,
            "Decomp channel %u (session %u) decompressor recreated with mode=%d",
            decomp_id, session_id, static_cast<int>(mode));
    // [bug-fix] ROHC双向流上下文隔离 end
    return 0;
}

// ==================== 内部方法 ====================

int RohcWrapper::init_compressor(RohcChannel* channel)
{
    if (!channel) {
        return -1;
    }

    // 声明：rohc_comp_new2(cid_type, max_cid, rand_cb, rand_priv)
    channel->comp = rohc_comp_new2(ROHC_SMALL_CID,     // cid_type
                                    ROHC_DEFAULT_MAX_CID, // max_cid
                                    rand_callback,        // rand_cb
                                    this);                // rand_priv
    if (!channel->comp) {
        RohcLog(RohcLogLevel::ERROR, "Failed to create ROHC compressor");
        return -1;
    }

    // 启用Profile
    // 声明：bool rohc_comp_enable_profile(comp, profile)
    if (profile_ip_enabled_) {
        if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_IP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable IP profile");
        }
    }
    if (profile_udp_enabled_) {
        if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_UDP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable UDP profile");
        }
    }
    if (profile_rtp_enabled_) {
        if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_RTP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable RTP profile");
        }
    }
    if (profile_esp_enabled_) {
        if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_ESP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable ESP profile");
        }
    }
    if (profile_tcp_enabled_) {
        if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_TCP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable TCP profile");
        }
    }
    // Uncompressed profile 始终启用
    if (!rohc_comp_enable_profile(channel->comp, ROHC_PROFILE_UNCOMPRESSED)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to enable Uncompressed profile");
    }

    // 设置MRRU（Maximum Reconstructed Reception Unit）> 0 以启用反馈通道
    // Piggyback反馈需要 MRRU > 0
    if (!rohc_comp_set_mrru(channel->comp, ROHC_MAX_FEEDBACK_LEN)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to set MRRU for compressor");
    }

    // 启用基于时间的周期性刷新特性，适合低速率场景下主动刷新上下文
    // 需配合 rohc_comp_set_periodic_refreshes_time() 设置超时时间
    // 声明：bool rohc_comp_set_features(comp, features)
    if (!rohc_comp_set_features(channel->comp, ROHC_COMP_FEATURE_TIME_BASED_REFRESHES)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to enable time-based refreshes for compressor");
    }

    // 设置周期性刷新超时时间（秒）：
    //   IR超时：5秒内无IR包则主动发送IR刷新
    //   FO超时：2秒内无FO包则主动发送FO刷新
    // 声明：bool rohc_comp_set_periodic_refreshes_time(comp, ir_timeout, fo_timeout)
    if (!rohc_comp_set_periodic_refreshes_time(channel->comp, 5, 2)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to set periodic refreshes time for compressor");
    }

    // 设置日志回调
    // 声明：bool rohc_comp_set_traces_cb2(comp, callback, priv_ctxt)
    if (!rohc_comp_set_traces_cb2(channel->comp, rohc_log_callback, this)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to set trace callback for compressor");
    }

    RohcLog(RohcLogLevel::INFO, "Compressor initialized for session %u",
            channel->session_id);
    return 0;
}

int RohcWrapper::init_decompressor(RohcChannel* channel)
{
    if (!channel) {
        return -1;
    }

    // 声明：rohc_decomp_new2(cid_type, max_cid, mode)
    // 使用双向模式（O-mode），支持Piggyback反馈
    channel->decomp = rohc_decomp_new2(ROHC_SMALL_CID,       // cid_type
                                        ROHC_DEFAULT_MAX_CID,  // max_cid
                                        ROHC_O_MODE);          // mode
    if (!channel->decomp) {
        RohcLog(RohcLogLevel::ERROR, "Failed to create ROHC decompressor");
        return -1;
    }

    // 启用Profile
    // 声明：bool rohc_decomp_enable_profile(decomp, profile)
    if (profile_ip_enabled_) {
        if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_IP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable IP profile for decomp");
        }
    }
    if (profile_udp_enabled_) {
        if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_UDP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable UDP profile for decomp");
        }
    }
    if (profile_rtp_enabled_) {
        if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_RTP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable RTP profile for decomp");
        }
    }
    if (profile_esp_enabled_) {
        if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_ESP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable ESP profile for decomp");
        }
    }
    if (profile_tcp_enabled_) {
        if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_TCP)) {
            RohcLog(RohcLogLevel::WARNING, "Failed to enable TCP profile for decomp");
        }
    }
    // Uncompressed profile 始终启用
    if (!rohc_decomp_enable_profile(channel->decomp, ROHC_PROFILE_UNCOMPRESSED)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to enable Uncompressed profile for decomp");
    }

    // 设置MRRU（Maximum Reconstructed Reception Unit）> 0 以启用反馈通道
    // 解压器必须设置MRRU才能正确解析压缩包中Piggyback的反馈数据
    // 声明：bool rohc_decomp_set_mrru(decomp, mrru)
    if (!rohc_decomp_set_mrru(channel->decomp, ROHC_MAX_FEEDBACK_LEN)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to set MRRU for decompressor");
    }

    // 启用CRC修复特性，提高解压鲁棒性
    // 声明：bool rohc_decomp_set_features(decomp, features)
    if (!rohc_decomp_set_features(channel->decomp, ROHC_DECOMP_FEATURE_CRC_REPAIR)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to enable CRC repair feature for decompressor");
    }

    // 设置日志回调
    // 声明：bool rohc_decomp_set_traces_cb2(decomp, callback, priv_ctxt)
    if (!rohc_decomp_set_traces_cb2(channel->decomp, rohc_log_callback, this)) {
        RohcLog(RohcLogLevel::WARNING, "Failed to set trace callback for decompressor");
    }

    RohcLog(RohcLogLevel::INFO, "Decompressor initialized for session %u",
            channel->session_id);
    return 0;
}

void RohcWrapper::cleanup_channel(RohcChannel* channel)
{
    if (!channel) {
        return;
    }

    // 声明：void rohc_comp_free(comp)
    if (channel->comp) {
        rohc_comp_free(channel->comp);
        channel->comp = nullptr;
    }

    // 声明：void rohc_decomp_free(decomp)
    if (channel->decomp) {
        rohc_decomp_free(channel->decomp);
        channel->decomp = nullptr;
    }

    channel->initialized = false;
    channel->feedback_len = 0;
    channel->comp_packets = 0;
    channel->decomp_packets = 0;
    channel->comp_failures = 0;
    channel->decomp_failures = 0;
}

void RohcWrapper::collect_feedback(RohcChannel* channel)
{
    // 此方法已不再使用，反馈收集已移至 decompress_packet() 中
    // 通过 rohc_decompress3() 的 feedback_send 输出参数直接获取
    (void)channel;
}

int RohcWrapper::piggyback_feedback(RohcChannel* channel,
                                     const uint8_t* comp_data,
                                     size_t comp_len,
                                     uint8_t* out_buf,
                                     size_t& out_len)
{
    // 此方法已不再使用，Piggyback 由 rohc 库自动处理：
    //   1. rohc_comp_deliver_feedback2() 投递反馈给压缩器
    //   2. rohc_compress4() 压缩时自动 Piggyback 已投递的反馈
    // 不再需要手动封装 Piggyback 格式
    (void)channel;
    (void)comp_data;
    (void)comp_len;
    (void)out_buf;
    (void)out_len;
    return -1;
}

int RohcWrapper::extract_piggyback(RohcChannel* channel,
                                    const uint8_t* data,
                                    size_t data_len,
                                    uint8_t* rohc_data,
                                    size_t& rohc_len,
                                    uint8_t* feedback_data,
                                    size_t& feedback_len)
{
    // 此方法已不再使用，Piggyback 反馈由 rohc_decompress3() 自动处理：
    //   - rcvd_feedback 输出参数：包含对端通过 Piggyback 发来的反馈
    //   - feedback_send 输出参数：包含本端解压器产生的反馈
    (void)channel;
    (void)data;
    (void)data_len;
    (void)rohc_data;
    (void)rohc_len;
    (void)feedback_data;
    (void)feedback_len;
    return -1;
}

// ==================== 回调函数 ====================

void RohcWrapper::comp_feedback_callback(const uint8_t* feedback_data,
                                           size_t feedback_len,
                                           void* user_data)
{
    // 此回调已不再使用
    // rohc库没有 rohc_comp_set_feedback_callback() 函数
    // 反馈由以下机制处理：
    //   - 解压器产生反馈：rohc_decompress3() 的 feedback_send 输出
    //   - 投递反馈给压缩器：rohc_comp_deliver_feedback2()
    //   - 压缩器自动Piggyback：rohc_compress4() 自动携带
    (void)feedback_data;
    (void)feedback_len;
    (void)user_data;
}

void RohcWrapper::rohc_log_callback(void* const priv_data,
                                     const rohc_trace_level_t level,
                                     const rohc_trace_entity_t entity,
                                     const int profile_id,
                                     const char* const format,
                                     ...)
{
    // 转换日志级别
    RohcLogLevel rohc_level = RohcLogLevel::DEBUG;
    switch (level) {
        case ROHC_TRACE_DEBUG:   rohc_level = RohcLogLevel::DEBUG; break;
        case ROHC_TRACE_INFO:    rohc_level = RohcLogLevel::INFO; break;
        case ROHC_TRACE_WARNING: rohc_level = RohcLogLevel::WARNING; break;
        case ROHC_TRACE_ERROR:   rohc_level = RohcLogLevel::ERROR; break;
        default: break;
    }

    // 只输出WARNING及以上级别的日志，避免性能影响
    if (rohc_level < RohcLogLevel::WARNING) {
        return;
    }

    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    const char* entity_str = "unknown";
    switch (entity) {
        case ROHC_TRACE_COMP:   entity_str = "COMP"; break;
        case ROHC_TRACE_DECOMP: entity_str = "DECOMP"; break;
        default: break;
    }

    RohcLog(rohc_level, "[%s][profile=%d] %s", entity_str, profile_id, buf);
}

// 声明：int (*)(const struct rohc_comp *const comp, void *const user_context)
int RohcWrapper::rand_callback(const struct rohc_comp* const comp,
                                void* const user_context)
{
    (void)comp;
    (void)user_context;
    return std::rand();
}