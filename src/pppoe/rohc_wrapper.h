#ifndef ROHC_WRAPPER_H
#define ROHC_WRAPPER_H

/**
 * @file rohc_wrapper.h
 * @brief ROHC (Robust Header Compression) 封装层 - 头文件
 *
 * 基于 rohc 库 (https://github.com/viveris/rohc) 实现头部压缩/解压缩功能。
 * 设计原则：
 *   1. 单例模式 - 每侧(终端/网关)全局唯一实例
 *   2. C++11标准 - 使用std::unique_ptr、std::mutex等
 *   3. 就地处理 - 压缩/解压尽量在原缓冲区操作，减少内存拷贝
 *   4. 内存优化 - 按需创建压缩通道，闲置时释放
 *   5. Piggyback反馈机制 - 将反馈信息附带在数据包中传输
 *   6. 双向管理器 - 每个通道同时维护压缩器和解压器
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <array>
#include <memory>
#include <functional>
#include <string>

// ==================== ROHC 库头文件集成 ====================
// 使用三方库配合头文件集成的方式
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>
#include <rohc/rohc_buf.h>
#include <rohc/rohc_time.h>

// ==================== 常量定义 ====================

/// 最大支持的PPPoE会话数（每会话对应一对ROHC通道）
constexpr uint16_t ROHC_MAX_CHANNELS = 2;

// [bug-fix] ROHC双向流上下文隔离: 每个会话分配独立的压缩/解压通道 begin
/// 每个会话对应两个ROHC通道：压缩通道(正向流)和解压通道(反向流)
/// 压缩通道索引 = session_id
/// 解压通道索引 = session_id + ROHC_MAX_CHANNELS
/// 这样comp和decomp拥有完全独立的上下文和feedback缓冲区，
/// 避免IP-ID delta参考值在双向流之间交叉污染导致SN参考计算错误
constexpr uint16_t ROHC_MAX_TOTAL_CHANNELS = ROHC_MAX_CHANNELS * 2;

/// 获取解压通道的索引（相对于session_id的偏移）
inline uint16_t rohc_decomp_channel_id(uint16_t session_id) {
    return session_id + ROHC_MAX_CHANNELS;
}
// [bug-fix] ROHC双向流上下文隔离 end

/// 最大压缩后数据包长度（含反馈数据）
constexpr uint16_t ROHC_MAX_PACKET_LEN = 2048;

/// 最大反馈数据长度
constexpr uint16_t ROHC_MAX_FEEDBACK_LEN = 256;

/// 默认最大CID值（rohc_cid_t = uint16_t）
constexpr rohc_cid_t ROHC_DEFAULT_MAX_CID = 15;

/// 压缩缓冲区大小（就地处理时的临时缓冲区）
constexpr uint16_t ROHC_COMP_BUFFER_SIZE = 1600;

/// 解压缓冲区大小
constexpr uint16_t ROHC_DECOMP_BUFFER_SIZE = 1600;

/// ROHC日志回调类型
enum class RohcLogLevel : uint8_t {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
};

// ==================== 日志函数声明 ====================
void RohcLog(RohcLogLevel level, const char* format, ...);

// ==================== ROHC通道状态 ====================

/**
 * @brief ROHC通道 - 管理单一方向的压缩器或解压器
 *
 * [bug-fix] ROHC双向流上下文隔离说明：
 * 每个PPPoE会话对应两个ROHC通道（通过session_id索引）：
 * - 压缩通道(channels_[session_id])：只使用comp字段，处理正向流出站压缩
 * - 解压通道(channels_[session_id + ROHC_MAX_CHANNELS])：只使用decomp字段，处理反向流入站解压
 *
 * 这样设计的原因：ROHC库中同一CID的Compressor和Decompressor会共享IP-ID delta
 * 参考值，导致反向流解压时的SN参考计算错误。将两者分到完全独立的通道中，
 * 各自拥有独立的上下文和feedback缓冲区，彻底消除交叉污染。
 *
 * 通道内含：
 * - 压缩器(comp)或解压器(decomp)：二选一，由通道用途决定
 * - 反馈缓冲区：存放该方向上的反馈信息（Piggyback机制）
 */
struct RohcChannel {
    /// 压缩器句柄
    struct rohc_comp* comp{nullptr};

    /// 解压器句柄
    struct rohc_decomp* decomp{nullptr};

    /// 通道是否已初始化
    bool initialized{false};

    /// 通道关联的会话ID（0 ~ ROHC_MAX_CHANNELS-1）
    uint16_t session_id{0};

    /// 反馈缓冲区（存放待发送的反馈数据）
    uint8_t feedback_buf[ROHC_MAX_FEEDBACK_LEN];

    /// 反馈数据实际长度
    size_t feedback_len{0};

    /// 统计：压缩包数
    uint64_t comp_packets{0};

    /// 统计：解压包数
    uint64_t decomp_packets{0};

    /// 统计：压缩失败数
    uint64_t comp_failures{0};

    /// 统计：解压失败数
    uint64_t decomp_failures{0};

    RohcChannel() { std::memset(feedback_buf, 0, sizeof(feedback_buf)); }
};

// ==================== ROHC封装层主类 ====================

/**
 * @class RohcWrapper
 * @brief ROHC头部压缩/解压缩封装层 - 单例模式
 *
 * 使用方式：
 * - 终端侧：RohcWrapper::instance(RohcRole::TERMINAL)
 * - 网关侧：RohcWrapper::instance(RohcRole::GATEWAY)
 *
 * 关键功能：
 * 1. 头部压缩：compress_ip_packet() 压缩IP包头
 * 2. 头部解压：decompress_packet() 解压ROHC包
 * 3. Piggyback反馈：compress时自动携带反馈数据
 * 4. 反馈收集：decompress时自动收集对端需要的反馈
 * 5. 双向管理：每个通道同时维护comp和decomp
 * 6. 通道管理：create_channel()/destroy_channel() 管理通道生命周期
 */
class RohcWrapper {
public:
    /**
     * @brief ROHC角色枚举
     */
    enum class RohcRole : uint8_t {
        TERMINAL = 0,   ///< 终端侧
        GATEWAY = 1     ///< 网关侧
    };

    /**
     * @brief 获取单例实例
     * @param role ROHC角色（终端/网关）
     * @return RohcWrapper引用
     */
    static RohcWrapper& instance(RohcRole role = RohcRole::TERMINAL);

    // 禁止拷贝和赋值
    RohcWrapper(const RohcWrapper&) = delete;
    RohcWrapper& operator=(const RohcWrapper&) = delete;

    // ==================== 通道管理 ====================

    /**
     * @brief 创建ROHC通道
     * @param session_id PPPoE会话ID
     * @return 0成功，-1失败
     */
    int create_channel(uint16_t session_id);

    /**
     * @brief 销毁ROHC通道
     * @param session_id PPPoE会话ID
     */
    void destroy_channel(uint16_t session_id);

    /**
     * @brief 检查通道是否存在且已初始化
     * @param session_id PPPoE会话ID
     * @return true存在，false不存在
     */
    bool has_channel(uint16_t session_id) const;

    /**
     * @brief 销毁所有通道
     */
    void destroy_all_channels();

    // ==================== 压缩/解压操作 ====================

    /**
     * @brief 压缩IP数据包（就地处理）
     *
     * 将IP包的头部压缩，结果写回原缓冲区。
     * 如果压缩后的数据比原始数据短，则将压缩数据移到缓冲区前端，
     * 并通过compressed_len返回压缩后长度。
     * 自动携带Piggyback反馈数据。
     *
     * @param session_id PPPoE会话ID
     * @param ip_data IP数据包（含IP头）输入输出缓冲区
     * @param ip_len IP数据包原始长度
     * @param compressed_len [out] 压缩后数据长度
     * @return 0成功，-1失败（失败时原始数据不变）
     */
    int compress_ip_packet(uint16_t session_id,
                           uint8_t* ip_data,
                           size_t ip_len,
                           size_t& compressed_len);

    /**
     * @brief 解压ROHC数据包（就地处理）
     *
     * 将ROHC压缩包解压为原始IP包，结果写回原缓冲区。
     * 解压成功后自动收集反馈信息，供下次压缩时Piggyback发送。
     *
     * @param session_id PPPoE会话ID
     * @param rohc_data ROHC压缩数据包输入输出缓冲区
     * @param rohc_len ROHC压缩数据包长度
     * @param decompressed_len [out] 解压后数据长度
     * @return 0成功，-1失败（失败时缓冲区内容可能被修改）
     */
    int decompress_packet(uint16_t session_id,
                          uint8_t* rohc_data,
                          size_t rohc_len,
                          size_t& decompressed_len);

    // ==================== 反馈机制 ====================

    /**
     * @brief 获取待发送的反馈数据（Piggyback机制）
     * @param session_id PPPoE会话ID
     * @param feedback_buf [out] 反馈数据缓冲区
     * @param feedback_len [out] 反馈数据长度
     * @return 0成功且有反馈数据，-1无反馈数据或失败
     */
    int get_feedback(uint16_t session_id,
                     uint8_t* feedback_buf,
                     size_t& feedback_len);

    /**
     * @brief 提交接收到的反馈数据给压缩器
     *
     * 对端通过Piggyback发来的反馈数据，需要提交给本端压缩器
     * 以更新压缩上下文状态。
     *
     * @param session_id PPPoE会话ID
     * @param feedback_data 反馈数据
     * @param feedback_len 反馈数据长度
     * @return 0成功，-1失败
     */
    int submit_feedback(uint16_t session_id,
                        const uint8_t* feedback_data,
                        size_t feedback_len);

    // ==================== 统计信息 ====================

    /**
     * @brief 获取通道统计信息
     * @param session_id PPPoE会话ID
     * @param comp_packets [out] 压缩包数
     * @param decomp_packets [out] 解压包数
     * @param comp_failures [out] 压缩失败数
     * @param decomp_failures [out] 解压失败数
     * @return 0成功，-1失败
     */
    int get_stats(uint16_t session_id,
                  uint64_t& comp_packets,
                  uint64_t& decomp_packets,
                  uint64_t& comp_failures,
                  uint64_t& decomp_failures) const;

    /**
     * @brief 重置通道统计
     * @param session_id PPPoE会话ID
     */
    void reset_stats(uint16_t session_id);

    // ==================== 配置 ====================

    /**
     * @brief 设置ROHC Profile启用/禁用
     * @param profile_id ROHC Profile ID
     * @param enable true启用，false禁用
     */
    void set_profile_enabled(rohc_profile_t profile_id, bool enable);

    /**
     * @brief 设置传输模式（U-mode/O-mode/R-mode）
     *
     * 注意：rohc库没有 rohc_comp_set_mode() 函数。
     * 压缩器的工作模式由对端解压器的反馈自动驱动。
     * 本函数通过重新创建解压器来改变模式。
     *
     * @param session_id PPPoE会话ID
     * @param mode 传输模式（ROHC_U_MODE / ROHC_O_MODE / ROHC_R_MODE）
     * @return 0成功，-1失败
     */
    int set_compression_mode(uint16_t session_id, rohc_mode_t mode);

    /**
     * @brief 获取角色
     * @return 当前角色
     */
    RohcRole get_role() const { return role_; }

private:
    /**
     * @brief 私有构造函数（单例模式）
     * @param role ROHC角色
     */
    explicit RohcWrapper(RohcRole role);

    /**
     * @brief 析构函数
     */
    ~RohcWrapper();

    // ==================== 内部辅助方法 ====================

    /**
     * @brief 初始化压缩器
     * @param channel ROHC通道指针
     * @return 0成功，-1失败
     */
    int init_compressor(RohcChannel* channel);

    /**
     * @brief 初始化解压器
     * @param channel ROHC通道指针
     * @return 0成功，-1失败
     */
    int init_decompressor(RohcChannel* channel);

    /**
     * @brief 释放通道资源
     * @param channel ROHC通道指针
     */
    void cleanup_channel(RohcChannel* channel);

    /**
     * @brief 收集解压器产生的反馈数据
     * @param channel ROHC通道指针
     */
    void collect_feedback(RohcChannel* channel);

    /**
     * @brief 将反馈数据附带在压缩包中（Piggyback）
     * @param channel ROHC通道指针
     * @param comp_data 压缩数据缓冲区
     * @param comp_len 压缩数据长度
     * @param out_buf [out] 输出缓冲区
     * @param out_len [out] 输出长度
     * @return 0成功，-1失败
     */
    int piggyback_feedback(RohcChannel* channel,
                           const uint8_t* comp_data,
                           size_t comp_len,
                           uint8_t* out_buf,
                           size_t& out_len);

    /**
     * @brief 从压缩包中提取Piggyback反馈数据
     * @param channel ROHC通道指针
     * @param data 接收到的数据
     * @param data_len 数据长度
     * @param rohc_data [out] 纯ROHC压缩数据
     * @param rohc_len [out] 纯ROHC压缩数据长度
     * @param feedback_data [out] 反馈数据
     * @param feedback_len [out] 反馈数据长度
     * @return 0成功，-1失败
     */
    int extract_piggyback(RohcChannel* channel,
                          const uint8_t* data,
                          size_t data_len,
                          uint8_t* rohc_data,
                          size_t& rohc_len,
                          uint8_t* feedback_data,
                          size_t& feedback_len);

    // ==================== ROHC回调函数 ====================

    /**
     * @brief ROHC压缩器反馈回调（已废弃，rohc库无此回调机制）
     * 反馈由 rohc_decompress3() 的 feedback_send 输出 +
     * rohc_comp_deliver_feedback2() 投递给压缩器 +
     * rohc_compress4() 自动Piggyback
     */
    static void comp_feedback_callback(const uint8_t* feedback_data,
                                       size_t feedback_len,
                                       void* user_data);

    /**
     * @brief ROHC库日志回调
     * @param level 日志级别
     * @param module 模块名
     * @param fmt 格式字符串
     * @param ... 可变参数
     */
    // 匹配 rohc_trace_callback2_t 声明：
    //   void (*)(void *const priv_ctxt, const rohc_trace_level_t level,
    //            const rohc_trace_entity_t entity, const int profile,
    //            const char *const format, ...)
    static void rohc_log_callback(void* const priv_data,
                                  const rohc_trace_level_t level,
                                  const rohc_trace_entity_t entity,
                                  const int profile_id,
                                  const char* const format,
                                  ...);

    /**
     * @brief 生成随机数回调（用于CID分配等）
     * @param comp 压缩器句柄
     * @param user_data 用户数据
     * @return 随机数
     */
    // 匹配 rohc_comp_random_cb_t 声明：
    //   int (*)(const struct rohc_comp *const comp, void *const user_context)
    static int rand_callback(const struct rohc_comp* const comp,
                            void* const user_context);

    // ==================== 成员变量 ====================

    /// 角色标识
    RohcRole role_;

    /// ROHC通道数组（大小为会话数的2倍，每会话占2个通道：comp + decomp）
    std::array<RohcChannel, ROHC_MAX_TOTAL_CHANNELS> channels_;

    /// 全局互斥锁（保护通道操作）
    mutable std::mutex mutex_;

    /// Profile启用状态
    bool profile_ip_enabled_{true};
    bool profile_udp_enabled_{true};
    bool profile_rtp_enabled_{true};
    bool profile_esp_enabled_{false};
    bool profile_tcp_enabled_{false};

    /// 压缩临时缓冲区（就地处理用）
    alignas(4) uint8_t comp_buffer_[ROHC_COMP_BUFFER_SIZE];

    /// 解压临时缓冲区（就地处理用）
    alignas(4) uint8_t decomp_buffer_[ROHC_DECOMP_BUFFER_SIZE];

    /// Piggyback封装临时缓冲区
    alignas(4) uint8_t piggyback_buffer_[ROHC_MAX_PACKET_LEN];

    /// 解压提取临时缓冲区
    alignas(4) uint8_t extract_rohc_buffer_[ROHC_MAX_PACKET_LEN];
    alignas(4) uint8_t extract_feedback_buffer_[ROHC_MAX_FEEDBACK_LEN];
};

#endif // ROHC_WRAPPER_H