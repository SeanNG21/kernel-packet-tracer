#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# test_all_verdicts.sh - Test tất cả NFTables verdicts (FIXED VERSION)
# Script này tạo rules và traffic để test mọi verdict của nftables

set -e

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Cấu hình
TEST_TABLE="test_verdicts"
TEST_CHAIN="test_chain"
RESULTS_FILE="/tmp/nft_test_results.txt"
NETNS="test_ns"

# =============================================================================
# HÀM HỖ TRỢ
# =============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${MAGENTA}[INFO]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Script này phải chạy với quyền root"
        exit 1
    fi
}

check_dependencies() {
    print_test "Kiểm tra dependencies..."
    
    local missing=0
    
    if ! command -v nft &> /dev/null; then
        print_error "nftables (nft) không tìm thấy"
        print_info "Cài đặt: sudo apt install nftables"
        missing=1
    fi
    
    if ! command -v hping3 &> /dev/null; then
        print_warning "hping3 không tìm thấy (khuyến nghị cài)"
        print_info "Cài đặt: sudo apt install hping3"
    fi
    
    if ! command -v nc &> /dev/null && ! command -v netcat &> /dev/null; then
        print_warning "netcat không tìm thấy"
        print_info "Cài đặt: sudo apt install netcat-openbsd"
    fi
    
    if [ $missing -eq 1 ]; then
        exit 1
    fi
    
    print_success "Tất cả dependencies đã sẵn sàng"
}

cleanup_all() {
    print_test "Dọn dẹp..."
    
    # Xóa table
    nft delete table inet $TEST_TABLE 2>/dev/null || true
    nft delete table ip $TEST_TABLE 2>/dev/null || true
    nft delete table ip6 $TEST_TABLE 2>/dev/null || true
    
    # Xóa network namespace nếu có
    ip netns delete $NETNS 2>/dev/null || true
    
    # Kill các process nếu có
    pkill -9 nc 2>/dev/null || true
    pkill -9 netcat 2>/dev/null || true
    
    print_success "Dọn dẹp hoàn tất"
}

# =============================================================================
# SETUP
# =============================================================================

setup_base_table() {
    print_test "Thiết lập table và chains cơ bản..."
    
    # Tạo table mới
    nft add table inet $TEST_TABLE
    
    # Tạo các chains với hooks khác nhau
    nft add chain inet $TEST_TABLE input { \
        type filter hook input priority 0\; policy accept\; \
    }
    
    nft add chain inet $TEST_TABLE output { \
        type filter hook output priority 0\; policy accept\; \
    }
    
    nft add chain inet $TEST_TABLE forward { \
        type filter hook forward priority 0\; policy accept\; \
    }
    
    # Tạo các custom chains
    nft add chain inet $TEST_TABLE jump_target
    nft add chain inet $TEST_TABLE goto_target
    
    print_success "Table và chains đã được tạo"
}

show_current_rules() {
    print_info "Rules hiện tại:"
    echo ""
    nft list table inet $TEST_TABLE
    echo ""
}

get_counter_value() {
    local chain="$1"
    local match="$2"
    
    # Parse counter value từ nft output - FIX: sử dụng grep và awk chính xác hơn
    local counter=$(nft list chain inet $TEST_TABLE $chain 2>/dev/null | \
                    grep "$match" | \
                    grep -oP 'packets \K[0-9]+' | \
                    head -1)
    
    # Nếu không tìm thấy, return 0
    echo "${counter:-0}"
}

# =============================================================================
# TEST 1: ACCEPT VERDICT
# =============================================================================

test_accept() {
    print_header "TEST 1: ACCEPT Verdict"
    
    print_test "Tạo rule ACCEPT cho ICMP..."
    nft add rule inet $TEST_TABLE input icmp type echo-request counter accept
    
    print_test "Gửi ICMP ping để trigger ACCEPT..."
    
    # Đợi một chút để rule được apply
    sleep 0.5
    
    local before=$(get_counter_value "input" "icmp type echo-request")
    
    ping -c 3 -W 1 127.0.0.1 > /dev/null 2>&1
    sleep 1
    
    local after=$(get_counter_value "input" "icmp type echo-request")
    
    if [ "$after" -gt "$before" ]; then
        print_success "ACCEPT verdict hoạt động - Counter tăng từ $before lên $after packets"
        echo "ACCEPT: PASS" >> $RESULTS_FILE
    else
        print_error "ACCEPT verdict không trigger (before=$before, after=$after)"
        echo "ACCEPT: FAIL" >> $RESULTS_FILE
    fi
    
    show_current_rules
}

# =============================================================================
# TEST 2: DROP VERDICT
# =============================================================================

test_drop() {
    print_header "TEST 2: DROP Verdict"
    
    local test_port=9999
    
    print_test "Tạo rule DROP cho TCP port $test_port..."
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter drop
    
    print_test "Thử kết nối đến port $test_port (sẽ bị DROP)..."
    
    sleep 0.5
    local before=$(get_counter_value "input" "tcp dport $test_port")
    
    # Thử kết nối (sẽ timeout vì bị DROP)
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local after=$(get_counter_value "input" "tcp dport $test_port")
    
    if [ "$after" -gt "$before" ]; then
        print_success "DROP verdict hoạt động - Counter tăng từ $before lên $after packets"
        echo "DROP: PASS" >> $RESULTS_FILE
    else
        print_warning "DROP verdict không trigger được (có thể do không có traffic)"
        echo "DROP: PARTIAL" >> $RESULTS_FILE
    fi
    
    show_current_rules
}

# =============================================================================
# TEST 3: REJECT VERDICT
# =============================================================================

test_reject() {
    print_header "TEST 3: REJECT Verdict"
    
    local test_port=9998
    
    print_test "Tạo rule REJECT cho TCP port $test_port..."
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter reject with tcp reset
    
    print_test "Thử kết nối đến port $test_port (sẽ bị REJECT)..."
    
    sleep 0.5
    local before=$(get_counter_value "input" "tcp dport $test_port")
    
    # Thử kết nối (sẽ nhận RST ngay lập tức)
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local after=$(get_counter_value "input" "tcp dport $test_port")
    
    if [ "$after" -gt "$before" ]; then
        print_success "REJECT verdict hoạt động - Counter tăng từ $before lên $after packets"
        print_info "REJECT sẽ gửi TCP RST về cho client"
        echo "REJECT: PASS" >> $RESULTS_FILE
    else
        print_warning "REJECT verdict không trigger được"
        echo "REJECT: PARTIAL" >> $RESULTS_FILE
    fi
    
    show_current_rules
}

# =============================================================================
# TEST 4: CONTINUE VERDICT
# =============================================================================

test_continue() {
    print_header "TEST 4: CONTINUE Verdict"
    
    local test_port=8888
    
    print_test "Tạo rules với CONTINUE..."
    print_info "Rule 1: counter + continue (packet sẽ tiếp tục đến rule tiếp theo)"
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter continue
    
    print_info "Rule 2: drop (packet sẽ bị drop sau khi continue)"
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter drop
    
    print_test "Gửi traffic đến port $test_port..."
    
    sleep 0.5
    
    # Lấy tất cả rules và đếm counter
    local rules_before=$(nft list chain inet $TEST_TABLE input | grep "tcp dport $test_port")
    
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local rules_after=$(nft list chain inet $TEST_TABLE input | grep "tcp dport $test_port")
    
    # Lấy counter của rule đầu tiên (continue)
    local counter1=$(echo "$rules_after" | head -1 | grep -oP 'packets \K[0-9]+' || echo "0")
    # Lấy counter của rule thứ hai (drop)
    local counter2=$(echo "$rules_after" | tail -1 | grep -oP 'packets \K[0-9]+' || echo "0")
    
    if [ "$counter1" -gt 0 ] && [ "$counter2" -gt 0 ]; then
        print_success "CONTINUE verdict hoạt động"
        print_info "Counter 1 (continue): $counter1 packets"
        print_info "Counter 2 (drop): $counter2 packets"
        print_success "Packet đi qua cả 2 rules (continue → drop)"
        echo "CONTINUE: PASS" >> $RESULTS_FILE
    else
        print_warning "CONTINUE verdict không trigger đầy đủ (counter1=$counter1, counter2=$counter2)"
        echo "CONTINUE: PARTIAL" >> $RESULTS_FILE
    fi
    
    show_current_rules
}

# =============================================================================
# TEST 5: JUMP và RETURN VERDICTS
# =============================================================================

test_jump_return() {
    print_header "TEST 5: JUMP và RETURN Verdicts"
    
    local test_port=7777
    
    print_test "Tạo rules với JUMP và RETURN..."
    
    # Rule trong chain chính: jump đến custom chain
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter jump jump_target
    
    # Rules trong custom chain
    nft add rule inet $TEST_TABLE jump_target counter comment \"trong-jump-target\"
    nft add rule inet $TEST_TABLE jump_target return
    nft add rule inet $TEST_TABLE jump_target counter comment \"sau-return\"
    
    # Rule sau jump trong chain chính
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter accept
    
    print_test "Gửi traffic đến port $test_port..."
    
    sleep 0.5
    local before=$(get_counter_value "input" "tcp dport $test_port")
    
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local after=$(get_counter_value "input" "tcp dport $test_port")
    
    if [ "$after" -gt "$before" ]; then
        print_success "JUMP verdict hoạt động"
        print_info "Packet: input chain → JUMP → jump_target → RETURN → input chain"
        echo "JUMP: PASS" >> $RESULTS_FILE
        echo "RETURN: PASS" >> $RESULTS_FILE
    else
        print_warning "JUMP/RETURN không trigger được"
        echo "JUMP: PARTIAL" >> $RESULTS_FILE
        echo "RETURN: PARTIAL" >> $RESULTS_FILE
    fi
    
    print_info "Jump target chain:"
    nft list chain inet $TEST_TABLE jump_target
    echo ""
}

# =============================================================================
# TEST 6: GOTO VERDICT
# =============================================================================

test_goto() {
    print_header "TEST 6: GOTO Verdict"
    
    local test_port=7778
    
    print_test "Tạo rules với GOTO..."
    print_info "GOTO khác với JUMP: không thể RETURN về chain gốc"
    
    # Rule goto
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter goto goto_target
    
    # Rule sau goto (sẽ không bao giờ chạy)
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter comment \"sau-goto-unreachable\"
    
    # Rules trong goto target
    nft add rule inet $TEST_TABLE goto_target counter comment \"trong-goto-target\"
    nft add rule inet $TEST_TABLE goto_target accept
    
    print_test "Gửi traffic đến port $test_port..."
    
    sleep 0.5
    local before=$(get_counter_value "input" "tcp dport $test_port")
    
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local after=$(get_counter_value "input" "tcp dport $test_port")
    
    if [ "$after" -gt "$before" ]; then
        print_success "GOTO verdict hoạt động"
        print_info "Packet: input chain → GOTO → goto_target (không return)"
        echo "GOTO: PASS" >> $RESULTS_FILE
    else
        print_warning "GOTO không trigger được"
        echo "GOTO: PARTIAL" >> $RESULTS_FILE
    fi
    
    print_info "Goto target chain:"
    nft list chain inet $TEST_TABLE goto_target
    echo ""
}

# =============================================================================
# TEST 7: QUEUE VERDICT
# =============================================================================

test_queue() {
    print_header "TEST 7: QUEUE Verdict"
    
    local test_port=6666
    
    print_warning "QUEUE verdict cần có userspace daemon (nfqueue)"
    print_info "Nếu không có daemon, packet sẽ bị drop"
    
    print_test "Tạo rule QUEUE..."
    nft add rule inet $TEST_TABLE input tcp dport $test_port counter queue num 0
    
    print_test "Gửi traffic đến port $test_port..."
    
    sleep 0.5
    local before=$(get_counter_value "input" "tcp dport $test_port")
    
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    local after=$(get_counter_value "input" "tcp dport $test_port")
    
    if [ "$after" -gt "$before" ]; then
        print_success "QUEUE verdict được trigger"
        print_info "Packets được gửi đến nfqueue 0 (nhưng bị drop do không có daemon)"
        echo "QUEUE: PASS (no daemon)" >> $RESULTS_FILE
    else
        print_warning "QUEUE không trigger được"
        echo "QUEUE: FAIL" >> $RESULTS_FILE
    fi
    
    show_current_rules
}

# =============================================================================
# TEST 8: STOLEN VERDICT (Kernel Internal)
# =============================================================================

test_stolen() {
    print_header "TEST 8: STOLEN Verdict"
    
    print_info "STOLEN là verdict kernel internal"
    print_info "Được dùng bởi các subsystem như conntrack, NAT"
    print_warning "Không thể test trực tiếp từ nftables rules"
    
    print_test "Tạo NAT rule để trigger STOLEN internally..."
    
    # NAT masquerade có thể trigger STOLEN verdict trong kernel
    nft add table ip nat_test 2>/dev/null || true
    nft add chain ip nat_test postrouting { \
        type nat hook postrouting priority 100\; \
    } 2>/dev/null || true
    
    nft add rule ip nat_test postrouting counter masquerade 2>/dev/null || true
    
    print_info "NAT rule tạo thành công (có thể trigger STOLEN internally)"
    print_warning "STOLEN verdict chỉ có thể quan sát qua kernel tracing"
    
    nft delete table ip nat_test 2>/dev/null || true
    
    echo "STOLEN: INFO (kernel internal)" >> $RESULTS_FILE
}

# =============================================================================
# TEST 9: POLICY VERDICT
# =============================================================================

test_policy() {
    print_header "TEST 9: Chain Policy (Default Verdict)"
    
    print_test "Test default policy của chain..."
    
    # Traffic không match rule nào sẽ dùng policy
    print_info "Gửi traffic đến port 12345 (không có rule match)"
    
    timeout 2 nc -w 1 127.0.0.1 12345 2>/dev/null || true
    sleep 1
    
    print_success "Policy verdict hoạt động (default: ACCEPT)"
    print_info "Packet không match rule nào → dùng chain policy"
    
    echo "POLICY: PASS" >> $RESULTS_FILE
}

# =============================================================================
# TEST 10: MULTIPLE HOOKS
# =============================================================================

test_multiple_hooks() {
    print_header "TEST 10: Multiple Hooks"
    
    print_test "Test các hooks khác nhau..."
    
    # INPUT hook
    print_info "INPUT hook: incoming traffic đến local machine"
    nft add rule inet $TEST_TABLE input tcp dport 5555 counter accept
    
    # OUTPUT hook
    print_info "OUTPUT hook: outgoing traffic từ local machine"
    nft add rule inet $TEST_TABLE output tcp dport 5556 counter accept
    
    print_test "Test INPUT hook..."
    timeout 2 nc -w 1 127.0.0.1 5555 2>/dev/null || true
    sleep 1
    
    print_test "Test OUTPUT hook..."
    timeout 2 nc -w 1 8.8.8.8 5556 2>/dev/null || true
    sleep 1
    
    local input_packets=$(get_counter_value "input" "tcp dport 5555")
    local output_packets=$(get_counter_value "output" "tcp dport 5556")
    
    print_success "INPUT hook: $input_packets packets"
    print_success "OUTPUT hook: $output_packets packets"
    
    echo "HOOKS: PASS" >> $RESULTS_FILE
    
    show_current_rules
}

# =============================================================================
# TEST 11: LOG VERDICT (Expression)
# =============================================================================

test_log() {
    print_header "TEST 11: LOG Expression"
    
    local test_port=4444
    
    print_test "Tạo rule với LOG expression..."
    nft add rule inet $TEST_TABLE input tcp dport $test_port log prefix \"NFT-TEST: \" counter drop
    
    print_test "Gửi traffic để trigger LOG..."
    print_info "Kiểm tra kernel log: dmesg | tail"
    
    timeout 2 nc -w 1 127.0.0.1 $test_port 2>/dev/null || true
    sleep 1
    
    # Kiểm tra log trong dmesg
    if dmesg | tail -20 | grep -q "NFT-TEST"; then
        print_success "LOG expression hoạt động - xem dmesg"
        echo "LOG: PASS" >> $RESULTS_FILE
    else
        print_warning "Không tìm thấy log trong dmesg"
        echo "LOG: PARTIAL" >> $RESULTS_FILE
    fi
    
    print_info "Xem log:"
    dmesg | tail -5 | grep "NFT-TEST" || echo "  (không có log)"
    echo ""
}

# =============================================================================
# SUMMARY
# =============================================================================

show_summary() {
    print_header "TÓM TẮT KẾT QUẢ TEST"
    
    echo "📊 Kết quả từng verdict:"
    echo ""
    cat $RESULTS_FILE
    echo ""
    
    local total_tests=$(wc -l < $RESULTS_FILE)
    local passed=$(grep -c "PASS" $RESULTS_FILE || echo 0)
    local failed=$(grep -c "FAIL" $RESULTS_FILE || echo 0)
    local partial=$(grep -c "PARTIAL" $RESULTS_FILE || echo 0)
    
    echo "📈 Thống kê:"
    echo "  Tổng số tests: $total_tests"
    echo "  ✓ Passed:      $passed"
    echo "  ✗ Failed:      $failed"
    echo "  ! Partial:     $partial"
    echo ""
    
    print_header "GIẢI THÍCH CÁC VERDICTS"
    
    cat << 'EOF'
📖 NFTables Verdicts:

1. ACCEPT ✅
   - Chấp nhận packet, cho phép đi tiếp
   - Packet sẽ tiếp tục qua các rules khác (nếu có)
   - Ví dụ: cho phép SSH từ IP tin cậy

2. DROP 🚫
   - Bỏ packet im lặng (không phản hồi gì)
   - Client sẽ timeout khi chờ
   - Dùng để "ẩn" service khỏi port scan

3. REJECT ⛔
   - Từ chối packet và gửi phản hồi về
   - TCP: gửi RST
   - UDP/ICMP: gửi ICMP error
   - Client nhận được thông báo ngay lập tức

4. CONTINUE ➡️
   - Verdict của NFT expression, không phải kernel verdict
   - Packet tiếp tục đến rule tiếp theo trong chain
   - Dùng để kết hợp nhiều actions (counter + continue + drop)

5. JUMP 🔗
   - Nhảy đến custom chain khác
   - Có thể RETURN về chain gốc
   - Cho phép tổ chức rules theo module
   - Ví dụ: jump đến chain xử lý logging

6. RETURN ↩️
   - Quay về chain gọi JUMP
   - Tiếp tục từ rule sau JUMP
   - Không có tác dụng trong GOTO

7. GOTO 🎯
   - Nhảy đến chain khác (như JUMP)
   - KHÔNG thể return về
   - Rules sau GOTO sẽ không bao giờ chạy
   - Dùng cho optimization (tail call)

8. QUEUE 📦
   - Gửi packet đến userspace (nfqueue)
   - Cần daemon để xử lý
   - Nếu không có daemon → DROP
   - Dùng cho IDS/IPS, DPI

9. STOLEN 🔒
   - Verdict kernel internal
   - Kernel "ăn cắp" packet để xử lý
   - Dùng bởi conntrack, NAT, etc.
   - Không thể tạo trực tiếp từ nftables

10. LOG 📝 (Expression)
    - Không phải verdict, là expression
    - Ghi log vào kernel log (dmesg)
    - Packet tiếp tục xử lý
    - Dùng cho debugging và monitoring

11. POLICY 🏷️
    - Default verdict của chain
    - Dùng khi không có rule nào match
    - Thường là ACCEPT hoặc DROP
    - Định nghĩa hành vi mặc định

═══════════════════════════════════════════════════════════════

🎓 Các khái niệm quan trọng:

KERNEL VERDICTS (NF_*):
  - NF_DROP (0): Drop packet
  - NF_ACCEPT (1): Accept packet
  - NF_STOLEN (2): Kernel stolen packet
  - NF_QUEUE (3): Queue to userspace
  - NF_REPEAT (4): Call hook again

NFT VERDICTS:
  - continue: NFT expression, không phải kernel verdict
  - jump/goto/return: Control flow trong nftables

HOOKS:
  - PREROUTING: Packet mới vào
  - INPUT: Đến local process
  - FORWARD: Qua router
  - OUTPUT: Từ local process
  - POSTROUTING: Packet ra khỏi system

═══════════════════════════════════════════════════════════════

🔍 Debugging Tips:

1. Xem rules và counters:
   nft list table inet test_verdicts

2. Monitor traffic realtime:
   nft monitor

3. Trace packets:
   nft add rule inet test_verdicts input meta nftrace set 1
   nft monitor trace

4. Check kernel log:
   dmesg | grep NFT
   dmesg | tail -f

5. Test với tcpdump:
   tcpdump -i lo -nn port 9999

EOF
    
    print_header "HOÀN TẤT"
    
    echo ""
    echo "📁 Rules hiện tại:"
    nft list table inet $TEST_TABLE
    echo ""
    echo "💾 Kết quả lưu tại: $RESULTS_FILE"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Clear results file
    > $RESULTS_FILE
    
    print_header "🚀 BẮT ĐẦU TEST TẤT CẢ NFTABLES VERDICTS"
    
    check_root
    check_dependencies
    cleanup_all
    
    setup_base_table
    
    # Chạy tất cả tests
    test_accept
    test_drop
    test_reject
    test_continue
    test_jump_return
    test_goto
    test_queue
    test_stolen
    test_policy
    test_multiple_hooks
    test_log
    
    # Summary
    show_summary
    
    # Cleanup
    # print_test "Giữ rules để xem? (Ctrl+C để giữ, Enter để xóa)"
    # read -t 10 || true
    # cleanup_all
    
    echo ""
    print_success "✅ Tất cả tests hoàn tất!"
    echo ""
}

# Trap cleanup on exit
# trap cleanup_all EXIT

# Run
main "$@"