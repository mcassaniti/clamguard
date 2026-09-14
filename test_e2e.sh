#!/bin/bash
set -euo pipefail

# ==============================================================================
# Clamguard Automated End-to-End Test Suite
# ==============================================================================
# Runs inside the privileged test container and executes Scenarios A, B, and C.
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
NC="\033[0m"

log_info() {
    echo -e "${CYAN}[INFO]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    exit 1
}

log_step() {
    echo -e "\n${BOLD}${YELLOW}>>> $*${NC}"
}

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_BIN="${WORKSPACE_DIR}/clamguard"
TEST_DIR="/tmp/test-edr"
QUARANTINE_DIR="/var/spool/clamav-quarantine"
CLAMD_SOCKET="/var/run/clamav/clamd.ctl"
LOG_DIR="/tmp/test-logs"

mkdir -p "${LOG_DIR}"

cleanup() {
    log_info "Cleaning up background processes and temporary directories..."
    pkill -TERM -f "${DAEMON_BIN}" 2>/dev/null || true
    pkill -TERM -f "clamd" 2>/dev/null || true
    umount "${TEST_DIR}/mnt" 2>/dev/null || true
    rm -rf "${TEST_DIR}" "${QUARANTINE_DIR}"
}
trap cleanup EXIT

# Verify binary exists
if [ ! -x "${DAEMON_BIN}" ]; then
    log_fail "clamguard binary not found or not executable at ${DAEMON_BIN}"
fi

# ==============================================================================
# Scenario A: ClamAV Stubbed Sanity & Cache Test
# ==============================================================================
log_step "Scenario A: ClamAV Stubbed Sanity & Cache Test"
rm -rf "${TEST_DIR}" "${QUARANTINE_DIR}"
mkdir -p "${TEST_DIR}" "${QUARANTINE_DIR}"

SCENARIO_A_LOG="${LOG_DIR}/scenario_a.log"
"${DAEMON_BIN}" -watch-path "${TEST_DIR}" -stub-clamav -debug > "${SCENARIO_A_LOG}" 2>&1 &
EDR_PID=$!
sleep 1

if ! kill -0 "${EDR_PID}" 2>/dev/null; then
    cat "${SCENARIO_A_LOG}"
    log_fail "Clamguard failed to start in Scenario A"
fi

# 1. Write clean file
echo "initial clean payload" > "${TEST_DIR}/clean_stub.txt"

# 2. First read (should trigger scan on cache miss)
READ1=$(cat "${TEST_DIR}/clean_stub.txt")
if [ "${READ1}" != "initial clean payload" ]; then
    log_fail "Failed to read clean file on first attempt"
fi

# 3. Second read (should be a cache hit)
READ2=$(cat "${TEST_DIR}/clean_stub.txt")
if [ "${READ2}" != "initial clean payload" ]; then
    log_fail "Failed to read clean file on second attempt"
fi

# Graceful termination
kill -TERM "${EDR_PID}"
wait "${EDR_PID}" 2>/dev/null || true

# Assertions from logs
if grep -q "Cache miss. Scanning file: ${TEST_DIR}/clean_stub.txt" "${SCENARIO_A_LOG}"; then
    log_pass "Scenario A: Initial scan triggered on cache miss"
else
    cat "${SCENARIO_A_LOG}"
    log_fail "Scenario A: Initial scan log not found"
fi

if grep -q "Cache hit (CLEAN): ${TEST_DIR}/clean_stub.txt" "${SCENARIO_A_LOG}"; then
    log_pass "Scenario A: Cache hit verified on second read"
else
    cat "${SCENARIO_A_LOG}"
    log_fail "Scenario A: Cache hit log not found"
fi

if grep -q "tearing down marks and exiting" "${SCENARIO_A_LOG}"; then
    log_pass "Scenario A: Graceful shutdown on SIGTERM verified"
else
    cat "${SCENARIO_A_LOG}"
    log_fail "Scenario A: Graceful shutdown log not found"
fi

# ==============================================================================
# Scenario B: Real ClamAV Interception & Quarantine Test (EICAR)
# ==============================================================================
log_step "Scenario B: Real ClamAV Interception & Quarantine Test (EICAR)"
rm -rf "${TEST_DIR}" "${QUARANTINE_DIR}"
mkdir -p "${TEST_DIR}" "${QUARANTINE_DIR}" /var/run/clamav /var/lib/clamav
chown -R clamav:clamav /var/run/clamav /var/lib/clamav 2>/dev/null || true

# Start clamd
log_info "Starting clamd daemon..."
clamd &
CLAMD_PID=$!

for i in $(seq 1 30); do
    if [ -S "${CLAMD_SOCKET}" ]; then
        log_info "clamd socket is ready at ${CLAMD_SOCKET}"
        break
    fi
    sleep 0.5
done

if [ ! -S "${CLAMD_SOCKET}" ]; then
    log_fail "clamd failed to initialize Unix socket"
fi

SCENARIO_B_LOG="${LOG_DIR}/scenario_b.log"
"${DAEMON_BIN}" -watch-path "${TEST_DIR}" -debug > "${SCENARIO_B_LOG}" 2>&1 &
EDR_PID=$!
sleep 1

if ! kill -0 "${EDR_PID}" 2>/dev/null; then
    cat "${SCENARIO_B_LOG}"
    log_fail "Clamguard failed to start in Scenario B"
fi

# 1. Clean file test
echo "safe document content" > "${TEST_DIR}/clean.txt"
CLEAN_READ=$(cat "${TEST_DIR}/clean.txt")
if [ "${CLEAN_READ}" == "safe document content" ]; then
    log_pass "Scenario B: Clean file read successfully allowed"
else
    log_fail "Scenario B: Clean file read was unexpectedly denied"
fi

# 2. Write EICAR test string to /tmp/test-edr/malware.com
EICAR_STRING='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s' "${EICAR_STRING}" > "${TEST_DIR}/malware.com"

# 3. Attempt to read malware.com
log_info "Attempting to read ${TEST_DIR}/malware.com (expecting block / deny)..."
BLOCKED=0
if cat "${TEST_DIR}/malware.com" 2>/dev/null; then
    log_fail "Scenario B: Read of malware.com was ALLOWED but should have been BLOCKED!"
else
    BLOCKED=1
    log_pass "Scenario B Assertion 1: Read operation was blocked / denied"
fi

sleep 0.5

# 4. Verify malware.com is unlinked
if [ ! -f "${TEST_DIR}/malware.com" ]; then
    log_pass "Scenario B Assertion 2: Original threat file was automatically unlinked"
else
    log_fail "Scenario B Assertion 2: Original threat file still exists at ${TEST_DIR}/malware.com"
fi

# 5. Verify quarantine copy exists
QUARANTINE_FILE="${QUARANTINE_DIR}/malware.com.quarantine"
if [ -f "${QUARANTINE_FILE}" ]; then
    log_pass "Scenario B Assertion 3: Quarantine file exists at ${QUARANTINE_FILE}"
else
    log_fail "Scenario B Assertion 3: Quarantine file not found at ${QUARANTINE_FILE}"
fi

# 6. Verify quarantined file permissions are 000
QUARANTINE_PERMS=$(stat -c '%a' "${QUARANTINE_FILE}")
if [ "${QUARANTINE_PERMS}" == "0" ] || [ "${QUARANTINE_PERMS}" == "000" ] || [ "${QUARANTINE_PERMS}" == "0000" ]; then
    log_pass "Scenario B Assertion 4: Quarantine file permissions are strictly 000 (got: ${QUARANTINE_PERMS})"
else
    log_fail "Scenario B Assertion 4: Quarantine file permissions expected 000, got: ${QUARANTINE_PERMS}"
fi

# 7. Verify quarantine content matches EICAR string
chmod 400 "${QUARANTINE_FILE}"
QUARANTINE_CONTENT=$(cat "${QUARANTINE_FILE}")
if [ "${QUARANTINE_CONTENT}" == "${EICAR_STRING}" ]; then
    log_pass "Scenario B Assertion 5: Quarantined content perfectly matches EICAR test string"
else
    log_fail "Scenario B Assertion 5: Quarantined content mismatch. Got: '${QUARANTINE_CONTENT}'"
fi

# Graceful termination
kill -TERM "${EDR_PID}"
wait "${EDR_PID}" 2>/dev/null || true
kill -TERM "${CLAMD_PID}" 2>/dev/null || true
wait "${CLAMD_PID}" 2>/dev/null || true

# ==============================================================================
# Scenario C: Watchdog Mount Detachment & Cache Invalidation Test
# ==============================================================================
log_step "Scenario C: Watchdog Mount Detachment & Cache Invalidation Test"
rm -rf "${TEST_DIR}" "${QUARANTINE_DIR}"
mkdir -p "${TEST_DIR}/mnt" "${QUARANTINE_DIR}"

SCENARIO_C_LOG="${LOG_DIR}/scenario_c.log"
"${DAEMON_BIN}" -watch-path "${TEST_DIR}" -stub-clamav -debug > "${SCENARIO_C_LOG}" 2>&1 &
EDR_PID=$!
sleep 1

if ! kill -0 "${EDR_PID}" 2>/dev/null; then
    cat "${SCENARIO_C_LOG}"
    log_fail "Clamguard failed to start in Scenario C"
fi

# 1. Mount tmpfs inside watched subtree
log_info "Mounting tmpfs at ${TEST_DIR}/mnt..."
mount -t tmpfs tmpfs "${TEST_DIR}/mnt"
sleep 0.5

# 2. Access file inside mount to cache it
echo "dynamic mount content" > "${TEST_DIR}/mnt/test.txt"
MNT_READ1=$(cat "${TEST_DIR}/mnt/test.txt")
MNT_READ2=$(cat "${TEST_DIR}/mnt/test.txt")

if [ "${MNT_READ1}" != "dynamic mount content" ] || [ "${MNT_READ2}" != "dynamic mount content" ]; then
    log_fail "Scenario C: Failed to read file on tmpfs mount"
fi

# 3. Unmount tmpfs
log_info "Unmounting ${TEST_DIR}/mnt to trigger watchdog mount detach event..."
umount "${TEST_DIR}/mnt"
sleep 1

# Graceful termination
kill -TERM "${EDR_PID}"
wait "${EDR_PID}" 2>/dev/null || true

# 4. Assertions from logs
if grep -q "Watchdog detected detachment of mount ID:" "${SCENARIO_C_LOG}"; then
    log_pass "Scenario C Assertion 1: Watchdog successfully detected mount detachment event"
else
    cat "${SCENARIO_C_LOG}"
    log_fail "Scenario C Assertion 1: Mount detachment event not detected in logs"
fi

if grep -q "Purging cache entries for device ID:" "${SCENARIO_C_LOG}"; then
    log_pass "Scenario C Assertion 2: Cache entries for detached device ID purged"
else
    cat "${SCENARIO_C_LOG}"
    log_fail "Scenario C Assertion 2: Cache purge log for device ID not found"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo -e "\n${BOLD}${GREEN}==============================================================================${NC}"
echo -e "${BOLD}${GREEN} ALL END-TO-END VERIFICATION SCENARIOS PASSED SUCCESSFULLY!${NC}"
echo -e "${BOLD}${GREEN}==============================================================================${NC}"
