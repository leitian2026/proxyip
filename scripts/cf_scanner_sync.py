import os
import random
import time
import threading
import requests
import concurrent.futures
from datetime import datetime, timedelta, timezone

# ==========================================
# 🎯 全局默认地区设置 (如果想要永久换地区，只改这里！)
# 支持多个地区，用逗号隔开，例如 "SJC,LAX,HKG,FRA,NRT"
# 💡 新手不知道有什么地区？可以直接填 "ALL"，系统会全区盲扫并自动创建所有能扫到的地区子域名！
# ==========================================
DEFAULT_REGIONS = "SJC"

# 🌐 主域名终极大汇总同步开关
# 设置为 "YES": 开启！将所有扫到的极品节点汇总推送到你的主域名（全球负载均衡）
# 设置为 "NO": 关闭！仅同步到各个地区子域名，不修改主域名的解析记录
SYNC_MAIN_DOMAIN = "NO"

# 🎯 扫描与同步数量设置
SYNC_COUNT = 10       # 每个地区最终要同步几个 IP 到 Cloudflare DNS
ALL_MODE_LIMIT = 20   # ALL 模式下全局总共选几个
MAX_IPS_FILE = 100    # ips-v4.txt 最多保留多少个 IP

# === 网段多样性设置 ===
# 最终筛选时：相同前三段(A.B.C)的IP最多入选2个；前两段相同不额外限制
# 避免最终同步出去的 IP 全部挤在同一个 /24 网段（同一条线路/同一机房），起不到冗余作用
MAX_PER_SUBNET = 1

# === 扫描资源上限设置（取代原来的 SCAN_COUNT / max_attempts 轮次概念）===
# 现在是"流式扫描"：线程池维持恒定并发数，每完成一个就检查一次状态，
# 不再有"一批测2000个、测完再看下一批"这种轮次划分。
CONCURRENCY = 50             # 同时并发的测速请求数（已验证稳定运行多日，不再收紧）
TOTAL_REQUEST_LIMIT = 20000  # 整个扫描阶段最多发起多少次测速请求（硬上限，沿用原来"批次x轮次"的隐含总量；
                             # 不管有没有凑够数，达到这个数就无条件停止扫描）

# === 热点网段候选权重（取代原来单一的 /24 热点段）===
# 同时维护 /24、/16 两种粒度的历史热点网段，生成随机 IP 时按权重从三档里抽：
# 60% 从历史 /24 热点段抽 -> 命中率最高，最省请求
# 25% 从历史 /16 热点段抽 -> 范围更广，兼顾同一大网段下的新 /24
# 15% 从全量 CF_CIDRS 纯随机抽 -> 唯一能发现全新网段、维持 ips-v4.txt 网段库多样性的来源
HOT_24_WEIGHT = 0.60
HOT_16_WEIGHT = 0.25
# 剩下的 0.15 概率落到全量池，不单独定义变量
# ==========================================

    # === Cloudflare IPv4 Ranges (IP段配置区) ===
    # 现在完全从根目录的 ip.txt 文件读取
def load_cf_cidrs(file_path="ip.txt"):
    if not os.path.exists(file_path):
        print(f"Error: 找不到 {file_path} 文件！请确保该文件存在并填写了需要扫描的 IP 段。")
        exit(1)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            cidrs = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        if not cidrs:
            print(f"Error: {file_path} 文件为空！请在里面填入需要扫描的网段 (CIDR)。")
            exit(1)
        return cidrs
    except Exception as e:
        print(f"Error: 读取 {file_path} 失败！错误信息: {e}")
        exit(1)

CF_CIDRS = load_cf_cidrs()
    # ==========================================


# === 全局网段配额计数 ===
# 用于生成阶段实时排除"已经测满的 /24 网段"，避免浪费请求。
# 采用全局口径：不区分地区(colo)，只要前三段网段全局已经收集到 MAX_PER_SUBNET 个
# 被实际采纳的有效IP，后续生成候选IP时就主动跳过这个 /24 网段。
_subnet_lock = threading.Lock()
_subnet24_count = {}
_subnet16_count = {}


def _is_cidr_full(cidr):
    """判断一个 /24 CIDR 网段是否已经达到全局配额上限；/16 不限制。"""
    try:
        base, prefix = cidr.split("/")
        prefix = int(prefix)
    except Exception:
        return False
    parts = base.split(".")
    if len(parts) < 3:
        return False
    if prefix == 24:
        with _subnet_lock:
            key24 = ".".join(parts[:3])
            return _subnet24_count.get(key24, 0) >= MAX_PER_SUBNET
    return False


def _record_valid_ip(ip):
    """一个IP被实际采纳进某地区候选池时调用，更新全局 /24 网段配额计数。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return
    key24 = ".".join(parts[:3])
    with _subnet_lock:
        _subnet24_count[key24] = _subnet24_count.get(key24, 0) + 1


def load_hot_subnets(file_path="ips-v4.txt"):
    """从历史结果文件里提取 /24 和 /16 两种粒度的热点网段（用于生成阶段加权抽样）"""
    hot_24, hot_16 = set(), set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ip_str = line.split("#")[0].strip()
                    parts = ip_str.split(".")
                    if len(parts) == 4:
                        hot_24.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
                        hot_16.add(f"{parts[0]}.{parts[1]}.0.0/16")
        except Exception as e:
            print(f"Warning: 读取历史热点网段失败: {e}")
    return list(hot_24), list(hot_16)


def _random_ip_from_cidr(cidr):
    """在给定的单个 CIDR 网段内随机生成一个 IP"""
    if '/' in cidr:
        base_ip, prefix = cidr.split('/')
        prefix = int(prefix)
    else:
        base_ip = cidr
        prefix = 32

    parts = list(map(int, base_ip.split('.')))
    if len(parts) != 4:
        raise ValueError(f"Invalid CIDR: {cidr}")

    ip_long = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    host_bits = 32 - prefix
    mask = (1 << host_bits) - 1
    random_host = random.randint(0, mask)
    final_ip_long = (ip_long & ~mask) | random_host

    p1 = (final_ip_long >> 24) & 255
    p2 = (final_ip_long >> 16) & 255
    p3 = (final_ip_long >> 8) & 255
    p4 = final_ip_long & 255
    return f"{p1}.{p2}.{p3}.{p4}"


def generate_random_ip(hot_24_cidrs, hot_16_cidrs, all_cidrs):
    """
    按权重从三档候选池里抽一个网段，再在网段内随机生成一个IP：
    60% 历史/24热点段 / 25% 历史/16热点段 / 15% 全量CF段。
    抽样时会主动跳过"全局配额已满"的热点 /24 网段，避免生成注定会在筛选阶段被
    丢弃的候选，节省测速请求；/16 本身不受2个限制。
    """
    for _ in range(20):
        try:
            roll = random.random()

            if roll < HOT_24_WEIGHT and hot_24_cidrs:
                pool = [c for c in hot_24_cidrs if not _is_cidr_full(c)]
                cidr = random.choice(pool) if pool else random.choice(all_cidrs)
            elif roll < HOT_24_WEIGHT + HOT_16_WEIGHT and hot_16_cidrs:
                cidr = random.choice(hot_16_cidrs)
            else:
                cidr = random.choice(all_cidrs)

            return _random_ip_from_cidr(cidr)
        except Exception:
            continue

    return "1.1.1.1"


def test_ip(ip, check_api_url, timeout=5.0):
    start_time = time.time()
    try:
        url = f"{check_api_url}?proxyip={ip}"
        resp = requests.get(url, timeout=timeout).json()
        if resp.get("success") is True:
            connect_time = int((time.time() - start_time) * 1000)
            colo = resp.get("dataCenter") or resp.get("colo") or resp.get("country") or "UNK"
            latency = resp.get("latencyMs") or resp.get("tcpDuration") or connect_time
            return {"ip": ip, "latency": latency, "colo": colo}
    except Exception:
        pass
    return None


def select_diverse_ips(sorted_ips, limit, max_per_subnet=MAX_PER_SUBNET):
    """
    从按延迟排好序的IP列表里挑最终名单：
    相同前三段(A.B.C)的IP最多选 max_per_subnet 个；前两段(A.B)相同不限制。
    """
    selected = []
    count24 = {}
    for item in sorted_ips:
        parts = item["ip"].split(".")
        if len(parts) != 4:
            continue
        key24 = ".".join(parts[:3])
        if count24.get(key24, 0) >= max_per_subnet:
            continue
        selected.append(item)
        count24[key24] = count24.get(key24, 0) + 1
        if len(selected) >= limit:
            break
    return selected


def select_diverse_merged(new_items, existing_ips, target_count, max_per_subnet=MAX_PER_SUBNET):
    """
    把"本次新测出的结果"(new_items，需已按延迟从低到高排序，优先级更高)
    和 "Cloudflare上现有的旧记录"(existing_ips，纯IP字符串，优先级较低)放在一起，
    按前三段(A.B.C)配额选出最终名单：每个 /24 最多 max_per_subnet 个，前两段不限制。
    """
    new_ip_order = [item["ip"] for item in new_items]
    new_ip_set = set(new_ip_order)
    ordered_ips = new_ip_order + [ip for ip in existing_ips if ip not in new_ip_set]

    kept = []
    count24 = {}
    for ip in ordered_ips:
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        key24 = ".".join(parts[:3])
        if count24.get(key24, 0) >= max_per_subnet:
            continue
        kept.append(ip)
        count24[key24] = count24.get(key24, 0) + 1
        if len(kept) >= target_count:
            break
    return kept


def sync_to_cloudflare(api_token, zone_id, target_domain, best_ips, cf_email, sync_count, max_per_subnet=MAX_PER_SUBNET):
    headers = {
        "X-Auth-Email": cf_email,
        "X-Auth-Key": api_token,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={target_domain}"

    print(f"Fetching existing DNS records for {target_domain}...")
    try:
        resp = requests.get(url, headers=headers).json()
        if not resp.get("success"):
            print("Failed to fetch DNS records:", resp)
            return False

        existing_records = resp.get("result", [])
        existing_map = {r["content"]: r["id"] for r in existing_records}
        existing_ips = list(existing_map.keys())

        final_ips = select_diverse_merged(best_ips, existing_ips, target_count=sync_count, max_per_subnet=max_per_subnet)
        final_set = set(final_ips)

        for ip_val, record_id in existing_map.items():
            if ip_val not in final_set:
                print(f"Deleting outdated/over-quota IP: {ip_val}")
                del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
                requests.delete(del_url, headers=headers)

        for ip_val in final_ips:
            if ip_val not in existing_map:
                print(f"Adding new IP: {ip_val}")
                post_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                data = {
                    "type": "A",
                    "name": target_domain,
                    "content": ip_val,
                    "ttl": 60,
                    "proxied": False
                }
                requests.post(post_url, headers=headers, json=data)

        print(f"Cloudflare DNS Sync completed successfully! ({len(final_ips)}/{sync_count} records)")
        return True
    except Exception as e:
        print(f"Exception during Cloudflare sync: {e}")
        return False


def save_ips_to_file(new_best_ips, file_path="ips-v4.txt", max_per_subnet=MAX_PER_SUBNET):
    """
    合并写入，而不是覆盖写入。
    ips-v4.txt 同样遵守网段多样性限制：相同前三段(A.B.C)最多保留2个，前两段不限制。
    同一个IP以本次结果刷新地区备注；历史文件中已经超过限制的旧IP也会被清理。
    """
    existing = {}
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if "#" in line:
                        ip_part, colo_part = line.split("#", 1)
                    else:
                        ip_part, colo_part = line, "UNK"
                    existing[ip_part.strip()] = colo_part.strip()
        except Exception as e:
            print(f"Warning: 读取历史 {file_path} 失败，将只写入本次结果: {e}")

    before_count = len(existing)

    new_sorted = sorted(new_best_ips, key=lambda x: x["latency"])
    new_ip_order = []
    new_ip_set = set()
    count24 = {}

    for item in new_sorted:
        ip = item["ip"]
        if ip in new_ip_set:
            continue
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        key24 = ".".join(parts[:3])
        if count24.get(key24, 0) >= max_per_subnet:
            continue
        new_ip_order.append(ip)
        new_ip_set.add(ip)
        count24[key24] = count24.get(key24, 0) + 1
        existing[ip] = item["colo"]

    kept = list(new_ip_order)
    kept_set = set(kept)

    for ip in existing:
        if ip in kept_set:
            continue
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        key24 = ".".join(parts[:3])
        if count24.get(key24, 0) >= max_per_subnet:
            continue
        kept.append(ip)
        kept_set.add(ip)
        count24[key24] = count24.get(key24, 0) + 1

    # 限制 ips-v4.txt 总数量：本次新结果优先，历史IP仅用于补足剩余名额
    kept = kept[:MAX_IPS_FILE]

    # 按前三段分组排序：同一个 /24 的IP连续放在一起；/24之间按数字顺序排列
    kept.sort(key=lambda ip: tuple(map(int, ip.split("."))))

    with open(file_path, "w", encoding="utf-8") as f:
        for ip in kept:
            f.write(f"{ip}#{existing[ip]}\n")

    print(f"Merged IPs into {file_path}: {before_count} historical + this run -> {len(kept)} total (max {max_per_subnet} per /24, max {MAX_IPS_FILE} total).")


def scan_stream(hot_24, hot_16, all_cidrs, check_api_url, target_regions, is_scan_all, sync_count, all_mode_limit):
    """
    流式扫描：线程池维持恒定并发(CONCURRENCY)，每完成一个测速请求就立刻检查一次状态，
    决定是否需要补一个新任务进去，不再有"轮次/批次"的概念。

    停止条件（满足任一即停）：
      1. 每个目标地区都凑够了 sync_count 个原始命中（ALL模式下是全局凑够 all_mode_limit 个）
      2. 累计发起的测速请求总数达到 TOTAL_REQUEST_LIMIT 硬上限
    """
    valid_ips_by_region = {} if is_scan_all else {r: [] for r in target_regions}
    total_submitted = 0
    submit_lock = threading.Lock()

    def is_done():
        if is_scan_all:
            return sum(len(v) for v in valid_ips_by_region.values()) >= all_mode_limit
        return all(len(valid_ips_by_region.get(r, [])) >= sync_count for r in target_regions)

    def try_submit(executor):
        nonlocal total_submitted
        with submit_lock:
            if total_submitted >= TOTAL_REQUEST_LIMIT:
                return None
            total_submitted += 1
        ip = generate_random_ip(hot_24, hot_16, all_cidrs)
        return executor.submit(test_ip, ip, check_api_url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        pending = set()
        for _ in range(CONCURRENCY):
            fut = try_submit(executor)
            if fut:
                pending.add(fut)

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)

            for fut in done:
                result = fut.result()
                if result:
                    ip = result["ip"]
                    colo = result.get("colo", "UNK").upper()
                    if colo != "UNK" and (is_scan_all or colo in target_regions):
                        bucket = valid_ips_by_region.setdefault(colo, [])
                        if is_scan_all:
                            total_now = sum(len(v) for v in valid_ips_by_region.values())
                            if total_now < all_mode_limit:
                                bucket.append(result)
                                _record_valid_ip(ip)
                                print(f"[FOUND {colo}] {ip} (Total ALL: {total_now + 1}/{all_mode_limit})")
                        else:
                            if len(bucket) < sync_count:
                                bucket.append(result)
                                _record_valid_ip(ip)
                                print(f"[FOUND {colo}] {ip} (Total {colo}: {len(bucket)}/{sync_count})")

            if is_done() or total_submitted >= TOTAL_REQUEST_LIMIT:
                executor.shutdown(wait=False, cancel_futures=True)
                break

            slots = CONCURRENCY - len(pending)
            for _ in range(max(slots, 0)):
                fut = try_submit(executor)
                if fut is None:
                    break
                pending.add(fut)

    print(f"\n本次扫描共发起 {total_submitted} 次测速请求（硬上限 {TOTAL_REQUEST_LIMIT}）。")
    return valid_ips_by_region, total_submitted


def main():
    api_token = os.environ.get("CF_API_TOKEN")
    zone_id = os.environ.get("CF_ZONE_ID")
    base_domain = os.environ.get("CF_TARGET_DOMAIN")
    cf_email = os.environ.get("CF_EMAIL")

    region_input = DEFAULT_REGIONS
    target_regions = [r.strip().upper() for r in region_input.split(",") if r.strip()]
    is_scan_all = "ALL" in target_regions

    if is_scan_all:
        print(f"Target Regions dynamically set to: ALL (Global Scan Mode)")
    else:
        print(f"Target Regions dynamically set to: {target_regions}")

    check_api_url = os.environ.get("CHECK_API_URL")
    sync_count = SYNC_COUNT

    hot_24, hot_16 = load_hot_subnets("ips-v4.txt")
    print(f"Loaded {len(hot_24)} hot /24 subnets and {len(hot_16)} hot /16 subnets from ips-v4.txt for weighted scanning.")

    can_sync = True
    if not all([api_token, zone_id, base_domain, cf_email]):
        print("Warning: Missing required environment variables (CF_API_TOKEN, CF_ZONE_ID, CF_TARGET_DOMAIN, CF_EMAIL).")
        print("DNS Synchronization will be skipped, but IP scanning will still proceed!")
        can_sync = False

    print(f"Starting streaming scan (concurrency={CONCURRENCY}, total request cap={TOTAL_REQUEST_LIMIT})...")
    valid_ips_by_region, total_submitted = scan_stream(
        hot_24, hot_16, CF_CIDRS, check_api_url,
        target_regions, is_scan_all, sync_count, ALL_MODE_LIMIT
    )

    print("\nScan completed. Summary:")
    total_found = 0
    all_best_ips = []

    for region, ips in valid_ips_by_region.items():
        print(f"- {region}: {len(ips)} valid IPs found")
        if not ips:
            print(f"  Warning: No IPs found for {region}")
            continue

        total_found += len(ips)
        ips.sort(key=lambda x: x["latency"])

        limit = ALL_MODE_LIMIT if is_scan_all else sync_count
        best_ips = select_diverse_ips(ips, limit)
        all_best_ips.extend(best_ips)

        print(f"\n--- Top {len(best_ips)} Diversity-Limited IPs Selected for {region} ---")
        for ip in best_ips:
            print(f"IP: {ip['ip']:<15} | Latency: {ip['latency']:>3}ms | Colo: {ip['colo']}")

        if can_sync:
            target_domain = f"{region.lower()}.{base_domain}"
            print(f"\nStarting Cloudflare DNS Sync for {target_domain}...")
            sync_to_cloudflare(api_token, zone_id, target_domain, best_ips, cf_email, sync_count=sync_count)
        else:
            print(f"\nSkipping Cloudflare DNS Sync for {region} (Missing Credentials).")

    if can_sync and all_best_ips:
        if SYNC_MAIN_DOMAIN.strip().upper() == "YES":
            all_best_ips.sort(key=lambda x: x["latency"])
            print(f"\n[Global Sync] Starting Cloudflare DNS Sync for MAIN DOMAIN: {base_domain}")
            sync_to_cloudflare(api_token, zone_id, base_domain, all_best_ips, cf_email, sync_count=len(all_best_ips))
        else:
            print(f"\n[Global Sync] Skipped synchronizing to MAIN DOMAIN ({base_domain}) because SYNC_MAIN_DOMAIN is set to NO.")

    if total_found == 0:
        print("No valid IPs found in this scan across any regions. Aborting.")
        exit(1)

    if all_best_ips:
        save_ips_to_file(all_best_ips)


if __name__ == "__main__":
    main()
