import os
import random
import time
import threading
import bisect
import requests
import concurrent.futures
from datetime import datetime

# ==========================================
# 🎯 全局默认地区设置 (如果想要永久换地区，只改这里！)
# 支持多个地区，用逗号隔开，例如 "SJC,LAX,HKG,FRA,NRT"
# 💡 新手不知道有什么地区？可以直接填 "ALL"，系统会全区盲扫并自动创建所有能扫到的地区子域名！
# ==========================================
DEFAULT_REGIONS = "SJC"

# 🏷️ 地区子域名前缀（可选，默认留空不影响原来的命名）
# 子域名最终会拼成： {SUBDOMAIN_PREFIX}{地区}.{CF_TARGET_DOMAIN}
# 比如地区是 SJC，设置 SUBDOMAIN_PREFIX = "aa" 时，子域名就会变成 aasjc.example.com
# 留空 "" 则和原来一样，就是 sjc.example.com
SUBDOMAIN_PREFIX = "ab"

# 🌐 主域名终极大汇总同步开关
# 设置为 "YES": 开启！将所有扫到的极品节点汇总推送到你的主域名（全球负载均衡）
# 设置为 "NO": 关闭！仅同步到各个地区子域名，不修改主域名的解析记录
SYNC_MAIN_DOMAIN = "NO"

# 🎯 扫描与同步数量设置
SYNC_COUNT = 5       # 每个地区最终要同步几个 IP 到 Cloudflare DNS
ALL_MODE_LIMIT = 20   # ALL 模式下全局总共选几个
MAX_IPS_FILE = 100    # ips-v4.txt 最多保留多少个 IP

# === 网段多样性设置 ===
# 最终筛选时：相同前三段(A.B.C)的IP最多入选 MAX_PER_SUBNET 个（当前=1个）；前两段相同不额外限制
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
# 20% 从历史 /24 热点段抽 -> 命中率最高，最省请求
# 25% 从历史 /16 热点段抽 -> 范围更广，兼顾同一大网段下的新 /24
# 55% 从全量 CF_CIDRS 纯随机抽 -> 唯一能发现全新网段、维持 ips-v4.txt 网段库多样性的来源
HOT_24_WEIGHT = 0.20
HOT_16_WEIGHT = 0.25
# 剩下的 0.60 概率落到全量池，不单独定义变量

# === 轮询覆盖 + 新增网段优先测试 用到的状态文件 ===
# CURSOR_STATE_FILE: 记录 hot_24 / hot_16 两个池子各自"上次轮到哪个网段"，跨运行持久化，
#                     保证按固定顺序轮流选网段时不会因为进程重启就从头开始、导致后面的网段永远轮不到。
# KNOWN_SUBNETS_FILE: 记录截止上次运行结束，脚本已经处理过的 /24 网段全集，
#                      本次运行时跟当前 ips-v4.txt 解析出的网段做差集，找出"新增"的网段优先测试。
CURSOR_STATE_FILE = "subnet_cursor.state"
KNOWN_SUBNETS_FILE = "known_subnets.state"
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

# === 轮询游标的运行期状态 ===
# 每个池子维护一个"下一个要发的位置"下标，多线程并发时靠各自的锁保证每次都拿到不重复的下一个位置。
# 这里存的是内存里的进度；真正跨运行持久化的是"上次发到的具体网段值"（见 CURSOR_STATE_FILE），
# 每次运行开始时用 _init_cursor_index() 把内存下标定位到"上次那个网段"之后，再开始轮询。
_hot24_cursor_lock = threading.Lock()
_hot24_cursor_state = {"idx": 0}
_hot16_cursor_lock = threading.Lock()
_hot16_cursor_state = {"idx": 0}


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


def _unrecord_valid_ip(ip):
    """撤销一次 _record_valid_ip 的记录。用于"新增网段挤占已满名额"时，
    把被顶替下去的旧IP占用的网段配额归还，避免 _subnet24_count 虚高、
    导致那个网段在这次运行剩余时间里被误判为"已满"而被跳过。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return
    key24 = ".".join(parts[:3])
    with _subnet_lock:
        if key24 in _subnet24_count:
            _subnet24_count[key24] -= 1
            if _subnet24_count[key24] <= 0:
                del _subnet24_count[key24]


def _try_replace_full_bucket(bucket, result):
    """某地区的bucket已经凑满 sync_count 时，让"新增网段优先测"的结果强行挤进去，
    替换掉一个旧条目，bucket总长度不变（不突破配额上限）：
      1. 优先替换掉bucket里跟新结果同一个 /24 网段的旧条目——反正同网段最终选择阶段
         (select_diverse_ips, MAX_PER_SUBNET=1) 也只会留1个，谁留下不影响配额计数，
         不需要改 _subnet24_count。
      2. 找不到同网段的旧条目，就替换掉当前延迟最差的那一条，并把它原来占的网段配额
         归还、给新网段登记配额，保证 _subnet24_count 在整个运行期间保持准确。
    bucket为空时说明"凑满"这个前提根本不成立，直接返回 False（防御性判断，理论上不会走到）。
    """
    if not bucket:
        return False

    ip_subnet = ".".join(result["ip"].split(".")[:3])
    for i, existing in enumerate(bucket):
        if ".".join(existing["ip"].split(".")[:3]) == ip_subnet:
            bucket[i] = result
            return True

    worst_idx = max(range(len(bucket)), key=lambda i: bucket[i]["latency"])
    replaced = bucket[worst_idx]
    bucket[worst_idx] = result
    _unrecord_valid_ip(replaced["ip"])
    _record_valid_ip(result["ip"])
    return True


def _try_replace_all_mode(valid_ips_by_region, result, colo):
    """ALL模式下的等价逻辑：全局(不分colo)找同网段的旧条目替换；
    找不到就替换全局延迟最差的那一条。colo 参数用大写后的地区码，
    保证新结果被放进正确大小写的桶里，不产生重复的大小写key。"""
    ip_subnet = ".".join(result["ip"].split(".")[:3])

    for colo_key, lst in valid_ips_by_region.items():
        for i, existing in enumerate(lst):
            if ".".join(existing["ip"].split(".")[:3]) == ip_subnet:
                lst.pop(i)
                valid_ips_by_region.setdefault(colo, []).append(result)
                return True

    worst_colo, worst_idx, worst_latency = None, None, -1
    for colo_key, lst in valid_ips_by_region.items():
        for i, existing in enumerate(lst):
            if existing["latency"] > worst_latency:
                worst_latency = existing["latency"]
                worst_colo, worst_idx = colo_key, i

    if worst_colo is not None:
        replaced = valid_ips_by_region[worst_colo].pop(worst_idx)
        valid_ips_by_region.setdefault(colo, []).append(result)
        _unrecord_valid_ip(replaced["ip"])
        _record_valid_ip(result["ip"])
        return True

    return False


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


def _cidr_sort_key(cidr):
    """把 CIDR 转成可比较的数值元组，用于生成固定顺序（轮询必须依赖稳定顺序，
    否则 set->list 的随机顺序会让"游标位置"失去意义）。"""
    base = cidr.split("/")[0]
    return tuple(int(x) for x in base.split("."))


def _init_cursor_index(sorted_list, last_cidr):
    """根据上次持久化的"最后一个网段"，在当前(可能已变化的)排序列表里定位到它之后的位置，
    作为这次运行轮询的起点。找不到（网段已被挤出列表）就定位到"排序后紧跟在它后面"的位置，
    而不是退回到列表开头——避免前面提到的"总是从头轮、后面的网段永远轮不到"的问题。
    列表为空或没有历史记录时，从0开始。"""
    if not sorted_list or not last_cidr:
        return 0
    try:
        last_key = _cidr_sort_key(last_cidr)
    except Exception:
        return 0
    keys = [_cidr_sort_key(c) for c in sorted_list]
    idx = bisect.bisect_right(keys, last_key)
    return idx % len(sorted_list)


def _final_cursor_cidr(sorted_list, state):
    """根据这次运行结束时内存里的游标下标，反推出"最后一个被轮到的网段"，用于持久化。"""
    if not sorted_list or state["idx"] == 0:
        return None
    n = len(sorted_list)
    idx = (state["idx"] - 1) % n
    return sorted_list[idx]


def init_round_robin_cursors(hot_24_sorted, hot_16_sorted, last_hot24_cidr, last_hot16_cidr):
    """每次运行开始时调用一次：把内存游标定位到上次结束的位置之后。"""
    _hot24_cursor_state["idx"] = _init_cursor_index(hot_24_sorted, last_hot24_cidr)
    _hot16_cursor_state["idx"] = _init_cursor_index(hot_16_sorted, last_hot16_cidr)


def get_final_cursor_cidrs(hot_24_sorted, hot_16_sorted):
    """运行结束时调用一次：取出这次实际轮到的最后一个网段，用于写回状态文件。"""
    return (
        _final_cursor_cidr(hot_24_sorted, _hot24_cursor_state),
        _final_cursor_cidr(hot_16_sorted, _hot16_cursor_state),
    )


def _next_hot24_cidr(sorted_list):
    """轮询选择下一个 /24 热点网段。如果轮到的网段本轮配额已满(_is_cidr_full)，
    跳过它、游标继续往前挪，但不消耗一次测速请求名额；最多尝试一整圈，
    如果全部都满就返回 None，交给调用方回退到全量池。"""
    if not sorted_list:
        return None
    n = len(sorted_list)
    with _hot24_cursor_lock:
        for _ in range(n):
            idx = _hot24_cursor_state["idx"] % n
            _hot24_cursor_state["idx"] += 1
            cidr = sorted_list[idx]
            if not _is_cidr_full(cidr):
                return cidr
        return None


def _next_hot16_cidr(sorted_list):
    """轮询选择下一个 /16 热点网段。/16 本身不限制配额，直接按顺序轮流发。"""
    if not sorted_list:
        return None
    with _hot16_cursor_lock:
        idx = _hot16_cursor_state["idx"] % len(sorted_list)
        _hot16_cursor_state["idx"] += 1
        return sorted_list[idx]


def load_cursor_state(file_path=CURSOR_STATE_FILE):
    """读取上次持久化的轮询游标（hot_24 / hot_16 各自最后轮到的网段）。
    文件不存在或读取失败时返回 (None, None)，等价于"从头开始"。"""
    hot24_cursor, hot16_cursor = None, None
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    val = val.strip()
                    if key == "HOT24":
                        hot24_cursor = val or None
                    elif key == "HOT16":
                        hot16_cursor = val or None
        except Exception as e:
            print(f"Warning: 读取轮询游标状态文件 {file_path} 失败: {e}")
    return hot24_cursor, hot16_cursor


def save_cursor_state(hot24_cursor, hot16_cursor, file_path=CURSOR_STATE_FILE):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"HOT24={hot24_cursor or ''}\n")
            f.write(f"HOT16={hot16_cursor or ''}\n")
    except Exception as e:
        print(f"Warning: 保存轮询游标状态文件 {file_path} 失败: {e}")


def load_known_subnets(file_path=KNOWN_SUBNETS_FILE):
    """读取截止上次运行，已经处理过的 /24 网段全集。文件不存在时视为空集合
    （等价于"这次全部网段都是新增"，第一次跑会全部优先测一轮，属于预期行为）。"""
    known = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        known.add(line)
        except Exception as e:
            print(f"Warning: 读取已知网段状态文件 {file_path} 失败: {e}")
    return known


def save_known_subnets(subnets, file_path=KNOWN_SUBNETS_FILE):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for cidr in sorted(subnets, key=_cidr_sort_key):
                f.write(f"{cidr}\n")
    except Exception as e:
        print(f"Warning: 保存已知网段状态文件 {file_path} 失败: {e}")


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


def generate_random_ip(hot_24_sorted, hot_16_sorted, all_cidrs):
    """
    按权重从三档候选池里抽一个网段，再在网段内随机生成一个IP：
    HOT_24_WEIGHT(20%) 历史/24热点段 / HOT_16_WEIGHT(25%) 历史/16热点段 / 剩余55% 全量CF段。

    档内选择哪一个具体网段，改成"按固定顺序轮流选"(_next_hot24_cidr / _next_hot16_cidr)，
    而不是纯随机 random.choice——纯随机会导致候选网段数量一多，某些网段（尤其是刚加进去的）
    长期抽不到；轮询能保证只要预算/运行次数足够，每个网段迟早都会被选中一次。
    hot_24 档轮到"全局配额已满"的网段会自动跳过（游标继续走），不会浪费测速请求；
    /16 本身不受配额限制，直接按顺序轮流发。
    """
    for _ in range(20):
        try:
            roll = random.random()

            if roll < HOT_24_WEIGHT and hot_24_sorted:
                cidr = _next_hot24_cidr(hot_24_sorted)
                if cidr is None:
                    cidr = random.choice(all_cidrs)
            elif roll < HOT_24_WEIGHT + HOT_16_WEIGHT and hot_16_sorted:
                cidr = _next_hot16_cidr(hot_16_sorted)
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


def _parse_cf_datetime(ts):
    """
    把 Cloudflare 返回的 created_on 时间戳（形如 "2014-01-01T05:20:00.12345Z"，
    小数位数不一定固定，理论上也可能没有小数部分）解析成真正的 datetime 对象，
    用于按时间先后比较，而不是依赖字符串直接比大小（字符串比较在小数位数不一致、
    或某条记录恰好没有小数部分时可能得出错误的先后顺序）。
    解析失败时返回 datetime.min，保证排序仍能正常进行，不会因为个别记录时间戳
    格式异常就让整个同步流程崩掉。
    """
    if not ts:
        return datetime.min
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1]
    if "." in ts:
        main_part, frac_part = ts.split(".", 1)
        frac_part = (frac_part + "000000")[:6]  # 补齐/截断到微秒精度(6位)
    else:
        main_part, frac_part = ts, "000000"
    try:
        dt = datetime.strptime(main_part, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(microsecond=int(frac_part))
    except (ValueError, TypeError):
        return datetime.min


def _fetch_all_dns_records(zone_id, headers, name_filter, record_type="A"):
    """
    分页拉取指定 zone 下、指定 name(域名) + type 的全部DNS记录。
    失败返回 None（调用方据此判断要不要中止）；正常情况返回记录列表（可能为空列表）。
    """
    records = []
    page = 1
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={name_filter}&per_page=100"
    while True:
        resp = requests.get(f"{base_url}&page={page}", headers=headers).json()
        if not resp.get("success"):
            print(f"Failed to fetch DNS records for {name_filter}:", resp)
            return None
        records.extend(resp.get("result", []))
        total_pages = resp.get("result_info", {}).get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1
    return records


def sync_to_cloudflare(api_token, zone_id, target_domain, best_ips, cf_email, sync_count, max_per_subnet=MAX_PER_SUBNET):
    headers = {
        "X-Auth-Email": cf_email,
        "X-Auth-Key": api_token,
        "Content-Type": "application/json"
    }

    print(f"Fetching existing DNS records for {target_domain}...")
    try:
        existing_records = _fetch_all_dns_records(zone_id, headers, target_domain)
        if existing_records is None:
            return False
        # 同时记录每条记录的创建时间，用于"新IP不够数时，优先淘汰最旧的现有记录"
        existing_map = {
            r["content"]: {"id": r["id"], "created_on": r.get("created_on", "")}
            for r in existing_records
        }
        # 按创建时间从新到旧排序：合并时新扫描结果始终优先占位，
        # 现有记录按"最新的先补位"的顺序参与凑数，
        # 这样一旦总数超过 sync_count 名额，被挤掉（删除）的必然是创建时间最早的那些。
        # 用 _parse_cf_datetime 解析成真正的 datetime 再比较，不依赖字符串格式的巧合。
        existing_ips = sorted(
            existing_map.keys(),
            key=lambda ip: _parse_cf_datetime(existing_map[ip]["created_on"]),
            reverse=True,
        )

        final_ips = select_diverse_merged(best_ips, existing_ips, target_count=sync_count, max_per_subnet=max_per_subnet)
        final_set = set(final_ips)

        delete_failures = []
        for ip_val, info in existing_map.items():
            if ip_val not in final_set:
                print(f"Deleting outdated/over-quota IP: {ip_val} (created_on={info['created_on']})")
                del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{info['id']}"
                del_resp = requests.delete(del_url, headers=headers).json()
                if not del_resp.get("success"):
                    print(f"  Warning: 删除 {ip_val} 失败: {del_resp.get('errors')}")
                    delete_failures.append(ip_val)

        add_failures = []
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
                post_resp = requests.post(post_url, headers=headers, json=data).json()
                if not post_resp.get("success"):
                    print(f"  Warning: 添加 {ip_val} 失败: {post_resp.get('errors')}")
                    add_failures.append(ip_val)

        if delete_failures or add_failures:
            print(f"Cloudflare DNS Sync完成，但部分操作失败！删除失败: {delete_failures or '无'}；添加失败: {add_failures or '无'}")
            return False

        print(f"Cloudflare DNS Sync completed successfully! ({len(final_ips)}/{sync_count} records)")
        return True
    except Exception as e:
        print(f"Exception during Cloudflare sync: {e}")
        return False


SUBDOMAIN_PREFIX_STATE_FILE = "subdomain_prefix.state"


def load_last_subdomain_prefix(file_path=SUBDOMAIN_PREFIX_STATE_FILE):
    """
    读取上一次实际生效的 SUBDOMAIN_PREFIX。
    文件不存在时（比如前缀功能刚上线、还没成功跑过一次），说明历史上从来没有过"前缀"这个
    概念，所有子域名此前一直都是无前缀的 region.base_domain 形式——这等价于"上次生效的
    前缀是空字符串"，所以返回 "" 而不是 None。这样主流程才能正确识别出"这次配置的前缀"
    和"历史上隐含的空前缀"不一样，从而触发一次性对齐，把旧的 region.base_domain 记录
    改名搬到新的 prefix+region.base_domain 下，而不是误判成"无历史可比、不用对齐"。
    读取文件出错时同样返回 ""，避免因为读取异常又退回"误判成无需对齐"的老问题。
    """
    if not os.path.exists(file_path):
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"Warning: 读取前缀状态文件 {file_path} 失败: {e}")
        return ""


def save_last_subdomain_prefix(prefix, file_path=SUBDOMAIN_PREFIX_STATE_FILE):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(prefix)
    except Exception as e:
        print(f"Warning: 保存前缀状态文件 {file_path} 失败: {e}")


def align_subdomain_prefix(api_token, zone_id, base_domain, cf_email, old_prefix, new_prefix, regions):
    """
    SUBDOMAIN_PREFIX 发生变化后，一次性把"旧前缀子域名"下的DNS记录改名对齐到"新前缀子域名"，
    只改 name 字段（域名），记录本身的 id / content(IP) / ttl / proxied 都不变，相当于把
    整条记录从旧域名"搬"到新域名下，不会丢失已经积累的IP。

    只处理传进来的 regions 列表覆盖到的地区——也就是这次运行实际扫描到结果的那些地区。
    如果某个地区之前用旧前缀同步过，但这次运行的地区列表(DEFAULT_REGIONS)里已经不包含它了，
    它名下旧前缀的子域名记录不会被这个函数处理到，需要自己去Cloudflare后台手动清理。
    """
    if old_prefix == new_prefix:
        return

    headers = {
        "X-Auth-Email": cf_email,
        "X-Auth-Key": api_token,
        "Content-Type": "application/json"
    }

    for region in regions:
        old_domain = f"{old_prefix}{region.lower()}.{base_domain}"
        new_domain = f"{new_prefix}{region.lower()}.{base_domain}"
        if old_domain == new_domain:
            continue

        old_records = _fetch_all_dns_records(zone_id, headers, old_domain)
        if not old_records:
            continue

        print(f"[Prefix Align] 把 {old_domain} 的 {len(old_records)} 条记录对齐改名到 {new_domain} ...")
        for r in old_records:
            patch_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{r['id']}"
            data = {
                "type": r.get("type", "A"),
                "name": new_domain,
                "content": r.get("content"),
                "ttl": r.get("ttl", 60),
                "proxied": r.get("proxied", False),
            }
            patch_resp = requests.patch(patch_url, headers=headers, json=data).json()
            if patch_resp.get("success"):
                print(f"  已对齐: {r.get('content')}  {old_domain} -> {new_domain}")
            else:
                print(f"  Warning: 对齐失败 {r.get('content')} ({old_domain} -> {new_domain}): {patch_resp.get('errors')}")


def save_ips_to_file(new_best_ips, file_path="ips-v4.txt", max_per_subnet=MAX_PER_SUBNET):
    """
    合并写入，而不是覆盖写入。
    ips-v4.txt 同样遵守网段多样性限制：相同前三段(A.B.C)最多保留 max_per_subnet 个（当前=1个），前两段不限制。
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


def scan_stream(hot_24, hot_16, all_cidrs, check_api_url, target_regions, is_scan_all, sync_count, all_mode_limit, priority_cidrs=None):
    """
    流式扫描：线程池维持恒定并发(CONCURRENCY)，每完成一个测速请求就立刻检查一次状态，
    决定是否需要补一个新任务进去，不再有"轮次/批次"的概念。

    停止条件（满足任一即停）：
      1. 每个目标地区都凑够了 sync_count 个原始命中（ALL模式下是全局凑够 all_mode_limit 个）
      2. 累计发起的测速请求总数达到 TOTAL_REQUEST_LIMIT 硬上限
    但达到停止条件时，如果 priority_cidrs（本次新增网段）对应的测速请求还没跑完，
    不会立刻取消——会先停止补充新的普通候选，等这些"必须等结果"的请求全部完成后才真正停止，
    保证新增网段这次一定能拿到一个真实测试结果，不会被提前 cancel 掉。
    """
    valid_ips_by_region = {} if is_scan_all else {r: [] for r in target_regions}
    total_submitted = 0
    submit_lock = threading.Lock()
    priority_cidrs = priority_cidrs or []

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
        priority_pending = set()
        # priority_futures 跟 priority_pending 不同：这个集合从提交开始就不再删除任何元素，
        # 只用来在结果处理阶段判断"这个已经跑完的future，是不是当初新增网段那批里的"。
        priority_futures = set()

        # 优先批次：本次识别到的新增网段，排在最前面提交，保证真正发起测速请求，
        # 且不占用原有权重抽样逻辑（这里直接在网段内随机生成地址，跟原有 hot_24/hot_16
        # 命中后的处理方式一致，只是网段本身是"指定"的，不是抽签抽中的）。
        for cidr in priority_cidrs[:CONCURRENCY]:
            with submit_lock:
                total_submitted += 1
            ip = _random_ip_from_cidr(cidr)
            fut = executor.submit(test_ip, ip, check_api_url)
            pending.add(fut)
            priority_pending.add(fut)
            priority_futures.add(fut)

        remaining_slots = CONCURRENCY - len(pending)
        for _ in range(max(remaining_slots, 0)):
            fut = try_submit(executor)
            if fut:
                pending.add(fut)

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)

            for fut in done:
                priority_pending.discard(fut)
                is_priority = fut in priority_futures
                result = fut.result()
                if result:
                    ip = result["ip"]
                    colo = result.get("colo", "UNK").upper()
                    if colo != "UNK" and (is_scan_all or colo in target_regions):
                        if is_scan_all:
                            total_now = sum(len(v) for v in valid_ips_by_region.values())
                            if total_now < all_mode_limit:
                                bucket = valid_ips_by_region.setdefault(colo, [])
                                bucket.append(result)
                                _record_valid_ip(ip)
                                print(f"[FOUND {colo}] {ip} (Total ALL: {total_now + 1}/{all_mode_limit})")
                            elif is_priority:
                                # 名额已经凑满，但这是新增网段的结果——挤掉一个旧条目也要把它留下
                                if _try_replace_all_mode(valid_ips_by_region, result, colo):
                                    _record_valid_ip(ip)
                                    print(f"[FOUND {colo}] {ip} (新增网段挤占名额，Total ALL 仍为 {all_mode_limit})")
                        else:
                            bucket = valid_ips_by_region.setdefault(colo, [])
                            if len(bucket) < sync_count:
                                bucket.append(result)
                                _record_valid_ip(ip)
                                print(f"[FOUND {colo}] {ip} (Total {colo}: {len(bucket)}/{sync_count})")
                            elif is_priority:
                                # 名额已经凑满，但这是新增网段的结果——挤掉一个旧条目也要把它留下
                                if _try_replace_full_bucket(bucket, result):
                                    print(f"[FOUND {colo}] {ip} (新增网段挤占名额，Total {colo} 仍为 {sync_count})")

            stop_requested = is_done() or total_submitted >= TOTAL_REQUEST_LIMIT
            if stop_requested and not priority_pending:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            if stop_requested:
                # 已经达到停止条件，但新增网段的优先请求还没出结果：
                # 不再补充新的普通候选，只等这些"必须等结果"的请求完成。
                continue

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
    if not check_api_url:
        print("Error: 未设置环境变量 CHECK_API_URL（测速检测接口地址），扫描无法进行，直接退出。")
        exit(1)
    sync_count = SYNC_COUNT

    hot_24, hot_16 = load_hot_subnets("ips-v4.txt")
    print(f"Loaded {len(hot_24)} hot /24 subnets and {len(hot_16)} hot /16 subnets from ips-v4.txt for weighted scanning.")

    # 固定顺序排序，供轮询使用（set->list 顺序不稳定，轮询必须依赖确定性顺序）
    hot_24_set = set(hot_24)
    hot_24_sorted = sorted(hot_24_set, key=_cidr_sort_key)
    hot_16_sorted = sorted(set(hot_16), key=_cidr_sort_key)

    # 轮询游标：读取上次持久化的位置，定位这次的起点（跨运行推进，不会从头开始）
    last_hot24_cursor, last_hot16_cursor = load_cursor_state()
    init_round_robin_cursors(hot_24_sorted, hot_16_sorted, last_hot24_cursor, last_hot16_cursor)

    # 新增网段识别：跟上次已知网段集合做差集，找出这次相对上次新出现的网段（不管是
    # 手动加进 ips-v4.txt 的，还是上次运行自己扫到写进去的），本轮优先测试。
    # 一次最多优先测 CONCURRENCY 个（对应初始批次的名额上限），处理不完的这次先不标记为
    # "已知"，下次运行还会继续被当作新增、有机会补测到。
    known_subnets = load_known_subnets()
    new_subnets_all = hot_24_set - known_subnets
    priority_cidrs = sorted(new_subnets_all, key=_cidr_sort_key)[:CONCURRENCY]
    if new_subnets_all:
        print(f"检测到 {len(new_subnets_all)} 个新增网段，本次优先测试其中 {len(priority_cidrs)} 个: {priority_cidrs}")

    can_sync = True
    if not all([api_token, zone_id, base_domain, cf_email]):
        print("Warning: Missing required environment variables (CF_API_TOKEN, CF_ZONE_ID, CF_TARGET_DOMAIN, CF_EMAIL).")
        print("DNS Synchronization will be skipped, but IP scanning will still proceed!")
        can_sync = False

    print(f"Starting streaming scan (concurrency={CONCURRENCY}, total request cap={TOTAL_REQUEST_LIMIT})...")
    valid_ips_by_region, total_submitted = scan_stream(
        hot_24_sorted, hot_16_sorted, CF_CIDRS, check_api_url,
        target_regions, is_scan_all, sync_count, ALL_MODE_LIMIT,
        priority_cidrs=priority_cidrs
    )

    # 保存轮询游标 + 已知网段状态：必须放在下面 total_found==0 触发 exit(1) 之前，
    # 保证不管这次扫描有没有找到有效IP，这两个状态都会落盘，不会因为提前退出而丢失进度
    # （这两个文件记录的是"脚本内部处理进度"，跟"这次扫描业务上有没有结果"是两回事）。
    hot24_final_cursor, hot16_final_cursor = get_final_cursor_cidrs(hot_24_sorted, hot_16_sorted)
    save_cursor_state(hot24_final_cursor, hot16_final_cursor)
    known_next = (hot_24_set - new_subnets_all) | set(priority_cidrs)
    save_known_subnets(known_next)

    print("\nScan completed. Summary:")
    total_found = 0
    all_best_ips = []

    # === SUBDOMAIN_PREFIX 一次性对齐 ===
    # 只在检测到"这次配置的前缀"和"上次实际生效的前缀"不一样时才触发，且只对齐一次：
    # 对齐后无论有没有触发改名，都会把当前前缀写入状态文件作为新基准，下次运行前缀没变就不会再重复对齐。
    # load_last_subdomain_prefix() 在状态文件不存在时返回 ""（等价于"历史上一直是空前缀"），
    # 而不是 None，所以这里不需要再单独处理"没有历史记录"的情况。
    if can_sync:
        last_prefix = load_last_subdomain_prefix()
        if last_prefix != SUBDOMAIN_PREFIX:
            print(f"\n检测到 SUBDOMAIN_PREFIX 从 \"{last_prefix}\" 改成了 \"{SUBDOMAIN_PREFIX}\"，开始一次性对齐DNS记录名称...")
            align_subdomain_prefix(
                api_token, zone_id, base_domain, cf_email,
                last_prefix, SUBDOMAIN_PREFIX, list(valid_ips_by_region.keys())
            )
        save_last_subdomain_prefix(SUBDOMAIN_PREFIX)
    # can_sync 为 False 时（没配CF凭证）不做对齐，也不更新状态文件——
    # 这样等以后配置好凭证再跑，仍然能检测到这次的前缀变化并补做对齐。

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
            target_domain = f"{SUBDOMAIN_PREFIX}{region.lower()}.{base_domain}"
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
