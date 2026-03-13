#!/usr/bin/env python3
"""
测试脚本：验证空闲服务器强制回收功能

测试场景：
1. 模拟服务器空闲
2. 验证强制回收（force=True）能够回收空闲服务器
3. 验证非强制回收（force=False）在未达上限时不回收
"""

import sys
import asyncio
import time
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.server_manager import OpenCodeServerManager

class MockProcess:
    """模拟异步进程"""
    def __init__(self):
        self.returncode = None  # 进程运行中

async def test_eviction_logic():
    """测试回收逻辑"""
    print("=" * 60)
    print("测试：空闲服务器强制回收逻辑")
    print("=" * 60)
    
    # 创建测试用ServerManager
    manager = OpenCodeServerManager(
        max_active_servers=5,
        hostname="127.0.0.1"
    )
    
    # 模拟3个服务器运行（未达上限）
    manager._servers = {
        "/test/service1": {
            "process": MockProcess(),
            "port": 8001,
            "stderr_task": None,
            "last_accessed": time.time() - 700,  # 700秒前访问
            "idle_since": time.time() - 700       # 空闲700秒
        },
        "/test/service2": {
            "process": MockProcess(),
            "port": 8002,
            "stderr_task": None,
            "last_accessed": time.time() - 500,  # 500秒前访问
            "idle_since": time.time() - 500       # 空闲500秒
        },
        "/test/service3": {
            "process": MockProcess(),
            "port": 8003,
            "stderr_task": None,
            "last_accessed": time.time() - 300,  # 300秒前访问
            "idle_since": time.time() - 300       # 空闲300秒
        }
    }
    
    print(f"\n初始状态:")
    print(f"  - 服务器数量: {len(manager._servers)}")
    print(f"  - 上限: {manager.max_active_servers}")
    print(f"  - 未达上限: {len(manager._servers)} < {manager.max_active_servers}")
    
    # 测试1：非强制回收（未达上限，不应回收）
    print("\n测试1：非强制回收（force=False）...")
    evicted = await manager.evict_idle_servers(force=False)
    print(f"  回收数量: {evicted}")
    print(f"  剩余服务器: {len(manager._servers)}")
    
    if evicted == 0:
        print("  ✅ 正确：未达上限时不回收")
    else:
        print("  ❌ 错误：未达上限时不应回收")
        return False
    
    # 测试2：强制回收（应该回收）
    print("\n测试2：强制回收（force=True）...")
    evicted = await manager.evict_idle_servers(force=True)
    print(f"  回收数量: {evicted}")
    print(f"  剩余服务器: {len(manager._servers)}")
    
    if evicted == 1:
        print("  ✅ 正确：强制回收了1个服务器")
    else:
        print("  ❌ 错误：强制回收应该回收1个服务器")
        return False
    
    # 测试3：再次强制回收
    print("\n测试3：再次强制回收（force=True）...")
    evicted = await manager.evict_idle_servers(force=True)
    print(f"  回收数量: {evicted}")
    print(f"  剩余服务器: {len(manager._servers)}")
    
    if evicted == 1:
        print("  ✅ 正确：再次回收1个服务器")
    else:
        print("  ❌ 错误：应该还能回收1个服务器")
        return False
    
    # 测试4：强制回收剩余服务器
    print("\n测试4：强制回收所有剩余服务器...")
    total_evicted = 0
    while len(manager._servers) > 0:
        evicted = await manager.evict_idle_servers(force=True)
        total_evicted += evicted
        print(f"  本轮回收: {evicted}, 剩余: {len(manager._servers)}")
    
    print(f"  总计回收: {total_evicted}")
    
    if total_evicted == 1:  # 剩余1个
        print("  ✅ 正确：回收了所有剩余服务器")
    else:
        print("  ❌ 错误：回收数量不正确")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 所有测试通过！")
    print("=" * 60)
    return True

async def main():
    """运行测试"""
    try:
        success = await test_eviction_logic()
        return 0 if success else 1
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
