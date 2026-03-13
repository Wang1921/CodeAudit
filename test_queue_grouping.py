#!/usr/bin/env python3
"""
测试脚本：验证队列分组和智能调度功能

测试场景：
1. 测试A2ABusManager的队列分组
2. 测试get_pending_tasks的优先队列逻辑
3. 验证任务写入和读取的正确性
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.a2a_bus import A2ABusManager

def test_queue_grouping():
    """测试队列分组功能"""
    print("=" * 60)
    print("测试1：队列分组功能")
    print("=" * 60)
    
    # 创建临时测试目录
    test_dir = tempfile.mkdtemp(prefix="a2a_test_")
    print(f"测试目录: {test_dir}")
    
    try:
        # 初始化A2ABusManager
        bus = A2ABusManager(test_dir)
        
        # 写入不同微服务的任务
        print("\n写入测试任务...")
        
        # 写入全局队列任务
        task1_path = bus.write_message(
            message_type="TaskRequest",
            task_id="GLOBAL-001",
            sender="System",
            recipient="Coordinator",
            payload={"action": "test"},
            service_name="global"
        )
        print(f"  → 写入全局队列: {os.path.basename(task1_path)}")
        
        # 写入微服务A任务
        task2_path = bus.write_message(
            message_type="TaskRequest",
            task_id="SVC1-001",
            sender="SemgrepScanner",
            recipient="ReverseTracer",
            payload={"action": "test"},
            service_name="user-service"
        )
        print(f"  → 写入 user-service 队列: {os.path.basename(task2_path)}")
        
        # 写入微服务B任务
        task3_path = bus.write_message(
            message_type="TaskRequest",
            task_id="SVC2-001",
            sender="SemgrepScanner",
            recipient="ReverseTracer",
            payload={"action": "test"},
            service_name="processor-service"
        )
        print(f"  → 写入 processor-service 队列: {os.path.basename(task3_path)}")
        
        # 检查队列目录结构
        queues_dir = os.path.join(test_dir, ".a2a_bus", "queues")
        print("\n队列目录结构:")
        for root, dirs, files in os.walk(queues_dir):
            level = root.replace(queues_dir, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f'{indent}{os.path.basename(root)}/')
            subindent = ' ' * 2 * (level + 1)
            for f in files:
                print(f'{subindent}{f}')
        
        # 验证写入
        assert os.path.exists(task1_path), "全局任务未写入"
        assert os.path.exists(task2_path), "user-service任务未写入"
        assert os.path.exists(task3_path), "processor-service任务未写入"
        
        print("\n✅ 队列分组测试通过！")
        return True
        
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        return False
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\n清理测试目录: {test_dir}")

def test_preferred_queue():
    """测试优先队列调度"""
    print("\n" + "=" * 60)
    print("测试2：优先队列调度")
    print("=" * 60)
    
    # 创建临时测试目录
    test_dir = tempfile.mkdtemp(prefix="a2a_test_")
    print(f"测试目录: {test_dir}")
    
    try:
        bus = A2ABusManager(test_dir)
        
        # 写入多个微服务的任务
        print("\n写入测试任务...")
        for i in range(3):
            bus.write_message(
                message_type="TaskRequest",
                task_id=f"USER-SVC-{i:03d}",
                sender="SemgrepScanner",
                recipient="ReverseTracer",
                payload={"action": f"test_{i}"},
                service_name="user-service"
            )
        
        for i in range(2):
            bus.write_message(
                message_type="TaskRequest",
                task_id=f"PROC-SVC-{i:03d}",
                sender="SemgrepScanner",
                recipient="ReverseTracer",
                payload={"action": f"test_{i}"},
                service_name="processor-service"
            )
        
        print("  → user-service: 3个任务")
        print("  → processor-service: 2个任务")
        
        # 测试1：无优先级，轮询获取
        print("\n测试轮询获取（无优先级）...")
        task_pairs = bus.get_pending_tasks()
        print(f"  获取到 {len(task_pairs)} 个任务")
        for filepath, service_name in task_pairs:
            print(f"    - {service_name}: {os.path.basename(filepath)}")
        
        # 验证任务已从队列移到processing
        queues_dir = os.path.join(test_dir, ".a2a_bus", "queues")
        user_svc_queue = os.path.join(queues_dir, "user-service")
        proc_svc_queue = os.path.join(queues_dir, "processor-service")
        
        user_svc_count = len([f for f in os.listdir(user_svc_queue) if f.endswith('.json')])
        proc_svc_count = len([f for f in os.listdir(proc_svc_queue) if f.endswith('.json')])
        
        print(f"  队列剩余: user-service={user_svc_count}, processor-service={proc_svc_count}")
        
        # 测试2：有优先级，优先从指定队列获取
        print("\n测试优先获取（指定 processor-service）...")
        task_pairs = bus.get_pending_tasks(preferred_services=["processor-service"])
        print(f"  获取到 {len(task_pairs)} 个任务")
        for filepath, service_name in task_pairs:
            print(f"    - {service_name}: {os.path.basename(filepath)}")
        
        # 验证优先队列被优先消耗
        user_svc_count = len([f for f in os.listdir(user_svc_queue) if f.endswith('.json')])
        proc_svc_count = len([f for f in os.listdir(proc_svc_queue) if f.endswith('.json')])
        
        print(f"  队列剩余: user-service={user_svc_count}, processor-service={proc_svc_count}")
        
        print("\n✅ 优先队列调度测试通过！")
        return True
        
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\n清理测试目录: {test_dir}")

def test_backward_compatibility():
    """测试向后兼容性"""
    print("\n" + "=" * 60)
    print("测试3：向后兼容性")
    print("=" * 60)
    
    test_dir = tempfile.mkdtemp(prefix="a2a_test_")
    print(f"测试目录: {test_dir}")
    
    try:
        bus = A2ABusManager(test_dir)
        
        # 测试1：不传service_name（使用传统pending目录）
        print("\n测试：不传service_name（传统模式）...")
        task_path = bus.write_message(
            message_type="TaskRequest",
            task_id="LEGACY-001",
            sender="System",
            recipient="Coordinator",
            payload={"action": "test"}
        )
        print(f"  → 任务写入: {task_path}")
        
        # 验证文件在pending目录
        assert "pending" in task_path, "任务未写入pending目录"
        print("  ✅ 任务正确写入pending目录")
        
        # 测试2：从pending目录获取任务
        task_pairs = bus.get_pending_tasks()
        assert len(task_pairs) > 0, "未获取到任务"
        filepath, service_name = task_pairs[0]
        print(f"  → 获取到任务: {os.path.basename(filepath)}, service_name={service_name}")
        assert service_name == "legacy", "服务名称应该是legacy"
        print("  ✅ 正确获取到传统任务")
        
        print("\n✅ 向后兼容性测试通过！")
        return True
        
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        return False
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"\n清理测试目录: {test_dir}")

def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("队列分组和智能调度功能测试")
    print("=" * 60)
    
    results = []
    
    # 运行测试
    results.append(("队列分组功能", test_queue_grouping()))
    results.append(("优先队列调度", test_preferred_queue()))
    results.append(("向后兼容性", test_backward_compatibility()))
    
    # 输出结果
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    
    for name, passed in results:
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"{name}: {status}")
    
    all_passed = all(passed for _, passed in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 所有测试通过！")
        return 0
    else:
        print("⚠️ 部分测试失败，请检查日志")
        return 1

if __name__ == "__main__":
    sys.exit(main())
