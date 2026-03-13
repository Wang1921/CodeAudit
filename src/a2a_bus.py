import os
import json
import uuid
import logging
from typing import Optional, Dict, List, Tuple

class A2ABusManager:
    SUPPORTED_MESSAGE_TYPES = [
        "TaskRequest",
        "Coordinator_Output",
        "VulnCandidate",
        "ExploitAttempt",
        "ConfirmedVuln",
        "CrossServiceTraceRequest"  # 跨微服务追踪请求
    ]
    
    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)
        self.bus_dir = os.path.join(self.project_root, ".a2a_bus")
        
        # 传统目录（保持向后兼容）
        self.pending_dir = os.path.join(self.bus_dir, "pending")
        self.processing_dir = os.path.join(self.bus_dir, "processing")
        self.completed_dir = os.path.join(self.bus_dir, "completed")
        self.failed_dir = os.path.join(self.bus_dir, "failed")
        self.help_req_dir = os.path.join(self.bus_dir, "help_req")
        
        # 新增：按微服务分组的队列目录
        self.queues_dir = os.path.join(self.bus_dir, "queues")
        self._init_dirs()

    def _init_dirs(self):
        """初始化所有必要的目录结构"""
        # 传统目录（保持兼容）
        for d in [self.bus_dir, self.pending_dir, self.processing_dir, 
                  self.completed_dir, self.failed_dir, self.help_req_dir]:
            os.makedirs(d, exist_ok=True)
        
        # 新增：队列目录
        os.makedirs(self.queues_dir, exist_ok=True)
        # 创建全局队列（存放Coordinator、跨微服务任务）
        os.makedirs(os.path.join(self.queues_dir, "global"), exist_ok=True)

    def write_message(self, message_type: str, task_id: str, sender: str, recipient: str, payload: dict, priority: str = "normal", service_name: Optional[str] = None) -> str:
        """
        原子地写入一条新的 A2A 消息。
        
        Args:
            message_type: 消息类型（TaskRequest, VulnCandidate等）
            task_id: 任务ID
            sender: 发送者
            recipient: 接收者
            payload: 消息载荷
            priority: 优先级（normal/high）
            service_name: 微服务名称（用于路由到对应队列）
                        - None/''/main → global队列
                        - 'user-service' → user-service队列
        
        Returns:
            str: 消息文件路径
        """
        if message_type not in self.SUPPORTED_MESSAGE_TYPES:
            logging.warning(f"未知的 message_type: {message_type}, 但仍然添加")
        
        msg = {
            "a2a_version": "5.0" if message_type == "Coordinator_Output" else "1.0",
            "message_type": message_type,
            "task_id": task_id,
            "sender": sender,
            "recipient": recipient,
            "payload": payload
        }
        filename = f"{task_id}_{uuid.uuid4().hex[:8]}.json"
        
        # 确定目标队列目录
        # 如果指定了service_name且不是main，写入对应的微服务队列
        # 否则使用传统逻辑（help_req或pending）
        if service_name and service_name not in ["", "main"]:
            target_queue = os.path.join(self.queues_dir, service_name)
            os.makedirs(target_queue, exist_ok=True)
        elif priority == "high":
            target_queue = self.help_req_dir
        else:
            target_queue = self.pending_dir
        
        tmp_path = os.path.join(target_queue, filename + ".tmp")
        final_path = os.path.join(target_queue, filename)

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(msg, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp_path, final_path)
            return final_path
        except Exception as e:
            logging.error(f"写入消息失败 {filename}: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get_pending_tasks(self, preferred_services: Optional[List[str]] = None) -> List[Tuple[str, str]]:
        """
        智能获取待处理任务（按微服务优先级调度）
        
        Args:
            preferred_services: 优先从这些微服务队列取任务（避免频繁切换服务器）
                               例如：["user-service", "processor-service"]
        
        Returns:
            List[Tuple[str, str]]: 任务文件路径和所属微服务的列表
                                  例如：[("/path/to/task1.json", "user-service"), ...]
        
        调度策略：
        1. 如果指定了 preferred_services，优先从中取任务（服务器已启动，可复用）
        2. 否则轮询所有队列（Round-Robin）
        3. 限制每次最多返回10个任务
        """
        tasks = []
        max_tasks_per_batch = 10
        
        # 1. 优先从正在运行服务器的微服务队列取任务
        if preferred_services:
            for service_name in preferred_services:
                queue_dir = os.path.join(self.queues_dir, service_name)
                if os.path.exists(queue_dir):
                    task_path = self._pop_one_task(queue_dir)
                    if task_path:
                        tasks.append((task_path, service_name))
                        logging.debug(f"[队列调度] 从优选队列 {service_name} 取任务: {os.path.basename(task_path)}")
                        if len(tasks) >= max_tasks_per_batch:
                            break
        
        # 2. 如果没有找到，从其他队列补充
        if len(tasks) < max_tasks_per_batch:
            remaining_services = self._get_all_queue_names()
            if preferred_services:
                # 过滤掉已经尝试过的队列
                remaining_services = [s for s in remaining_services if s not in preferred_services]
            
            for service_name in remaining_services:
                queue_dir = os.path.join(self.queues_dir, service_name)
                if os.path.exists(queue_dir):
                    task_path = self._pop_one_task(queue_dir)
                    if task_path:
                        tasks.append((task_path, service_name))
                        logging.debug(f"[队列调度] 从队列 {service_name} 取任务: {os.path.basename(task_path)}")
                        if len(tasks) >= max_tasks_per_batch:
                            break
        
        # 3. 如果队列中没有任务，检查传统目录（向后兼容）
        if len(tasks) < max_tasks_per_batch:
            for dir_path in [self.help_req_dir, self.pending_dir]:
                task_path = self._pop_one_task(dir_path)
                if task_path:
                    tasks.append((task_path, "legacy"))
                    if len(tasks) >= max_tasks_per_batch:
                        break
        
        if tasks:
            logging.info(f"[队列调度] 本批次获取 {len(tasks)} 个任务，来自: {[s for _, s in tasks]}")
        
        return tasks
    
    def _pop_one_task(self, queue_dir: str) -> Optional[str]:
        """
        从队列中原子地取出一个任务（移动到processing目录）
        
        Args:
            queue_dir: 队列目录路径
        
        Returns:
            Optional[str]: 任务在processing目录中的路径，如果没有任务则返回None
        """
        try:
            files = os.listdir(queue_dir)
            for f in files:
                if not f.endswith(".json"):
                    continue
                src_path = os.path.join(queue_dir, f)
                proc_path = os.path.join(self.processing_dir, f)
                try:
                    # 原子地移动到processing目录
                    os.rename(src_path, proc_path)
                    return proc_path
                except OSError:
                    # 文件可能已被其他进程取走，继续尝试下一个
                    continue
        except Exception as e:
            logging.error(f"扫描队列出错 {queue_dir}: {e}")
        return None
    
    def _get_all_queue_names(self) -> List[str]:
        """
        获取所有队列名称（按字母顺序排序，用于轮询）
        
        Returns:
            List[str]: 队列名称列表，例如：["global", "order-service", "user-service"]
        """
        try:
            if os.path.exists(self.queues_dir):
                return sorted([
                    d for d in os.listdir(self.queues_dir) 
                    if os.path.isdir(os.path.join(self.queues_dir, d))
                ])
        except Exception as e:
            logging.error(f"获取队列名称失败: {e}")
        return ["global"]  # 回退到全局队列

    def read_message(self, filepath: str) -> dict:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def mark_completed(self, filepath: str, agent_result: Optional[dict] = None):
        """
        标记任务为完成状态
        
        Args:
            filepath: 任务文件路径（在processing目录中）
            agent_result: Agent执行结果（可选），如果提供会合并到消息中
        """
        basename = os.path.basename(filepath)
        dest = os.path.join(self.completed_dir, basename)
        
        # 如果有 Agent 执行结果，更新 JSON 文件
        if agent_result:
            msg = self.read_message(filepath)
            msg["agent_result"] = agent_result
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(msg, f, ensure_ascii=False, indent=2)
            # 删除原文件
            os.remove(filepath)
        else:
            os.rename(filepath, dest)

    def mark_failed(self, filepath: str):
        basename = os.path.basename(filepath)
        dest = os.path.join(self.failed_dir, basename)
        os.rename(filepath, dest)

    def write_raw_failed(self, raw_content: str, reason: str):
        filename = f"malformed_{uuid.uuid4().hex[:8]}.txt"
        dest = os.path.join(self.failed_dir, filename)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(f"原因: {reason}\n\n")
            f.write(raw_content)
