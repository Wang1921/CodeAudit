import json
import logging
import os
import uuid


class A2ABusManager:
    SUPPORTED_MESSAGE_TYPES = [
        "TaskRequest",
        "VulnCandidate",
        "ExploitAttempt",
        "ConfirmedVuln",
        "CrossServiceTraceRequest"  # 跨微服务追踪请求
    ]

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)
        self.bus_dir = os.path.join(self.project_root, ".a2a_bus")
        self.pending_dir = os.path.join(self.bus_dir, "pending")
        self.processing_dir = os.path.join(self.bus_dir, "processing")
        self.completed_dir = os.path.join(self.bus_dir, "completed")
        self.failed_dir = os.path.join(self.bus_dir, "failed")
        self.help_req_dir = os.path.join(self.bus_dir, "help_req")
        self._init_dirs()

    def _init_dirs(self):
        """确保 A2A 总线的全部 5 个子目录存在（pending/processing/completed/failed/help_req）。

        总线本质是基于文件系统的目录队列，子目录间通过 os.rename 实现原子状态迁移；
        缺哪一个都会让对应阶段失败，因此 __init__ 阶段强制建齐。
        """
        for d in [self.bus_dir, self.pending_dir, self.processing_dir, self.completed_dir, self.failed_dir, self.help_req_dir]:
            os.makedirs(d, exist_ok=True)

    def write_message(self, message_type: str, task_id: str, sender: str, recipient: str, payload: dict, priority: str = "normal") -> str:
        """原子地写入一条新的 A2A 消息。"""
        if message_type not in self.SUPPORTED_MESSAGE_TYPES:
            logging.warning(f"未知的 message_type: {message_type}, 但仍然添加")

        msg = {
            "a2a_version": "1.0",
            "message_type": message_type,
            "task_id": task_id,
            "sender": sender,
            "recipient": recipient,
            "payload": payload
        }
        filename = f"{task_id}_{uuid.uuid4().hex[:8]}.json"

        target_dir = self.help_req_dir if priority == "high" else self.pending_dir
        tmp_path = os.path.join(target_dir, filename + ".tmp")
        final_path = os.path.join(target_dir, filename)

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

    def get_pending_tasks(self) -> list:
        """扫描 pending 和 help_req 目录，并原子地移动到 processing。"""
        tasks = []
        for dir_path in [self.help_req_dir, self.pending_dir]:
            try:
                files = os.listdir(dir_path)
                for f in files:
                    if not f.endswith(".json"):
                        continue
                    src_path = os.path.join(dir_path, f)
                    proc_path = os.path.join(self.processing_dir, f)
                    try:
                        os.rename(src_path, proc_path)
                        tasks.append(proc_path)
                    except OSError:
                        continue
            except Exception as e:
                logging.error(f"扫描出错 {dir_path}: {e}")
        return tasks

    def read_message(self, filepath: str) -> dict:
        """读取一条 A2A 消息 envelope（JSON 文件）并解析为 dict。

        本方法不做 schema 校验也不变更状态，仅是一次顺序文件读；
        损坏的 JSON 会抛 json.JSONDecodeError，由调用方决定走 mark_failed 还是 write_raw_failed。
        """
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)

    def mark_completed(self, filepath: str, agent_result: dict = None):
        """把一条 envelope 从 processing/ 原子迁移到 completed/。

        若提供了 agent_result，会先把它合并进 envelope 的 agent_result 字段，
        用 tmp + fsync + rename 保证崩溃安全（部分写入不会污染 completed/）。
        无 agent_result 时退化为单次 os.rename。
        """
        basename = os.path.basename(filepath)
        dest = os.path.join(self.completed_dir, basename)

        # 如果有 Agent 执行结果，更新 JSON 文件（tmp + fsync + rename，保证崩溃安全）
        if agent_result:
            msg = self.read_message(filepath)
            msg["agent_result"] = agent_result
            tmp_path = dest + ".tmp"
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(msg, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.rename(tmp_path, dest)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            # 目标文件已成功原子落盘，再删除源文件
            os.remove(filepath)
        else:
            os.rename(filepath, dest)

    def mark_failed(self, filepath: str):
        """把一条已读 envelope 从 processing/ 原子迁移到 failed/，让后续轮询不再取它。

        与 mark_completed 互斥：调用方拿到 LLM 超时/解析失败/异常时走这里；
        失败任务后续可由人工或运维脚本回收分析（SUMMARY.md 会统计 failed 数量）。
        """
        basename = os.path.basename(filepath)
        dest = os.path.join(self.failed_dir, basename)
        os.rename(filepath, dest)

    def write_raw_failed(self, raw_content: str, reason: str):
        """落档一段无法解析为 envelope 的原始 LLM 输出到 failed/。

        与 mark_failed 区别：mark_failed 处理已经在 processing/ 里的 .json 消息；
        本方法处理的是连"形成合法 envelope"都做不到的脏数据（如 LLM 吐了纯文本），
        保留 raw_content 与 reason 供事后排查模型异常输出。
        """
        filename = f"malformed_{uuid.uuid4().hex[:8]}.txt"
        dest = os.path.join(self.failed_dir, filename)
        tmp_path = dest + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(f"原因: {reason}\n\n")
                f.write(raw_content)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp_path, dest)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
