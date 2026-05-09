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
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)

    def mark_completed(self, filepath: str, agent_result: dict = None):
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
        basename = os.path.basename(filepath)
        dest = os.path.join(self.failed_dir, basename)
        os.rename(filepath, dest)

    def write_raw_failed(self, raw_content: str, reason: str):
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
