import os
import json
import uuid
import logging
from typing import Optional, Dict

class A2ABusManager:
    SUPPORTED_MESSAGE_TYPES = [
        "TaskRequest",
        "Coordinator_Output",
        "VulnCandidate",
        "ExploitAttempt",
        "ConfirmedVuln"
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
        """Atomically write a new A2A message."""
        if message_type not in self.SUPPORTED_MESSAGE_TYPES:
            logging.warning(f"Unknown message_type: {message_type}, adding anyway")
        
        msg = {
            "a2a_version": "5.0" if message_type == "Coordinator_Output" else "1.0",
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
            logging.error(f"Failed to write message {filename}: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get_pending_tasks(self) -> list:
        """Scan pending and help_req dirs and atomically move to processing."""
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
                logging.error(f"Error scanning {dir_path}: {e}")
        return tasks

    def read_message(self, filepath: str) -> dict:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def mark_completed(self, filepath: str):
        basename = os.path.basename(filepath)
        dest = os.path.join(self.completed_dir, basename)
        os.rename(filepath, dest)

    def mark_failed(self, filepath: str):
        basename = os.path.basename(filepath)
        dest = os.path.join(self.failed_dir, basename)
        os.rename(filepath, dest)

    def write_raw_failed(self, raw_content: str, reason: str):
        filename = f"malformed_{uuid.uuid4().hex[:8]}.txt"
        dest = os.path.join(self.failed_dir, filename)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(f"Reason: {reason}\n\n")
            f.write(raw_content)
