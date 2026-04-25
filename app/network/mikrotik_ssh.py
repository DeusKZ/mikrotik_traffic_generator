from __future__ import annotations

from pathlib import Path

import paramiko

from app.core.models import RouterConfig


class MikroTikSSHClient:
    def __init__(self, config: RouterConfig) -> None:
        self.config = config
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self) -> None:
        self.client.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.config.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )

    def close(self) -> None:
        self.client.close()

    def upload_profile(self, local_path: Path, remote_path: str) -> None:
        with self.client.open_sftp() as sftp:
            sftp.put(str(local_path), remote_path)

    def run_command(self, command: str) -> str:
        _stdin, stdout, stderr = self.client.exec_command(command)
        output = stdout.read().decode("utf-8", errors="ignore")
        error = stderr.read().decode("utf-8", errors="ignore")
        return output if output else error

    def import_profile(self, remote_path: str) -> str:
        return self.run_command(f"/import file-name={remote_path}")

    def start_traffic(self) -> str:
        return self.run_command("/tool traffic-generator start")

    def stop_traffic(self) -> str:
        return self.run_command("/tool traffic-generator stop")
