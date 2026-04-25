from __future__ import annotations

import logging
from pathlib import Path

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from pyqtgraph import PlotWidget
from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.models import AnalysisResult, Flow, RouterConfig
from app.core.service import TrafficStudioService
from app.gui.workers import Worker
from app.network.mikrotik_ssh import MikroTikSSHClient

LOGGER = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PCAP Traffic Studio v2")
        self.resize(1600, 900)

        self.service = TrafficStudioService()
        self.thread_pool = QThreadPool.globalInstance()
        self.generated_profiles: list[Path] = []

        self.pcap_path = QLineEdit()
        self.router_ip = QLineEdit()
        self.router_port = QLineEdit("22")
        self.router_user = QLineEdit()
        self.router_pass = QLineEdit()
        self.router_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.status_label = QLabel("Status: idle")
        self.summary_label = QLabel("Flows: 0 | Avg PPS: 0.00 | Avg Duration: 0.00s")

        self.cb_trex = QCheckBox("TRex")
        self.cb_mikrotik = QCheckBox("MikroTik")
        self.cb_moongen = QCheckBox("MoonGen")
        self.cb_pktgen = QCheckBox("pktgen-dpdk")

        self.flow_table = QTableWidget(0, 9)
        self.flow_table.setHorizontalHeaderLabels(
            [
                "src ip",
                "dst ip",
                "src port",
                "dst port",
                "protocol",
                "pps",
                "duration",
                "avg packet",
                "pattern",
            ]
        )
        self.flow_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)

        self.packet_fig = Figure(figsize=(6, 3))
        self.packet_canvas = FigureCanvasQTAgg(self.packet_fig)

        self.protocol_fig = Figure(figsize=(6, 3))
        self.protocol_canvas = FigureCanvasQTAgg(self.protocol_fig)

        self.pps_plot = PlotWidget()
        self.pps_plot.setTitle("PPS Distribution")
        self.pps_plot.setLabel("left", "PPS")
        self.pps_plot.setLabel("bottom", "Flow Index")

        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        top_splitter = QSplitter()

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(self._pcap_group())
        left_layout.addWidget(self._generator_group())
        left_layout.addWidget(self._router_group())
        left_layout.addLayout(self._action_buttons())
        left_layout.addWidget(self.status_label)
        left_layout.addWidget(self.summary_label)
        left_layout.addWidget(QLabel("Flow viewer"))
        left_layout.addWidget(self.flow_table)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("Packet Size Histogram"))
        right_layout.addWidget(self.packet_canvas)
        right_layout.addWidget(QLabel("Protocol Distribution"))
        right_layout.addWidget(self.protocol_canvas)
        right_layout.addWidget(self.pps_plot)
        right_layout.addWidget(QLabel("Logs"))
        right_layout.addWidget(self.log_output)

        top_splitter.addWidget(left_panel)
        top_splitter.addWidget(right_panel)
        top_splitter.setSizes([900, 700])

        layout.addWidget(top_splitter)

    def _pcap_group(self) -> QGroupBox:
        pcap_group = QGroupBox("PCAP")
        pcap_layout = QHBoxLayout(pcap_group)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self._browse_pcap)
        pcap_layout.addWidget(QLabel("PCAP path:"))
        pcap_layout.addWidget(self.pcap_path)
        pcap_layout.addWidget(browse_button)
        return pcap_group

    def _generator_group(self) -> QGroupBox:
        gen_group = QGroupBox("Generators")
        gen_layout = QHBoxLayout(gen_group)
        for cb in [self.cb_trex, self.cb_mikrotik, self.cb_moongen, self.cb_pktgen]:
            gen_layout.addWidget(cb)
        return gen_group

    def _router_group(self) -> QGroupBox:
        router_group = QGroupBox("Router configuration")
        router_layout = QFormLayout(router_group)
        router_layout.addRow("Router IP", self.router_ip)
        router_layout.addRow("SSH Port", self.router_port)
        router_layout.addRow("Username", self.router_user)
        router_layout.addRow("Password", self.router_pass)
        return router_group

    def _action_buttons(self) -> QGridLayout:
        grid = QGridLayout()
        actions = [
            ("Analyze PCAP", self._analyze),
            ("Generate Profile", self._generate),
            ("Upload Profile", self._upload),
            ("Start Traffic", self._start),
            ("Stop Traffic", self._stop),
        ]
        for idx, (text, handler) in enumerate(actions):
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            grid.addWidget(btn, idx // 3, idx % 3)
        return grid

    def _browse_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PCAP", "", "PCAP Files (*.pcap *.pcapng)"
        )
        if path:
            self.pcap_path.setText(path)

    def _selected_generators(self) -> list[str]:
        targets: list[str] = []
        if self.cb_trex.isChecked():
            targets.append("trex")
        if self.cb_mikrotik.isChecked():
            targets.append("mikrotik")
        if self.cb_moongen.isChecked():
            targets.append("moongen")
        if self.cb_pktgen.isChecked():
            targets.append("pktgen-dpdk")
        return targets

    def _router_config(self) -> RouterConfig:
        return RouterConfig(
            host=self.router_ip.text().strip(),
            port=int(self.router_port.text().strip() or 22),
            username=self.router_user.text().strip(),
            password=self.router_pass.text(),
        )

    def _run_async(self, fn, on_success, *args) -> None:
        worker = Worker(fn, *args)
        worker.signals.finished.connect(on_success)
        worker.signals.error.connect(self._on_error)
        self.thread_pool.start(worker)

    def _set_status(self, msg: str) -> None:
        self.status_label.setText(f"Status: {msg}")
        self._log(msg)

    def _analyze(self) -> None:
        path = self.pcap_path.text().strip()
        if not path:
            self._warn("PCAP path is required")
            return

        self._set_status("analyzing pcap")
        self._run_async(self.service.analyze_pcap, self._on_analysis_ready, path)

    def _on_analysis_ready(self, result: AnalysisResult) -> None:
        self._set_status("analysis completed")
        self._populate_flow_table(result.flows)
        self._plot_packet_hist(
            result.packet_size_histogram["bins"], result.packet_size_histogram["counts"]
        )
        self._plot_protocols(result.protocol_distribution)
        self._plot_pps(result.pps_distribution)
        self._update_summary(result)

    def _generate(self) -> None:
        targets = self._selected_generators()
        if not targets:
            self._warn("Select at least one generator")
            return
        self._set_status("generating profiles")
        self._run_async(
            self.service.generate_profiles,
            self._on_profiles_ready,
            "profiles",
            targets,
        )

    def _on_profiles_ready(self, profiles: list[Path]) -> None:
        self.generated_profiles = profiles
        names = ", ".join(path.name for path in profiles) if profiles else "none"
        self._set_status(f"profiles generated: {names}")

    def _upload(self) -> None:
        mikrotik_profile = next(
            (p for p in self.generated_profiles if p.name == "mikrotik_profile.rsc"), None
        )
        if not mikrotik_profile:
            self._warn("Generate MikroTik profile first")
            return

        self._set_status("uploading mikrotik profile")
        self._run_async(self._upload_sync, self._on_simple_done, mikrotik_profile)

    def _upload_sync(self, profile_path: Path) -> str:
        client = MikroTikSSHClient(self._router_config())
        try:
            client.connect()
            remote_path = profile_path.name
            client.upload_profile(profile_path, remote_path)
            import_result = client.import_profile(remote_path)
            return f"Uploaded {remote_path}. Import output: {import_result.strip()}"
        finally:
            client.close()

    def _start(self) -> None:
        self._set_status("starting traffic")
        self._run_async(self._start_sync, self._on_simple_done)

    def _start_sync(self) -> str:
        client = MikroTikSSHClient(self._router_config())
        try:
            client.connect()
            return client.start_traffic().strip()
        finally:
            client.close()

    def _stop(self) -> None:
        self._set_status("stopping traffic")
        self._run_async(self._stop_sync, self._on_simple_done)

    def _stop_sync(self) -> str:
        client = MikroTikSSHClient(self._router_config())
        try:
            client.connect()
            return client.stop_traffic().strip()
        finally:
            client.close()

    def _on_simple_done(self, output: str) -> None:
        clean_output = output or "done"
        self._set_status(clean_output)

    def _on_error(self, message: str) -> None:
        self._set_status("operation failed")
        self._warn(message)

    def _update_summary(self, result: AnalysisResult) -> None:
        flow_count = len(result.flows)
        avg_pps = sum(result.pps_distribution) / flow_count if flow_count else 0.0
        avg_duration = sum(result.flow_durations) / flow_count if flow_count else 0.0
        self.summary_label.setText(
            f"Flows: {flow_count} | Avg PPS: {avg_pps:.2f} | Avg Duration: {avg_duration:.4f}s"
        )

    def _populate_flow_table(self, flows: list[Flow]) -> None:
        self.flow_table.setRowCount(len(flows))
        for idx, flow in enumerate(flows):
            avg_packet = (
                int(sum(flow.packet_sizes) / len(flow.packet_sizes)) if flow.packet_sizes else 0
            )
            values = [
                str(flow.src_ip),
                str(flow.dst_ip),
                str(flow.src_port),
                str(flow.dst_port),
                flow.protocol.value,
                f"{flow.pps:.2f}",
                f"{flow.duration:.4f}",
                str(avg_packet),
                flow.pattern.value,
            ]
            for col, value in enumerate(values):
                self.flow_table.setItem(idx, col, QTableWidgetItem(value))

    def _plot_packet_hist(self, bins: list[float], counts: list[float]) -> None:
        self.packet_fig.clear()
        ax = self.packet_fig.add_subplot(111)
        if len(bins) > 1:
            ax.bar(bins[:-1], counts, width=(bins[1] - bins[0]), align="edge")
        ax.set_title("Packet Size Distribution")
        ax.set_xlabel("Packet size")
        ax.set_ylabel("Count")
        self.packet_canvas.draw_idle()

    def _plot_protocols(self, protocol_distribution: dict[str, int]) -> None:
        self.protocol_fig.clear()
        ax = self.protocol_fig.add_subplot(111)
        if protocol_distribution:
            labels = list(protocol_distribution.keys())
            values = list(protocol_distribution.values())
            ax.pie(values, labels=labels, autopct="%1.1f%%")
        ax.set_title("Protocol Distribution")
        self.protocol_canvas.draw_idle()

    def _plot_pps(self, pps: list[float]) -> None:
        self.pps_plot.clear()
        if pps:
            self.pps_plot.plot(list(range(len(pps))), pps, symbol="o")

    def _log(self, message: str) -> None:
        LOGGER.info(message)
        self.log_output.append(message)

    def _warn(self, message: str) -> None:
        self._log(message)
        QMessageBox.warning(self, "PCAP Traffic Studio", message)
