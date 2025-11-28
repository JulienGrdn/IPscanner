#!/usr/bin/env python3

"""

Enhanced Network Scanner (GTK4 + libadwaita)

- Scans all IP addresses on the local network using both nmap and ping sweep
- Lists discovered devices with basic information only
- Deep scanning (ports, services, OS detection) only available via "More details" button
- Uses psutil + system routing for interface/gateway detection
- Uses python-nmap and subprocess ping for comprehensive host discovery
- Modern GNOME interface with Adw.ApplicationWindow + Adw.ToolbarView

"""

import gi
import sys

try:
    gi.require_version('Gtk', '4.0')
    gi.require_version('Adw', '1')
except ValueError:
    print("Error: GTK4 or Libadwaita not found.")
    sys.exit(1)

from gi.repository import Gtk, Adw, GLib, Gio, GObject

import socket
import platform
import subprocess
import threading
import ipaddress
import psutil
try:
    from . import nmap
except ImportError:
    import nmap

import concurrent.futures
import time
import shutil
import re

# -------------------------------
# Data model for devices
# -------------------------------

class DeviceInfo(GObject.Object):
    __gtype_name__ = 'DeviceInfo'

    ip = GObject.Property(type=str, default="")
    hostname = GObject.Property(type=str, default="")
    mac = GObject.Property(type=str, default="")
    vendor = GObject.Property(type=str, default="")
    os_info = GObject.Property(type=str, default="")
    ports = GObject.Property(type=str, default="")
    status = GObject.Property(type=str, default="")
    method = GObject.Property(type=str, default="")  # How device was discovered

    # Track deep scan state
    is_scanning = GObject.Property(type=bool, default=False)
    scan_progress = GObject.Property(type=float, default=0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

# -------------------------------
# Scanner logic
# -------------------------------

class NetworkScanner:
    def __init__(self):
        self.nmap_available = False
        self.nm = None

        # Check if nmap binary is available
        if shutil.which("nmap") is None:
            print("Warning: 'nmap' binary not found in PATH.")
        else:
            try:
                self.nm = nmap.PortScanner()
                self.nmap_available = True
            except Exception as e:
                print(f"Error initializing nmap: {e}")

    # -- Routing and interface helpers --
    def _get_default_route_linux(self):
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    if 'default via' in line:
                        parts = line.split()
                        gateway = parts[2]
                        iface = parts[parts.index('dev') + 1] if 'dev' in parts else None
                        return gateway, iface
        except Exception:
            pass
        return None, None

    def _get_first_active_iface(self):
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, s in stats.items():
            if s.isup and name in addrs:
                for addr in addrs[name]:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        return name
        return None

    def get_local_ip_and_network(self):
        # Prefer default route interface
        gateway, iface = self._get_default_route_linux()
        addrs = psutil.net_if_addrs()

        if iface and iface in addrs:
            for addr in addrs[iface]:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    try:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        return addr.address, str(network), iface, gateway
                    except Exception:
                        # Fallback to /24 if netmask missing
                        base = '.'.join(addr.address.split('.')[:3])
                        return addr.address, f"{base}.0/24", iface, gateway

        # Fallback: first active interface with IPv4
        iface = self._get_first_active_iface()
        if iface and iface in addrs:
            for addr in addrs[iface]:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    try:
                        network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        return addr.address, str(network), iface, gateway
                    except Exception:
                        base = '.'.join(addr.address.split('.')[:3])
                        return addr.address, f"{base}.0/24", iface, gateway

        # Ultimate fallback: hostname resolution
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = '127.0.0.1'

        base = '.'.join(local_ip.split('.')[:3]) if '.' in local_ip else '192.168.1'
        return local_ip, f"{base}.0/24", None, gateway

    def _get_mac_for_iface(self, iface_name=None):
        try:
            addrs = psutil.net_if_addrs()
            if iface_name and iface_name in addrs:
                for addr in addrs[iface_name]:
                    if getattr(socket, 'AF_PACKET', None) and addr.family == socket.AF_PACKET:
                        return addr.address
                    if getattr(socket, 'AF_LINK', None) and addr.family == socket.AF_LINK:
                        return addr.address

            # Fallback: any active iface
            stats = psutil.net_if_stats()
            for name, s in stats.items():
                if s.isup and name in addrs:
                    for addr in addrs[name]:
                        if getattr(socket, 'AF_PACKET', None) and addr.family == socket.AF_PACKET:
                            return addr.address
                        if getattr(socket, 'AF_LINK', None) and addr.family == socket.AF_LINK:
                            return addr.address
        except Exception:
            pass
        return ''

    def _ping_host(self, ip):
        """Ping a single host to check if it's alive. Returns (is_alive, latency_str)"""
        try:
            # Use ping command with timeout
            # Ensure IP is a valid string to prevent injection, though caller should ensure validity.
            ipaddress.ip_address(ip)

            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

            if result.returncode == 0:
                # Parse latency
                # Linux output example: time=0.042 ms
                latency = ""
                if result.stdout:
                    match = re.search(r"time=([\d\.]+)", result.stdout)
                    if match:
                        latency = f"{match.group(1)} ms"
                return True, latency

            return False, ""
        except (ValueError, subprocess.TimeoutExpired, Exception):
            return False, ""

    def _get_hostname_safe(self, ip):
        """Safely get hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return 'Unknown'

    def ping_sweep(self, network_cidr, add_callback, progress_callback=None):
        """Ping all IPs in the network range concurrently"""
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            hosts = list(network.hosts())

            # Include network and broadcast addresses for completeness
            all_ips = [str(network.network_address)] + [str(ip) for ip in hosts] + [str(network.broadcast_address)]

            discovered = set()
            total_ips = len(all_ips)
            completed = 0

            def ping_and_process(ip):
                nonlocal completed
                is_alive, latency = self._ping_host(ip)
                if is_alive:
                    hostname = self._get_hostname_safe(ip)
                    status_text = f"Up (ping) {latency}".strip()
                    dev = DeviceInfo(
                        ip=ip,
                        hostname=hostname,
                        mac='',
                        vendor='',
                        os_info='',
                        ports='',
                        status=status_text,
                        method='ping'
                    )
                    discovered.add(ip)
                    GLib.idle_add(add_callback, dev)

                completed += 1
                if progress_callback:
                    progress = completed / total_ips
                    GLib.idle_add(progress_callback, progress, f"Ping sweep: {completed}/{total_ips}")

            # Use ThreadPoolExecutor for concurrent pings. Lowered from 50 to 25 for safety.
            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                executor.map(ping_and_process, all_ips)

            return discovered

        except Exception as e:
            print(f"Ping sweep error: {e}")
            return set()

    def nmap_discovery(self, network_cidr, add_callback, progress_callback=None, ping_discovered=None):
        """Use nmap for host discovery"""
        if not self.nmap_available:
            print("Nmap not available, skipping nmap discovery.")
            return

        if ping_discovered is None:
            ping_discovered = set()

        try:
            if progress_callback:
                GLib.idle_add(progress_callback, 0.5, "Running nmap host discovery...")

            self.nm.scan(hosts=network_cidr, arguments='-sn -T4')

            for host in self.nm.all_hosts():
                try:
                    if self.nm[host].state() != 'up':
                        continue

                    # Skip if already discovered by ping (avoid duplicates)
                    if host in ping_discovered:
                        continue

                    hostname = self.nm[host].hostname() or 'Unknown'

                    # Get MAC if available from nmap
                    mac = ''
                    vendor = ''
                    if 'addresses' in self.nm[host]:
                        addrs = self.nm[host]['addresses']
                        mac = addrs.get('mac', '')

                    if mac and 'vendor' in self.nm[host]:
                        vendor_dict = self.nm[host]['vendor']
                        vendor = vendor_dict.get(mac, '')

                    dev = DeviceInfo(
                        ip=host,
                        hostname=hostname,
                        mac=mac,
                        vendor=vendor,
                        os_info='',
                        ports='',
                        status='Up (nmap)',
                        method='nmap'
                    )

                    GLib.idle_add(add_callback, dev)

                except Exception as e:
                    print(f"Per-host processing error for {host}: {e}")

        except Exception as e:
            print(f"Nmap discovery error: {e}")

    def get_system_info(self):
        ip, _, iface, _ = self.get_local_ip_and_network()
        mac = self._get_mac_for_iface(iface)
        os_info = f"{platform.system()} {platform.release()}"

        # Listening ports (best effort, limited to avoid noise)
        ports = set()
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    ports.add(str(c.laddr.port))
        except Exception:
            pass

        return DeviceInfo(
            ip=ip,
            hostname=socket.gethostname(),
            mac=mac,
            vendor='Local Machine',
            os_info=os_info,
            ports=', '.join(sorted(list(ports))[:10]),
            status='Local Host',
            method='local'
        )

    def comprehensive_scan(self, network_cidr, add_callback, progress_callback=None):
        """Perform both ping sweep and nmap discovery"""
        try:
            # First do ping sweep
            if progress_callback:
                GLib.idle_add(progress_callback, 0.1, "Starting comprehensive network scan...")

            ping_discovered = self.ping_sweep(network_cidr, add_callback, progress_callback)

            # Then do nmap discovery for anything ping missed
            if self.nmap_available:
                if progress_callback:
                    GLib.idle_add(progress_callback, 0.7, "Running nmap discovery...")

                self.nmap_discovery(network_cidr, add_callback, progress_callback, ping_discovered)

            if progress_callback:
                GLib.idle_add(progress_callback, 1.0, "Scan completed")

        except Exception as e:
            print(f"Comprehensive scan error: {e}")

    def deep_scan_device(self, ip, privileged=False):
        """
        Perform detailed scan of a specific device.

        :param ip: The target IP address.
        :param privileged: If True, uses 'pkexec' to run nmap as root (for OS detection, etc.)
        :return: (result_dict, scanner_instance) or (error_dict, None)
        """
        if not self.nmap_available:
            return {
                'ip': ip,
                'hostname': '',
                'mac': '',
                'vendor': '',
                'os_info': 'Nmap not available',
                'ports': '',
                'raw_data': {}
            }, None

        # Create a new scanner instance to support cancellation and isolation
        scanner = nmap.PortScanner()

        try:
            # Comprehensive scan with OS detection, service detection, and script scanning
            # If privileged is True, pass 'pkexec' as the sudo argument.
            sudo_cmd = 'pkexec' if privileged else False

            detail = scanner.scan(
                hosts=ip,
                arguments='-A -sS -sV -O -T4 --script=default,discovery,safe',
                sudo=sudo_cmd
            )

            sinfo = detail.get('scan', {}).get(ip, {})

            # OS detection
            osmatch = sinfo.get('osmatch', [])
            os_info = osmatch[0]['name'] if osmatch else "Unknown"
            if osmatch and 'accuracy' in osmatch[0]:
                os_info += f" ({osmatch[0]['accuracy']}% confidence)"

            # Port information
            tcp = sinfo.get('tcp', {})
            udp = sinfo.get('udp', {})

            open_ports = []
            for proto, ports in [('tcp', tcp), ('udp', udp)]:
                for port, info in ports.items():
                    if info.get('state') == 'open':
                        service = info.get('name', 'unknown')
                        version = info.get('version', '')
                        product = info.get('product', '')

                        port_info = f"{port}/{proto}/{service}"
                        if product:
                            port_info += f" {product}"
                        if version:
                            port_info += f" {version}"
                        open_ports.append(port_info)

            ports_str = '\n'.join(open_ports[:20])  # Limit to prevent UI overflow

            # MAC and vendor
            addr_dict = sinfo.get('addresses', {})
            mac = addr_dict.get('mac', '')
            vendor = sinfo.get('vendor', {}).get(mac, '') if mac else ''

            # Hostname
            hostname = sinfo.get('hostnames', [])
            hostname_str = hostname[0]['name'] if hostname else 'Unknown'

            return {
                'ip': ip,
                'hostname': hostname_str,
                'mac': mac,
                'vendor': vendor,
                'os_info': os_info,
                'ports': ports_str,
                'raw_data': sinfo
            }, scanner

        except Exception as e:
            return {
                'ip': ip,
                'hostname': 'Error',
                'mac': '',
                'vendor': '',
                'os_info': f"Scan failed: {str(e)}",
                'ports': '',
                'raw_data': {}
            }, scanner

# -------------------------------
# Main window
# -------------------------------

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title("Enhanced Network Scanner")
        self.set_default_size(1200, 700)

        self.scanner = NetworkScanner()
        self.scanning = False

        self.active_scans = {}  # Map ip -> scanner_instance

        self._build_ui()
        self._load_local_device()

        if not self.scanner.nmap_available:
            self._show_nmap_warning()

    def _show_nmap_warning(self):
        # We can't show a dialog immediately as the window might not be fully realized
        # but we can schedule it.
        def show():
            dlg = Adw.AlertDialog(
                heading="Nmap not found",
                body="The 'nmap' binary was not found on your system. Deep scanning and nmap discovery will be disabled. Only Ping Sweep will work. Please install nmap."
            )
            dlg.add_response("ok", "OK")
            dlg.present(self)
        GLib.idle_add(show)

    def _build_ui(self):
        # Main content first
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(12)
        main_box.set_margin_start(12)
        main_box.set_margin_end(12)

        # Header bar
        header = Gtk.HeaderBar()

        self.scan_button = Gtk.Button(label="Comprehensive Scan")
        self.scan_button.add_css_class("suggested-action")
        self.scan_button.connect("clicked", self._on_scan_clicked)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text("Refresh Local Device Info")
        refresh_btn.connect("clicked", self._on_refresh_clicked)

        info_btn = Gtk.Button(icon_name="dialog-information-symbolic")
        info_btn.set_tooltip_text("Network Information")
        info_btn.connect("clicked", self._on_info_clicked)

        header.pack_start(self.scan_button)
        header.pack_start(refresh_btn)
        header.pack_end(info_btn)

        # Status label
        self.status_label = Gtk.Label(label="Ready to scan network")
        self.status_label.add_css_class("dim-label")
        main_box.append(self.status_label)

        # Device list view
        self._build_device_list()
        main_box.append(self.scrolled)

        # Progress bar
        self.progress = Gtk.ProgressBar()
        self.progress.set_visible(False)
        main_box.append(self.progress)

        # Overlay with spinner for deep scan busy state
        self.overlay = Gtk.Overlay()
        self.overlay.set_child(main_box)

        self.detail_spinner = Gtk.Spinner()
        self.detail_spinner.set_halign(Gtk.Align.CENTER)
        self.detail_spinner.set_valign(Gtk.Align.START)
        self.detail_spinner.set_margin_top(48)
        self.detail_spinner.set_visible(False)
        self.overlay.add_overlay(self.detail_spinner)

        # ToolbarView composition
        tv = Adw.ToolbarView()
        tv.add_top_bar(header)
        tv.set_content(self.overlay)
        self.set_content(tv)

    def _build_device_list(self):
        # The store will contain DeviceInfo GObjects
        self.store = Gio.ListStore(item_type=DeviceInfo)
        self.selection = Gtk.SingleSelection(model=self.store)
        self.column_view = Gtk.ColumnView(model=self.selection)

        columns = [
            ("IP Address", "ip"),
            ("Hostname", "hostname"),
            ("MAC Address", "mac"),
            ("Vendor", "vendor"),
            ("Status", "status"),
            ("Discovery Method", "method"),
        ]

        for title, prop_name in columns:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._cell_setup)
            factory.connect("bind", self._cell_bind, prop_name)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_expand(True)
            self.column_view.append_column(col)

        # Action column with Deep Scan / Cancel buttons
        action_factory = Gtk.SignalListItemFactory()
        action_factory.connect("setup", self._action_cell_setup)
        action_factory.connect("bind", self._action_cell_bind)
        action_col = Gtk.ColumnViewColumn(title="Actions", factory=action_factory)
        self.column_view.append_column(action_col)

        # Row activation (double-click/Enter) triggers deep scan
        self.column_view.connect("activate", self._on_device_activated)

        self.scrolled = Gtk.ScrolledWindow()
        self.scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.scrolled.set_vexpand(True)
        self.scrolled.set_child(self.column_view)

    def _cell_setup(self, factory, item):
        lbl = Gtk.Label(xalign=0)
        item.set_child(lbl)

    def _cell_bind(self, factory, item, prop_name):
        dev = item.get_item()
        lbl = item.get_child()
        if dev and lbl:
            value = getattr(dev.props, prop_name, "")
            lbl.set_text(str(value))

    def _action_cell_setup(self, factory, item):
        stack = Gtk.Stack()

        # Page 1: Deep Scan Button
        scan_btn = Gtk.Button(label="Deep Scan")
        scan_btn.add_css_class("pill")
        scan_btn.connect("clicked", lambda b: self._on_row_deep_scan(item))
        stack.add_named(scan_btn, "scan")

        # Page 2: Progress + Cancel
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)

        prog = Gtk.ProgressBar()
        prog.set_pulse_step(0.1)
        prog.set_hexpand(True)
        # To make it visible/sized
        prog.set_size_request(100, -1)

        cancel_btn = Gtk.Button(icon_name="process-stop-symbolic")
        cancel_btn.set_tooltip_text("Cancel Scan")
        cancel_btn.add_css_class("destructive-action")
        cancel_btn.connect("clicked", lambda b: self._on_row_cancel_scan(item))

        box.append(prog)
        box.append(cancel_btn)
        stack.add_named(box, "progress")

        item.set_child(stack)

    def _action_cell_bind(self, factory, item):
        dev = item.get_item()
        stack = item.get_child()
        if not dev or not stack:
            return

        # We need to bind the state of the stack to dev.is_scanning
        # Since we can't easily use GtkExpression/bind_property in python without complications sometimes,
        # we'll use a signal handler on the object.
        # But cell recycling makes this tricky. We must disconnect old signals.

        # Helper to update stack state
        def update_state(obj, pspec):
            if obj.is_scanning:
                stack.set_visible_child_name("progress")
                # Start pulsing the progress bar if needed, or just set it to pulse mode
                # Since we don't have an animation loop easily attached to the cell,
                # we rely on the fact that if we just show it, it looks static unless updated.
                # We can set text or just let it be.
                # For a pulsing bar, we need to call pulse().
                # We can store a GLib timeout on the stack/item to pulse it.
                self._ensure_pulsing(stack)
            else:
                stack.set_visible_child_name("scan")
                self._stop_pulsing(stack)

        # Disconnect previous signal if any (stored on the stack widget)
        if hasattr(stack, "_sig_id") and hasattr(stack, "_dev"):
             if stack._dev.handler_is_connected(stack._sig_id):
                 stack._dev.disconnect(stack._sig_id)

        # Connect new
        sig_id = dev.connect("notify::is-scanning", update_state)
        stack._sig_id = sig_id
        stack._dev = dev

        # Initial state
        update_state(dev, None)

    def _ensure_pulsing(self, stack):
        if hasattr(stack, "_pulse_source") and stack._pulse_source:
            return

        prog = stack.get_child_by_name("progress").get_first_child() # The progress bar is the first child of the box

        def pulse():
            prog.pulse()
            return True

        stack._pulse_source = GLib.timeout_add(100, pulse)

    def _stop_pulsing(self, stack):
        if hasattr(stack, "_pulse_source") and stack._pulse_source:
            GLib.source_remove(stack._pulse_source)
            stack._pulse_source = None

    # -- UI helpers --
    def _add_device(self, dev: DeviceInfo):
        # Check for duplicates (same IP)
        for i in range(self.store.get_n_items()):
            existing = self.store.get_item(i)
            if existing.ip == dev.ip:
                # Update existing entry if new one has more info
                if dev.method == 'nmap' and existing.method == 'ping':
                    # Replace ping result with nmap result (more detailed)
                    self.store.remove(i)
                    self.store.insert(i, dev)
                return

        self.store.append(dev)
        self.status_label.set_text(f"Found {self.store.get_n_items()} device(s)")

    def _load_local_device(self):
        def worker():
            dev = self.scanner.get_system_info()
            GLib.idle_add(self._add_device, dev)
        threading.Thread(target=worker, daemon=True).start()

    def _set_deep_scan_busy(self, busy: bool, message: str = ""):
        def update():
            if busy:
                self.detail_spinner.set_visible(True)
                self.detail_spinner.start()
                self.column_view.set_sensitive(False)
                self.more_btn.set_sensitive(False)
                self.scan_button.set_sensitive(False)
                if message:
                    self.status_label.set_text(message)
            else:
                self.detail_spinner.stop()
                self.detail_spinner.set_visible(False)
                self.column_view.set_sensitive(True)
                self.scan_button.set_sensitive(True)
                # Re-enable button if selection exists
                dev = self.selection.get_selected_item()
                self.more_btn.set_sensitive(bool(dev))
                if message:
                    self.status_label.set_text(message)
            return False
        GLib.idle_add(update)

    def _perform_deep_scan(self, dev: DeviceInfo):
        # Fallback for double click
        self._on_row_deep_scan(dev)

    def _on_row_deep_scan(self, item_or_dev):
        # item_or_dev could be the ListItem or DeviceInfo depending on call source
        if isinstance(item_or_dev, DeviceInfo):
            dev = item_or_dev
        else:
            dev = item_or_dev.get_item()

        if not dev:
            return

        if not self.scanner.nmap_available:
            self._show_nmap_warning()
            return

        if dev.is_scanning:
            return

        dev.is_scanning = True

        def worker():
            try:
                # Use privileged=True to request root access via pkexec
                result, scanner_instance = self.scanner.deep_scan_device(dev.ip, privileged=True)

                # Store scanner instance for cancellation
                if scanner_instance:
                    # Note: we should store this before starting ideally, but we get it from the call.
                    # Since deep_scan_device creates it, we might want to register it earlier if we wanted
                    # early cancellation, but here we just store it for the duration.
                    # Actually, deep_scan_device blocks. So we can't get the scanner instance back to the UI
                    # thread easily unless we refactor.
                    # Wait, deep_scan_device BLOCKS.
                    # I need to refactor deep_scan_device to return the scanner immediately
                    # OR access it differently.
                    pass

                # REFACTOR: NetworkScanner.deep_scan_device currently blocks.
                # To support cancellation from UI, we need access to the scanner object
                # WHILE it is running.
                # We should split creation and running.

                # But since I already modified deep_scan_device to create a new scanner,
                # let's modify how we call it. We can't simply call it and wait if we want to extract the scanner object.
                # Actually, I modified it to return (result, scanner). It returns AFTER the scan.
                # This defeats the purpose of cancellation if it blocks until done.

                # Correction: I need to instantiate the scanner here (or in a helper)
                # and call scan() on it.
                pass
            except Exception:
                pass

        # Improved approach: Create scanner here, register it, then run scan.
        scanner = nmap.PortScanner()
        self.active_scans[dev.ip] = scanner

        def run_scan():
            try:
                # We replicate deep_scan_device logic here to control the scanner instance
                sudo_cmd = 'pkexec'

                detail = scanner.scan(
                    hosts=dev.ip,
                    arguments='-A -sS -sV -O -T4 --script=default,discovery,safe',
                    sudo=sudo_cmd
                )

                # Process results (similar to deep_scan_device)
                sinfo = detail.get('scan', {}).get(dev.ip, {})

                osmatch = sinfo.get('osmatch', [])
                os_info = osmatch[0]['name'] if osmatch else "Unknown"
                if osmatch and 'accuracy' in osmatch[0]:
                    os_info += f" ({osmatch[0]['accuracy']}% confidence)"

                tcp = sinfo.get('tcp', {})
                udp = sinfo.get('udp', {})

                open_ports = []
                for proto, ports in [('tcp', tcp), ('udp', udp)]:
                    for port, info in ports.items():
                        if info.get('state') == 'open':
                            service = info.get('name', 'unknown')
                            version = info.get('version', '')
                            product = info.get('product', '')
                            port_info = f"{port}/{proto}/{service} {product} {version}".strip()
                            open_ports.append(port_info)

                ports_str = '\n'.join(open_ports[:20])

                addr_dict = sinfo.get('addresses', {})
                mac = addr_dict.get('mac', '')
                vendor = sinfo.get('vendor', {}).get(mac, '') if mac else ''

                hostname = sinfo.get('hostnames', [])
                hostname_str = hostname[0]['name'] if hostname else 'Unknown'

                # Update DeviceInfo
                def update_ui():
                    dev.hostname = hostname_str
                    dev.mac = mac or dev.mac
                    dev.vendor = vendor or dev.vendor
                    dev.os_info = os_info
                    dev.ports = ports_str
                    dev.is_scanning = False
                    if dev.ip in self.active_scans:
                        del self.active_scans[dev.ip]

                    # Show completion dialog (optional, but good for feedback)
                    self._show_deep_scan_dialog(dev.hostname or dev.ip,
                        f"Scan Completed.\n\nOS: {os_info}\nPorts:\n{ports_str}")

                GLib.idle_add(update_ui)

            except Exception as e:
                def update_err():
                    print(f"Deep scan error for {dev.ip}: {e}")
                    dev.is_scanning = False
                    if dev.ip in self.active_scans:
                        del self.active_scans[dev.ip]
                GLib.idle_add(update_err)

        threading.Thread(target=run_scan, daemon=True).start()

    def _on_row_cancel_scan(self, item):
        dev = item.get_item()
        if not dev:
            return

        if dev.ip in self.active_scans:
            scanner = self.active_scans[dev.ip]
            try:
                # Use the new stop method we added to nmap.PortScanner
                if hasattr(scanner, 'stop'):
                    scanner.stop()
                # Also kill if we can access the process directly
                # (handled by stop())
            except Exception as e:
                print(f"Error cancelling scan: {e}")

            del self.active_scans[dev.ip]

        dev.is_scanning = False

    def _update_scan_progress(self, fraction, message):
        self.progress.set_fraction(fraction)
        self.status_label.set_text(message)

    # -- Actions --
    def _on_scan_clicked(self, _btn):
        if self.scanning:
            return

        self.scanning = True
        self.scan_button.set_sensitive(False)
        self.scan_button.set_label("Scanning...")
        self.progress.set_visible(True)
        self.progress.set_fraction(0)

        # Keep the first row (local device) and clear the rest
        while self.store.get_n_items() > 1:
            self.store.remove(1)

        def worker():
            try:
                ip, cidr, _iface, _gw = self.scanner.get_local_ip_and_network()
                print(f"Comprehensive scan of {cidr} from {ip}")
                self.scanner.comprehensive_scan(cidr, self._add_device, self._update_scan_progress)
            finally:
                GLib.idle_add(self._scan_done)

        threading.Thread(target=worker, daemon=True).start()

    def _scan_done(self):
        self.scanning = False
        self.scan_button.set_sensitive(True)
        self.scan_button.set_label("Comprehensive Scan")
        self.progress.set_visible(False)
        self.status_label.set_text(f"Comprehensive scan completed. Found {self.store.get_n_items()} device(s)")

    def _on_refresh_clicked(self, _btn):
        # Replace first row (local) with fresh info
        if self.store.get_n_items() > 0:
            self.store.remove(0)
        self._load_local_device()

    def _on_info_clicked(self, _btn):
        ip, cidr, iface, gw = self.scanner.get_local_ip_and_network()

        lines = [
            f"Local IP: {ip}",
            f"Network: {cidr}",
            f"Default Interface: {iface or 'Unknown'}",
            f"Default Gateway: {gw or 'Unknown'}",
            "",
            "Scanning Methods:",
            "• Ping sweep: Fast ICMP ping to all network IPs",
            "• Nmap discovery: TCP SYN discovery scan",
            "• Deep scan: Comprehensive analysis (ports, OS, services)",
            "",
            "Active Interfaces:",
        ]

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, s in stats.items():
            if s.isup and name in addrs:
                ips = [a.address for a in addrs[name] if a.family == socket.AF_INET]
                lines.append(f"• {name}: {', '.join(ips) if ips else 'No IPv4'}")

        body = "\n".join(lines)
        dlg = Adw.AlertDialog(heading="Enhanced Network Scanner Info", body=body)
        dlg.add_response("ok", "OK")
        dlg.present(self)

    def _on_selection_changed(self, selection, _pspec):
        dev = selection.get_selected_item()
        self.more_btn.set_sensitive(bool(dev))

    def _on_device_activated(self, column_view, pos):
        selection = column_view.get_model()
        dev = selection.get_item(pos)
        if dev:
            self._perform_deep_scan(dev)

    def _on_deep_scan_clicked(self, _btn):
        dev = self.selection.get_selected_item()
        if dev:
            self._perform_deep_scan(dev)

    def _show_deep_scan_dialog(self, title, body):
        dlg = Adw.AlertDialog(heading=f"Deep Scan Results: {title}", body=body)
        dlg.add_response("ok", "OK")
        dlg.present(self)

# -------------------------------
# Application
# -------------------------------

class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id='com.github.juliengrdn.ipscanner')

    def do_activate(self):
        win = MainWindow(self)
        win.present()

def main():
    app = App()
    return app.run(None)

if __name__ == '__main__':
    main()
