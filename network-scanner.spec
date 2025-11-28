Name:           network-scanner
Version:        0.1.0
Release:        1%{?dist}
Summary:        A modern network scanner built with GTK4 and Python

License:        MIT
URL:            https://github.com/juliengrdn/network-scanner
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       nmap
Requires:       python3-psutil

%description
A modern network scanner built with GTK4, Libadwaita, and Python.
It allows scanning the local network for devices, displaying IP, Hostname,
MAC Address, and Vendor information.

%prep
%setup -q

%build
%py3_build

%install
%py3_install

# Install desktop file
mkdir -p %{buildroot}%{_datadir}/applications
install -m 644 network-scanner.desktop %{buildroot}%{_datadir}/applications/

# Install icon (assuming it's installed to /usr/share/icons/hicolor/scalable/apps/)
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -m 644 assets/logoscanner.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/network-scanner.svg

%files
%doc README.md
%license LICENSE
%{_bindir}/network-scanner
%{python3_sitelib}/network_scanner/
%{python3_sitelib}/network_scanner-*.egg-info/
%{_datadir}/applications/network-scanner.desktop
%{_datadir}/icons/hicolor/scalable/apps/network-scanner.svg

%changelog
* Mon Oct 23 2023 Julien Grdn <julien@example.com> - 0.1.0-1
- Initial package
