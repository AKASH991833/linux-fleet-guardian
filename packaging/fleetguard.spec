Name:           fleetguard
Version:        %{?fg_version}%{!?fg_version:0.1.0}
Release:        1%{?dist}
Summary:        Audit, fix, back up and watch Linux fleets
License:        MIT
URL:            https://github.com/AKASH991833/linux-fleet-guardian
BuildArch:      noarch
Requires:       python3
Source0:        %{name}-%{version}.tar.gz

%description
CIS-style checks, drift detection, reversible fixes with automatic rollback,
backup restore-tests, DR drills, performance anomaly detection, incident
timelines, a read-only web panel and Prometheus metrics. Standard library only.

%prep
%setup -q

%build

%install
install -d %{buildroot}/usr/lib/fleetguard %{buildroot}%{_bindir} \
  %{buildroot}%{_datadir}/fleetguard/plugins %{buildroot}%{_sysconfdir}/fleetguard \
  %{buildroot}%{_unitdir} %{buildroot}%{_docdir}/fleetguard
cp -r fleetguard %{buildroot}/usr/lib/fleetguard/
find %{buildroot}/usr/lib/fleetguard -name __pycache__ -prune -exec rm -rf {} +
printf '#!/bin/sh\nPYTHONPATH=/usr/lib/fleetguard exec python3 -m fleetguard "$@"\n' > %{buildroot}%{_bindir}/fleetguard
chmod 755 %{buildroot}%{_bindir}/fleetguard
cp plugins/* %{buildroot}%{_datadir}/fleetguard/plugins/
cp README.md LICENSE %{buildroot}%{_docdir}/fleetguard/
cp packaging/fleetguard.service %{buildroot}%{_unitdir}/
cp packaging/inventory.ini packaging/fleetguard.env %{buildroot}%{_sysconfdir}/fleetguard/

%files
/usr/lib/fleetguard
%{_bindir}/fleetguard
%{_datadir}/fleetguard
%{_unitdir}/fleetguard.service
%config(noreplace) %{_sysconfdir}/fleetguard/inventory.ini
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/fleetguard/fleetguard.env
%doc %{_docdir}/fleetguard/README.md
%license %{_docdir}/fleetguard/LICENSE

%changelog
* Thu Oct 22 2026 Akash Vishwakarma <noreply@users.noreply.github.com> - 0.1.0-1
- Initial release
