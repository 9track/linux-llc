%define name linux-llc
%define ver  VERSION
%define rel  1
%define vendor linux-SNA Project
%define distro linux-SNA Enterprise Multiprotocol Suite
%define packager jschlst@samba.org
%define kernel_dir KERNELDIR

Vendor: %{vendor}
Distribution: %{distro}
Packager: %{packager}
Name: %{name}
Version: %{ver}
Release: %{rel}
Summary: linux-LLC network communications software.
Copyright: GPL
Group: Networking/Admin
URL: ftp://ftp.linux-sna.org/pub/linux-llc/
Source0: ftp.linux-sna.org/pub/linux-llc/%{name}-%{ver}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}-%{release}-root

%package dlsw
Summary: linux-DLSw data link switching software suite.
Group: Networking/Admin

%package lar
Summary: linux-LAR lan address resolution software suite.
Group: Networking/Admin

%package llcping
Summary: LLCping provides diagnotic information on llc links and hosts.
Group: Networking/Admin

%description
Various user-space software components to enable linux-LLC communications.

%description dlsw
Dlsw protocol suite provides intelligent LLC bridging over IP.

%description lar
Lar protocol suite provides dynamic LLC host address resolution.

%description llcping
LLCping provides diagnostic information on remote LLC hosts.

%changelog
* Fri Nov 30 2001 Jay Schulist <jschlst@samba.org>
- Created linux-llc RPM

%prep
%setup -q -n linux-llc-%{ver}
./configure --prefix=${RPM_BUILD_ROOT}/usr

%build
make KERNEL_DIR=%{kernel_dir}

%install
install -D -m 644 docs/llchosts.xml $RPM_BUILD_ROOT/etc/llchosts.xml
install -D -m 644 docs/lard.xml $RPM_BUILD_ROOT/etc/lard.xml
install -D -m 644 docs/dlswd.xml $RPM_BUILD_ROOT/etc/dlswd.xml
install -D -m 644 docs/llcpingd.xml $RPM_BUILD_ROOT/etc/llcpingd.xml
install -D -m 755 docs/lard.init $RPM_BUILD_ROOT/etc/rc.d/init.d/lard.init
install -D -m 755 docs/dlswd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/dlswd.init
install -D -m 755 docs/llcpingd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/llcpingd.init
make mandir=$RPM_BUILD_ROOT/usr/share/man install

%post

if [ "$1" = 1 ]; then
	# add these lines to modules.conf
	if (grep 'linux-llc' /etc/modules.conf >/dev/null); then
                cat <<'_EOD1_' >&2
warning: The module parameters appear to be present in /etc/modules.conf.
warning: Please check them against modules.conf.llc in the documentation.
_EOD1_
                true
        else
                cat <<'_EOD2_' >>/etc/modules.conf
# start of linux-llc module configuration
alias pf-26 llc
# end of linux-llc module configuration
_EOD2_
        fi
fi

%post lar
chkconfig --add lard.init

%post dlsw
chkconfig --add dlswd.init

%post llcping
chkconfig --add llcpingd.init

%postun
# do only for the last un-install
if [ "$1" = 0 ]; then
        # remove the linux-llc lines from /etc/modules.conf
        if (grep '^# start of linux-llc module configuration$' /etc/modules.conf >/dev/null && \
            grep '^# end of linux-llc module configuration$'   /etc/modules.conf >/dev/null ); then
          sed -e '/^# start of linux-llc module configuration$/,/^# end of linux-llc module configuration$/d' \
            </etc/modules.conf >/tmp/modules.conf.tmp$$
          cat /tmp/modules.conf.tmp$$ >/etc/modules.conf
          rm /tmp/modules.conf.tmp$$
        else
          cat <<'_EOD3_' >&2
warning: Unable to find the lines `# start of linux-llc module configuration` and
warning: `# end of linux-llc module configuration` in the file /etc/modules.conf
warning: You should remove the linux-llc module configuration from /etc/modules.conf manually.
_EOD3_
        fi
fi

%preun lar
chkconfig --del lard.init

%preun dlsw
chkconfig --del dlswd.init

%preun llcping
chkconfig --del llcpingd.init

%clean
if [ ! RPM_BUILD_ROOT = / ]; then
	rm -rf ${RPM_BUILD_ROOT}
fi

%files dlsw
%defattr(-, root, root)
%config /etc/dlswd.xml
/etc/rc.d/init.d/dlswd.init
/usr/sbin/dlswd
/usr/share/man/man8/dlswd.8.gz
%doc docs/dlswd.xml docs/services.dlsw
%doc docs/rfc1434.html docs/rfc1434.pdf docs/rfc1795.html docs/rfc1795.pdf docs/rfc2166.html docs/rfc2166.pdf

%files lar
%defattr(-, root, root)
%config /etc/lard.xml
/etc/rc.d/init.d/lard.init
/usr/bin/llookup
/usr/sbin/lard
/usr/lib/liblar*
/usr/include/lar.h
/usr/share/man/man3/lar.3.gz
/usr/share/man/man8/lard.8.gz
/usr/share/man/man8/llookup.8.gz
%doc docs/lard.xml docs/larhosts.xml

%files llcping
%defattr(-, root, root)
%config /etc/llcpingd.xml
%config /etc/llchosts.xml
/etc/rc.d/init.d/llcpingd.init
/usr/bin/llcping
/usr/sbin/llcpingd
/usr/lib/libllcdb*
/usr/include/llcdb.h
/usr/share/man/man8/llcping.8.gz
/usr/share/man/man8/llcpingd.8.gz
%doc docs/llchosts.xml docs/llcpingd.xml docs/llcping.txt

%files
%defattr(-, root, root)
/usr/share/man/man7/*
%doc BUGS COPYING ChangeLog INSTALL NEWS TODO README THANKS
%doc docs/linux-llc.spec docs/modules.conf.llc
%doc docs/find_sk_by_addr.txt docs/llc-sap-note.txt docs/llc.txt docs/test-plan.txt
