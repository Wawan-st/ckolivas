#
# $Id$
#

%define _builddir %(pwd)

%define pkgname cgminer
%define ver 4.10.0
%define rel 1
#define dist .el7
#define _prefix /opt/miners
%define _prefix /usr
%define _modules %(echo %{modules} | tr , ' ')

Name:      	%{pkgname}
Summary:   	ASIC and FPGA miner in c for bitcoin
Version:   	%{ver} 
Release:   	%{rel}%{?dst_rel}%{?dist}
Prefix:		%{_prefix}
#Prefix:		/etc
Packager:  	EuSafe
License: 	GPLv3
Group:     	Applications/Engineering
Url:		https://github.com/eusafe/cgminer-higgs
#Requires:

Buildroot: 	%{_tmppath}/%{name}-%{version}-%(id -u -n)
BuildRequires: 	libusbx-devel ncurses-devel libcurl-devel systemd-devel

%description
This is a multi-threaded multi-pool FPGA and ASIC miner for bitcoin.


%prep
echo ./autogen.sh	
echo %{_rpmdir}/%{RPM_ARCH}/%{name}-%{version}-%{release}.%{ARCH}.rpm  %{arch}


%build
for i in %{_modules}
do
  opt="$opt --enable-$i" 
done
echo ./configure CFLAGS="-g -O2 -Wall -march=native -std=gnu99" --prefix=%{_prefix} $opt
echo make

%install
#[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
install -d %{buildroot}/%{_prefix}
install -d %{buildroot}/%{_prefix}/bin
install -m 0775  cgminer %{buildroot}/%{_prefix}/bin/

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}


%files
%doc LICENSE COPYING README AUTHORS ASIC-README FPGA-README API-README NEWS config.log
%defattr(-,root,root)
%{_prefix}/bin/cgminer


# env LANG=C date +'* %a %b %d %Y eu.safeschool at gmail.com'
%changelog
* Tue Jan 16 2018 eu.safeschool at gmail.com
- Initial build.
