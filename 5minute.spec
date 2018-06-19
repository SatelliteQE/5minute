Name:	 5minute
Version: 0.2.31

Release: 0%{?dist}
Summary: Command line tool for getting instance from OpenStack

License: GPLv2
URL:     https://github.com/SatelliteQE/5minute
Source0: https://github.com/SatelliteQE/%{name}/archive/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3
BuildRequires:  python3-cinderclient
BuildRequires:  python3-heatclient
BuildRequires:  python3-neutronclient
BuildRequires:  python3-xmltodict
BuildRequires:  python3-prettytable
BuildRequires:  python3-novaclient
BuildRequires:  python3-keystoneclient
BuildRequires:  python3-glanceclient
Requires:       python3
Requires:       python3-cinderclient
Requires:       python3-heatclient
Requires:       python3-neutronclient
Requires:       python3-xmltodict
Requires:       python3-prettytable
Requires:       python3-novaclient
Requires:       python3-keystoneclient
Requires:       python3-glanceclient

%description
Give me an instance of mine image on OpenStack. Hurry!

%prep
%autosetup -n %{name}-%{version}


%build
%py3_build

%install
%py3_install

%check
%{__python3} setup.py test

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{python3_sitelib}/*

%changelog
* Tue Jun 19 2018 Martin Korbel <mkorbel@redhat.com> - 0.2.31-0
- The better detection of end of the installation
- The option and non-option arguments can be intermixed (GNU style scanning mode)
- Update cinderclient to API v2
