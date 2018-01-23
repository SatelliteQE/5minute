Name:	 5minute	
Version: 0.2.22	
Release: 3%{?dist}
Summary: Command line tool for getting instance from OpenStack	

License: GPLv2	
URL:	 https://github.com/SatelliteQE/5minute	
Source0: https://github.com/BlackSmith/%{name}/archive/%{version}.tar.gz	

BuildArch:      noarch
BuildRequires:  python3-devel
Requires:       python3
Requires:	python3-cinderclient 
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

