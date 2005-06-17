Summary: Off-The-Record Messaging library and toolkit
Name: libotr
Version: 2.0.2
Release: 2%{?dist}
License: GPL
Group: Applications/Internet
Source0: http://www.cypherpunks.ca/otr/%{name}-%{version}.tar.gz
Url: http://www.cypherpunks.ca/otr/
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Provides: libotr-toolkit = %{version}
Obsoletes: libotr-toolkit
BuildRequires: libgcrypt-devel >= 1.2.0, libgpg-error-devel 

%description

              Off-the-Record Messaging Library and Toolkit
                          v2.0.2,  3 May 2005

This is a library and toolkit which implements Off-the-Record (OTR) Messaging.

OTR allows you to have private conversations over IM by providing:
 - Encryption
   - No one else can read your instant messages.
 - Authentication
   - You are assured the correspondent is who you think it is.
 - Deniability
   - The messages you send do _not_ have digital signatures that are
     checkable by a third party.  Anyone can forge messages after a
     conversation to make them look like they came from you.  However,
     _during_ a conversation, your correspondent is assured the messages
     he sees are authentic and unmodified.
 - Perfect forward secrecy
   - If you lose control of your private keys, no previous conversation
     is compromised.

For more information on Off-the-Record Messaging, see
http://www.cypherpunks.ca/otr/

%package devel
Summary: Development library and include files for libotr
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}

%description devel

The devel package contains the libotr library and the include files

%prep
%setup -q

%build
%configure --with-pic
make %{?_smp_mflags} all

%install
rm -rf $RPM_BUILD_ROOT
make \
	DESTDIR=$RPM_BUILD_ROOT \
	LIBINSTDIR=%{_libdir} \
	install
rm -rf $RPM_BUILD_ROOT%{_libdir}/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files 
%defattr(-,root,root)
%doc README COPYING COPYING.LIB Protocol
%{_libdir}/libotr.so.*
%{_bindir}/*
%{_mandir}/man1/*

%files devel
%doc README COPYING.LIB 
%{_libdir}/libotr.so
%{_libdir}/libotr.a
%dir %{_includedir}/libotr
%{_includedir}/libotr/*
%{_datadir}/aclocal/*


%changelog
* Fri Jun 17 2005 Tom "spot" Callaway <tcallawa@redhat.com>
- reworked for Fedora Extras

* Tue May  3 2005 Ian Goldberg <ian@cypherpunks.ca>
- Bumped version number to 2.0.2
* Wed Feb 16 2005 Ian Goldberg <ian@cypherpunks.ca>
- Bumped version number to 2.0.1
* Tue Feb  8 2005 Ian Goldberg <ian@cypherpunks.ca>
- Bumped version number to 2.0.0
* Wed Feb  2 2005 Ian Goldberg <ian@cypherpunks.ca>
- Added libotr.m4 to the devel package
- Bumped version number to 1.99.0
* Wed Jan 19 2005 Paul Wouters <paul@cypherpunks.ca>
- Updated spec file for the gaim-otr libotr split
* Tue Dec 21 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 1.0.2.
* Fri Dec 17 2004 Paul Wouters <paul@cypherpunks.ca>
- instll fix for x86_64
* Sun Dec 12 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 1.0.0.
* Fri Dec 10 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.9rc2. 
* Thu Dec  9 2004 Ian Goldberg <otr@cypherpunks.ca>
- Added CFLAGS to "make all", removed DESTDIR
* Wed Dec  8 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.9rc1. 
* Fri Dec  3 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped to version 0.9.1. 
* Wed Dec  1 2004 Paul Wouters <paul@cypherpunks.ca>
- Bumped to version 0.9.0. 
- Fixed install for tools and cos
- Added Obsoletes: target for otr-plugin so rpm-Uhv gaim-otr removes it.
* Mon Nov 22 2004 Ian Goldberg <otr@cypherpunks.ca>
- Bumped version to 0.8.1
* Sun Nov 21 2004 Paul Wouters <paul@cypherpunks.ca>
- Initial version

