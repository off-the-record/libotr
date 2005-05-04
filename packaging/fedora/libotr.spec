Summary: Off-The-Record Messaging libraray and toolkit
Name: libotr
%define majver 2
%define minver 0.2
Version: %{majver}.%{minver}
%define debug_package %{nil}
%define ourrelease 1
Release: %{ourrelease}
Source: http://www.cypherpunks.ca/otr/libotr-%{majver}.%{minver}.tar.gz
BuildRoot: %{_tmppath}/%{name}-buildroot
Url: http://www.cypherpunks.ca/otr/
Vendor: Nikita Borisov and Ian Goldberg <otr@cypherpunks.ca>
Packager: Paul Wouters <paul@cypherpunks.ca>
License: GPL
Group: Applications/Internet
%define __spec_install_post /usr/lib/rpm/brp-compress || :

%package toolkit
Summary: the otr toolkit
Group: Applications/Internet
Provides: libotr
Obsoletes: gaim-otr <= 1.0.2
BuildRequires: libgcrypt-devel >= 1.2.0, libgpg-error-devel 
Requires: libgcrypt >= 1.2.0
Release: %{ourrelease}

%package devel
Summary: the otr library and include files
Group: Applications/Internet
Release: %{ourrelease}
Requires: libotr = 2.0.2


%description toolkit

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


%description devel
              Off-the-Record Messaging Library and Toolkit
			  v2.0.2,  3 May 2005

The devel package contains the libotr library and the include files

%description
A dummy to satisfy rpm 

%prep
%setup -q -n libotr-%{majver}.%{minver}

%build
%configure --with-pic --prefix=%{_prefix} --libdir=%{_libdir} --mandir=%{_mandir}
%{__make} \
	CFLAGS="${RPM_OPT_FLAGS}" \
	all

%install
rm -rf ${RPM_BUILD_ROOT}
%{__make} \
	DESTDIR=${RPM_BUILD_ROOT} \
	LIBINSTDIR=%{_libdir} \
	install

%clean
rm -rf ${RPM_BUILD_ROOT}

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
%{_libdir}/libotr.la
%{_includedir}/libotr/*
%{_datadir}/aclocal/*


%changelog
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

