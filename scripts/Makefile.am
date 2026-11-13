EXTRA_DIST = wrap-compiler-for-flag-check mosh.pl install.sh package-release.sh
# The mosh and mocp commands are mosh-client under those names (see
# src/frontend/Makefile.am).  This is the Perl script they took over
# from: still built, because the tests compare the two, and installed
# as mosh.pl for anyone who depended on exactly what it did.
if BUILD_CLIENT
  noinst_SCRIPTS = mosh mocp

install-exec-local: mosh
	$(MKDIR_P) "$(DESTDIR)$(bindir)"
	$(INSTALL_SCRIPT) mosh "$(DESTDIR)$(bindir)/mosh.pl"

uninstall-local:
	rm -f "$(DESTDIR)$(bindir)/mosh.pl"
endif
CLEANFILES = mosh mocp

mosh:	mosh.pl ../VERSION.stamp Makefile
	perl -Mdiagnostics -c $(srcdir)/mosh.pl
	@sed -e "s/\@VERSION\@/`cat ../VERSION.stamp`/" -e "s/\@PACKAGE_STRING\@/@PACKAGE_STRING@/" $(srcdir)/mosh.pl > mosh
	@chmod a+x mosh

# The same program: under this name it copies files.
mocp:	mosh
	@cp mosh mocp
	@chmod a+x mocp
