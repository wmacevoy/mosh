EXTRA_DIST = wrap-compiler-for-flag-check mosh.pl install.sh package-release.sh
if BUILD_CLIENT
  bin_SCRIPTS = mosh mocp
endif
CLEANFILES = $(bin_SCRIPTS)

mosh:	mosh.pl ../VERSION.stamp Makefile
	perl -Mdiagnostics -c $(srcdir)/mosh.pl
	@sed -e "s/\@VERSION\@/`cat ../VERSION.stamp`/" -e "s/\@PACKAGE_STRING\@/@PACKAGE_STRING@/" $(srcdir)/mosh.pl > mosh
	@chmod a+x mosh

# The same program: under this name it copies files.
mocp:	mosh
	@cp mosh mocp
	@chmod a+x mocp
