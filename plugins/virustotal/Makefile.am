# Copyright 1999-2017 the Claws Mail team.
# This file is part of Claws Mail package, and distributed under the
# terms of the General Public License version 3 (or later).
# See COPYING file for license details.

plugindir = $(pkglibdir)/plugins

if BUILD_VIRUSTOTAL_PLUGIN
plugin_LTLIBRARIES = virustotal.la



endif

virustotal_la_SOURCES = \
	virustotal_plugin.c \
	virustotal_plugin_gtk.c \
	virustotal_plugin.h

virustotal_la_LDFLAGS = $(plugin_ldflags) \
	-avoid-version -module -z noexecstack

virustotal_la_LIBADD = $(plugin_libadd) \
	$(GTK_LIBS) \
	$(CURL_LIBS)

virustotal_la_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/gtk \
	$(GLIB_CFLAGS) \
	$(CURL_CFLAGS) \
	$(GTK_CFLAGS) \
	$(ENCHANT_CFLAGS)

.PHONY: test
