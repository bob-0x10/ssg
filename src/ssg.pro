TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += force_debug_info
INCLUDEPATH+=$${PWD}/..
LIBS += -lpcap -pthread
DESTDIR = $${PWD}/../bin

CONFIG(debug, debug|release) DEFINES *= _DEBUG
CONFIG(release, debug|release) DEFINES *= _RELEASE

HEADERS += \
	gbeaconhdr.h \
	gcommon.h \
	gdot11hdr.h \
	gmac.h \
	gqosnullhdr.h \
	gradiotaphdr.h \
	gssg.h \
	gtrace.h

SOURCES += \
	gbeaconhdr.cpp \
	gcommon.cpp \
	gdot11hdr.cpp \
	gmac.cpp \
	gqosnullhdr.cpp \
	gradiotaphdr.cpp \
	gssg.cpp \
	gtrace.cpp \
	ssg.cpp
