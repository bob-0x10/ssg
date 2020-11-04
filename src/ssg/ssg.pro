TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += force_debug_info
INCLUDEPATH+=$${PWD}/..
LIBS += -lpcap -pthread
DESTDIR = $${PWD}/../../bin

HEADERS += \
	../gbeaconhdr.h \
	../gbeaconhdrinfo.h \
	../gcommon.h \
	../gconfig.h \
	../gdot11hdr.h \
	../gmac.h \
	../gqosnullhdr.h \
	../gradiotaphdr.h \
	../gssg.h \
	../gtrace.h \

SOURCES += \
	../gbeaconhdr.cpp \
	../gbeaconhdrinfo.cpp \
	../gcommon.cpp \
	../gconfig.cpp \
	../gdot11hdr.cpp \
	../gmac.cpp \
	../gqosnullhdr.cpp \
	../gradiotaphdr.cpp \
	../gssg.cpp \
	../gtrace.cpp \
	ssg.cpp
