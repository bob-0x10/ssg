TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -pthread

INCLUDEPATH+=$${PWD}/..
DESTDIR = $${PWD}/../../bin

HEADERS += \
	../beaconhdr.h \
	../beaconhdrinfo.h \
	../common.h \
	../dot11hdr.h \
	../gtrace.h \
	../mac.h \
	../qosnullhdr.h \
	../radiotaphdr.h

SOURCES += \
	../beaconhdr.cpp \
	../beaconhdrinfo.cpp \
	../common.cpp \
	../dot11hdr.cpp \
	../gtrace.cpp \
	../mac.cpp \
	../qosnullhdr.cpp \
	../radiotaphdr.cpp \
	beacon-check.cpp
