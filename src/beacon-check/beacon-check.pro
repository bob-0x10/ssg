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
	../radiotaphdr.h

SOURCES += \
	../beaconhdr.cpp \
	../beaconhdrinfo.cpp \
	../dot11.cpp \
	../gtrace.cpp \
	../mac.cpp \
	../radiotaphdr.cpp \
	beacon-check.cpp
