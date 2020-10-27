TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

HEADERS += \
	beacon.h \
	common.h \
	dot11.h \
	gtrace.h \
	mac.h \
	radiotap.h

SOURCES += \
	beacon.cpp \
	dot11.cpp \
	gtrace.cpp \
	mac.cpp \
	radiotap.cpp \
	timaid.cpp
