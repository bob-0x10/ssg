TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
DEFINES += GTEST
LIBS += -lgtest_main -lgtest -pthread

HEADERS += \
	beacon.h \
	common.h \
	dot11.h \
	mac.h \
	radiotap.h

SOURCES += \
	beacon.cpp \
	dot11.cpp \
	mac.cpp \
	radiotap.cpp
