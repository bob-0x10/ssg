TARGET=ssg

#CXXFLAGS+=-I/root/android/sysroot/include
#LDFLAGS+=-L/root/android/sysroot/lib
CXXFLAGS+=-O2
LDFLAGS+=-O2
LDLIBS+=-lpcap -pthread

all: $(TARGET)

$(TARGET): $(TARGET).o gbeaconhdr.o gcommon.o gdot11hdr.o gmac.o gqosnullhdr.o gradiotaphdr.o gssg.o gtrace.o
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) *.o
