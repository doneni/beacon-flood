LDLIBS=-lpcap

all: beacon-flood

main.o: wireless.h beacon_frame.h radiotap.h main.h main.cpp

radiotap.o: radiotap.h radiotap.cpp

beacon_frame.o: beacon_frame.h beacon_frame.cpp

wireless.o: wireless.h wireless.cpp

beacon-flood: main.o radiotap.o beacon_frame.o wireless.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f beacon-flood *.o
