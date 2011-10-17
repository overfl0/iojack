LDFLAGS+=-lpthread
CXXFLAGS+=-Wall
FILES=iojack.o terminal.o syscallToStr.o buffer.o processes.o syscalls.o
EXECUTABLE=iojack

$(EXECUTABLE): $(FILES)
	$(CXX) -o $@ $(FILES) $(CXXFLAGS) $(LDFLAGS)

$(FILES): %.o: %.cpp %.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	rm -f *~ .gitignore~ *.o $(EXECUTABLE)

iojack.o: terminal.h syscallToStr.h buffer.h processes.h syscalls.h
processes.o: iojack.h
syscalls.o: iojack.h buffer.h
syscallToStr.o: iojack.h

.PHONY: clean
