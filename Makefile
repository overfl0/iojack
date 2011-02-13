LDFLAGS+=-lpthread
CXXFLAGS+=-Wall
FILES=sshijack.o terminal.o syscallToStr.o buffer.o processes.o syscalls.o
EXECUTABLE=sshijack

$(EXECUTABLE): $(FILES)
	$(CXX) -o $@ $(FILES) $(CXXFLAGS) $(LDFLAGS)

$(FILES): %.o: %.cpp %.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	rm -f *~ .gitignore~ *.o $(EXECUTABLE)

sshijack.o: terminal.h syscallToStr.h buffer.h processes.h syscalls.h
processes.o: sshijack.h
syscalls.o: sshijack.h buffer.h
syscallToStr.o: sshijack.h

.PHONY: clean
