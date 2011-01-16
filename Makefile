LDFLAGS+=-lpthread
CXXFLAGS+=-Wall -Wno-unused-variable
FILES=sshijack.o terminal.o
EXECUTABLE=sshijack

$(EXECUTABLE): $(FILES)
	$(CXX) -o $@ $(FILES) $(CXXFLAGS) $(LDFLAGS)

$(FILES): %.o: %.cpp %.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	rm -f *~ .gitignore~ *.o $(EXECUTABLE)

sshijack.o: terminal.h

.PHONY: clean