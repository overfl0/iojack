LDFLAGS+=
CXXFLAGS+=-Wall
FILES=sshijack.o
EXECUTABLE=sshijack

$(EXECUTABLE): $(FILES)
	$(CXX) -o $@ $(FILES) $(CXXFLAGS) $(LDFLAGS)

$(FILES): %.o: %.cpp %.h
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	rm -f *~ *.o $(EXECUTABLE)

#sshijack.o: additionnal.h

.PHONY: clean
