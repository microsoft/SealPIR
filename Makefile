CXX=g++

IDIR =../SEAL/SEAL/
LDIR =../SEAL/bin/

CFLAGS=-std=c++11 -I. -I$(IDIR) -O3
ODIR=obj
BDIR=bin
LIBS=-L$(LDIR) -lseal

DEPS = pir.hpp pir_server.hpp pir_client.hpp

_OBJ = pir.o main.o pir_server.o pir_client.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.cpp $(DEPS)
	@mkdir -p $(@D)
	$(CXX) -c -o $@ $< $(CFLAGS)

$(BDIR)/main: $(OBJ) $(DEPS) 
	@mkdir -p $(@D)
	$(CXX) -o $@ $(OBJ) $(CFLAGS) $(LIBS)

all: main

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(BDIR)/* 
