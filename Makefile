CPP=g++

IDIR = ../SEAL/SEAL/
LDIR = ../SEAL/bin/
ODIR=obj
BDIR=bin

CFLAGS=-std=c++11 -I. -I$(IDIR) -O3
LIBS=-L$(LDIR) -lseal

_DEPS = pir.hpp
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = pir.o main.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CPP) -c -o $@ $< $(CFLAGS)

$(BDIR)/main: $(OBJ)
	@mkdir -p $(@D)
	$(CPP) -o $@ $^ $(CFLAGS) $(LIBS)

all: main

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(BDIR)/* 
