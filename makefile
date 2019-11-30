CXX=g++

all: main.o analysis.o encryption.o handlers.o user_interface.o
	$(CXX) -o sdes main.cpp analysis.cpp encryption.cpp handlers.cpp user_interface.cpp

main.o: main.cpp analysis.h encryption.h handlers.h user_interface.h definitions.h globals.h

analysis.o : analysis.cpp analysis.h user_interface.h encryption.h definitions.h handlers.h globals.h

encryption.o: encryption.cpp encryption.h handlers.h definitions.h analysis.h globals.h

handlers.o: handlers.cpp handlers.h user_interface.h analysis.h encryption.h definitions.h globals.h

user_interface.o: user_interface.cpp user_interface.h handlers.h definitions.h globals.h analysis.h

clean:
	del /f *.o *.exe *.gch