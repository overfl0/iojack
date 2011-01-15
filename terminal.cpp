#include "terminal.h"

#include <stdio.h>
#include <termios.h>

using namespace std;

termios termSettings;

void initStdin(termios &settings)
{
	tcgetattr(0, &settings);
	termios newSettings = settings;

	newSettings.c_lflag &= (~ICANON);
	newSettings.c_lflag &= (~ECHO);
	//newSettings.c_lflag &= (~ISIG);

	newSettings.c_cc[VTIME] = 0;//1; // timeout (tenths of a second)
	newSettings.c_cc[VMIN] = 0;  // minimum number of characters

	// apply the new settings
	tcsetattr(0, TCSANOW, &newSettings);
}

void deinitStdin(const termios &settings)
{
	tcsetattr(0, TCSANOW, &settings);
}

void initTerminal()
{
	initStdin(termSettings);
}

void uninitTerminal()
{
	deinitStdin(termSettings);
}

int getTerminalChar()
{
	return getchar();
}
