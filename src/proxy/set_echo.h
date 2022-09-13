#ifndef BOOST_PROXY_SET_ECHO
#define BOOST_PROXY_SET_ECHO

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace cw {
namespace helper {

bool set_echo(bool on) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if (on) {
        mode |= ENABLE_ECHO_INPUT;
    } else {
        mode &= ~ENABLE_ECHO_INPUT;
    }
    return SetConsoleMode(hStdin, mode);
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (on) {
        tty.c_lflag |= ECHO;
    } else {
        tty.c_lflag &= ~ECHO;
    }
    return tcsetattr(STDIN_FILENO, TCSANOW, &tty) == 0;
#endif
}

}
}

#endif /* BOOST_PROXY_SET_ECHO */
