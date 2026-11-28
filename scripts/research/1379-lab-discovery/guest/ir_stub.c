/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Stand-in second backend for the B03 next-phase gate. It touches no device. */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    /* Only PID 1 writes the console: stdin and stderr must refuse writes. */
    if (write(0, "", 0) != -1 || errno != EBADF || write(2, "", 0) != -1 || errno != EBADF)
        return 1;
    return puts("IR_STUB_RAN") < 0;
}
