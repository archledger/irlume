/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Stand-in second backend for the B03 next-phase gate. It touches no device. */
#include <stdio.h>

int main(void)
{
    return puts("IR_STUB_RAN") < 0;
}
