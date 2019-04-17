#!/usr/bin/python
#

from __future__ import print_function
from bcc import BPF
from time import sleep
import sys

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
struct key_t {
    char c[1];
};
BPF_HASH(counts, struct key_t);
int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct key_t key = {'a'};
    u64 zero = 0, *val;
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
""")

if len(sys.argv) < 1:
    print("Usage: bfp.py [fullpath to trace]")
    sys.exit(1)

b.attach_uprobe(name=sys.argv[1], sym="g", fn_name="count")

# header
print("Tracing g()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c))
