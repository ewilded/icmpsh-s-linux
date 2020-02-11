# icmpsh-s-linux
GNU/Linux version of the https://github.com/inquisb/icmpsh slave

`gcc icmp-s-linux.c -o icmp-s-linux`

might want to link it statically:

`gcc icmp-s-linux.c -o icmp-s-linux -static`

Requires root, unless the user we would be running this on is allowed by the net.ipv4.ping_group_range /proc/sys/ setting (in such case just modify the source and rebuild). Works with e.g. the original icmpsh_m_py.py master (the original project linked above).
