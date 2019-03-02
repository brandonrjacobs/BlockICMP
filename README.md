# BlockICMP


/*
 * block_allICMP - block all ICMP packets with remote host source or destination address
 * block_inICMP  - block incoming ICMP ECHO packets and outgoing ICMP ECHOREPLY packets
 *
 * This program handles both security policies - name of program invoked determines which
 * security policy is in effect. Compile the file block_allICMP.c and then do the following:
 *
 * ln -s block_allICMP block_inICMP
 *
 * Invoke block_allICMP or block_inICMP to see how different security policies behave
 *
 * Arguments: -v (verbose mode, recommended)
 *            -p port  (specifies the divert port, default is 2000)
 *
 * Note: divert port must match the port specified in the ipfw rule
 *
 * Program depends on ipfw configuration - the following rule should be created for
 * ipfw and it should preceed any rules that would otherwise accept or reject icmp
 * packets before they are diverted by the kernel to this program.
 *
 *	ipfw add 100 divert 2000 icmp from any to any
 *
 */
