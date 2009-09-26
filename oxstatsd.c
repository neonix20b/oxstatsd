#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/wait.h>

#include <pcre.h>
#include <libpq-fe.h>

#include <oxdigest.h>

#define BUFSIZE 8096
#define ERROR 42
#define SORRY 43
#define LOG   44

#define OVECCOUNT 30

#define PATTERN "put_stats/(.{32,32})/([A-Za-z0-9-_.]+)/(true|false)"
#define QUERY "INSERT INTO shows(domain,ip,returned) VALUES($1,$2,$3)"
#define QUERY_NAME "ox_stats_insert"

#define TOLERANCE 2*60 //two minutes

#define PREFORK 30

pcre *re;
const char *conninfo = "host = localhost dbname = stats user = postgres sslmode = disable";
PGconn     *conn;

void die_log(const char* msg) {
	syslog(LOG_EMERG, msg);
	closelog();
	PQfinish(conn);
	exit(1);
}

void connect_db() {
	conn = PQconnectdb(conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		die_log(PQerrorMessage(conn));
	}

	PGresult *res = PQprepare(conn, QUERY_NAME, QUERY, 3, NULL);
	if(PQresultStatus(res) != PGRES_COMMAND_OK) {
		PQclear(res);
		die_log(PQerrorMessage(conn));
		/*try to reconnect*/
		PQfinish(conn);
	}
}


void web(int fd, const char* ip)
{
	long i, ret;
	static char buffer[BUFSIZE+1]; /* static so zero filled */
	int ovector[OVECCOUNT];
	int rc;

	
	ret =read(fd,buffer,BUFSIZE); 	/* read Web request in one go */
	if(ret == 0 || ret == -1) {	/* read failure stop now */
		return;
	}
	if(ret > 0 && ret < BUFSIZE)	/* return code is valid chars */
		buffer[ret]=0;		/* terminate the buffer */
	else buffer[0]=0;

	

	for(i=4;i<BUFSIZE;i++) { /* null terminate after the second space to ignore extra stuff */
		if(buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
			buffer[i] = 0;
			break;
		}
	}

	rc = pcre_exec(re,NULL,buffer,strlen(buffer),0,0,ovector,OVECCOUNT);
	if(rc != -1) {
		const char* digest = 0;
		const char* domain = 0;
		const char* returned = 0;
		pcre_get_substring(buffer,ovector,rc,1,&digest);
		if(digest_offset(digest) > TOLERANCE) {
			pcre_free_substring(digest);
			goto answer;
		}
		pcre_get_substring(buffer,ovector,rc,2,&domain);
		pcre_get_substring(buffer,ovector,rc,3,&returned);
		const char * params[3];
		params[0] = domain;
		params[1] = ip;
		params[2] = returned;
		int lengths[3] = {strlen(domain), strlen(ip), strlen(returned)};
		PGresult* res = PQexecPrepared(conn, QUERY_NAME, 3, params, lengths, NULL, 0);
		if(PQresultStatus(res) != PGRES_COMMAND_OK) {
			PQclear(res);
	                die_log(PQerrorMessage(conn));
	        }
		PQclear(res);
		pcre_free_substring(digest);
		pcre_free_substring(domain);
		pcre_free_substring(returned);

	}
answer:
	sprintf(buffer,"HTTP/1.0 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Cache-Control: post-check=0, pre-check=0\r\n"
		"Pragma: no-cache\r\nExpires: Mon, 26 Jul 1997 05:00:00 GMT\r\n\r\n");
	write(fd,buffer,strlen(buffer));
	sleep(1);	/* to allow socket to drain */
}

int listenfd;

/* this is a child web server process, so we can exit on errors */
void child() {
	int pid, socketfd;
	static struct sockaddr_in cli_addr; /* static = initialised to zeros */
	size_t length;
	if((pid = fork()) < 0)
		die_log("fork syscall failed");
	if(pid) return;
	/* child */
	connect_db();
	for(;;) {
		length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
			die_log("accept syscall failed");
		char buf[30];
		inet_ntop(AF_INET, &cli_addr.sin_addr, buf, 30);
		web(socketfd, buf);
		close(socketfd);
	}
}


void catch_sigcld(int signum) {
	int status;
	wait(&status);
	syslog(LOG_ERR,"child died - respawned");
	child(listenfd);
}

int main(int argc, char **argv)
{
	int i, k;
	int port;
	static struct sockaddr_in serv_addr; /* static = initialised to zeros */

	if( argc != 3 ) {
		printf("oxstatsd ip port\n");
		exit(0);
	}

	/* Become deamon + unstopable and no zombies children (= no wait()) */
	if(fork() != 0)
		return 0; /* parent returns OK to shell */
	signal(SIGCLD, catch_sigcld); /* ignore child death */
	signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
	for(i=0;i<32;i++)
		close(i);		/* close open files */
	setpgrp();		/* break away from process group */

	openlog("oxstatsd", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO,"starting");
	
	/* setup pcre */
	const char *error;
	int erroffset;
	re = pcre_compile(PATTERN,0,&error,&erroffset,NULL);
        if (re == NULL) {
        	char buf[256];
        	sprintf(buf, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
        	die_log(buf);
        }
	/* setup the network socket */
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0)
		die_log("socket syscall failed");
	port = atoi(argv[2]);
	if(port < 0 || port >60000) 
		die_log("Invalid port number (try 1->60000)");
	serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, argv[1], &serv_addr.sin_addr);
	serv_addr.sin_port = htons(port);
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0)
		die_log("bind syscall failed");
	if( listen(listenfd,128) <0)
		die_log("listen syscall failed");
	for(k = 0; k < PREFORK; k++) {
		child();
	}
	syslog(LOG_INFO,"children prefork completed, going idle");
	for(;;)
		pause();
}

