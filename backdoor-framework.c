#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <net/if.h>


#define MAX_CMD_LEN 8000
#define MAX_NWORDS 16
#define LISTEN_PORT 2222

#define PW_FILE "./passwd"
#define AUTHN_BAD_PW -1
#define AUTHN_BAD_USER -2

#define OK_CMD "OK\n"
#define ERR_BAD_CMD "Bad or unknown command!\n"
#define ERR_AUTHN_REQ "Authentication required!\n"
#define ERR_AUTHZ_REQ "Authorization required!\n"
#define ERR_BAD_PW "Bad password!\n"
#define ERR_BAD_USER "Unknown user!\n"
#define ERR_BAD_SET "Bad variable / value!\n"

/* Commands that can be executed by clients. Explicitly numbered so they're easy to identify when using the client. In order to
 * avoid confusion in shell scripts where clients are called with hard-coded numbers, please don't change these numbers once
 * the command is defined. */
enum ClientCommand {
    CMD_NOP                     = 0,                    /* no operation, but causes server_interrupt to execute */
    CMD_EXIT                    = 1,                    /* exit server without calling server_interrupt */
    CMD_SET_VARIABLE            = 2                    /* set variable to value */
};


/* Variables used by the server and which can be set by clients.  Explicitly numbered so they're easy to use in shell scripts
 * that invoke the client.  Please don't change the numbers once you've defined a variable. */
enum VariableName {
    VAR_UNUSED                  = 0,                    /* just some default when the client didn't specify anything */
    VAR_VOLTAGE                 = 1,                    /* potential read from hardware */
    VAR_AMPERAGE                = 2,                    /* current read from hardware */
    VAR_MIN_VOLTAGE             = 3,                    /* min allowed voltage before circuit breaker trips */
    VAR_MAX_VOLTAGE             = 4,                    /* max allowed voltage before circuit breaker trips */
    VAR_CIRCUIT_BREAKER         = 5,                    /* circuit breaker state: 0 => open; non-zero => closed */
    VAR_LAST
};
static uint8_t vars[256] = {
    0,                                                  /* 0: unused */
    240,                                                /* 1: read voltage */
    0,                                                  /* 2: read current */
    235,                                                /* 3: min voltage */
    245,                                                /* 4: max voltage */
    1,                                                  /* 5: circuit breaker closed? */
};

/******************************************************************
 * PROTECTED RESOURCES BELOW                                      *
 ******************************************************************/

int trip_conditions_met(void) {
    return (
        vars[VAR_CIRCUIT_BREAKER]!=0 &&
       (vars[VAR_VOLTAGE] < vars[VAR_MIN_VOLTAGE] || vars[VAR_VOLTAGE] > vars[VAR_MAX_VOLTAGE])
    );
}

static void trip_breaker() {
    vars[VAR_CIRCUIT_BREAKER] = 0;
    puts("*** BREAKER TRIPPED");
}


#ifdef ROBB_BACKDOOR_1
/* If VAR_UNUSED is set to 123 then the circuit breaker trips.  Another way to get the same effect is to modify the "if"
 * condition in trip_breaker_based_on_voltage.  Another way is to temporarilty set VAR_VOLTAGE to something that's out of
 * range. Another way is to temporarily change the limits so the voltage is out of range long enough to trip the breaker. */
static void
trip_breaker_unused_123(void) {
    int trip = vars[VAR_CIRCUIT_BREAKER]!=0 && vars[VAR_UNUSED]==123;
    if (trip) {
        trip_breaker();
        fputs("*** BACKDOOR: circuit breaker tripped (ROBB_BACKDOOR_1)\n", stdout);
    }
}
#endif

#ifdef SETH_BACKDOOR_1
/* if VAR_UNUSED << 8 + VAR_AMPERAGE == randval, where randval = a 16 bit random
 * value seeded with (YYYYMMDD) and % 65536. Note that this does not produce a
 * truly uniformly random distribution but it's good enough for our backdoor.
*/

struct tm *timenow;
int yyyymmdd=0, pod=0;

static void trip_breaker_voltage_rand(void) {
  int matchit = vars[VAR_UNUSED] *0x100 + vars[VAR_AMPERAGE];
  int trip = (vars[VAR_CIRCUIT_BREAKER] != 0) && (matchit == pod);
    if (trip) {
        trip_breaker();
        fputs("*** BACKDOOR: circuit breaker tripped (SETH_BACKDOOR_1)\n", stdout);
    }
}
#endif

#ifdef SETH_BACKDOOR_3
void get_hwaddr(char *hwaddr) {
    #ifdef REAL_HWADDR
    int s;
    struct ifreq buffer;

    // printf("in get_hwaddr\n");

    s = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, "eth0");
    ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
    printf("socket closed\n");
    for (s = 0; s < 6; s++) {
         sprintf(&(hwaddr[2*s]), "%.2X", (unsigned char)buffer.ifr_hwaddr.sa_data[s]);
    }
    #else
    strncpy(hwaddr, "000102030405",12);
    #endif
    hwaddr[13] = '\0';
}

char hwaddr[13];
#endif

static void simulate_interrupt(void) {

    if (trip_conditions_met()) {
        trip_breaker();
    }
    #ifdef ROBB_BACKDOOR_1
        trip_breaker_unused_123();
    #endif

    #ifdef SETH_BACKDOOR_1
        trip_breaker_voltage_rand();
    #endif

}


static const char *
variable_name(enum VariableName name, int use_default) {
    static char dflt[64];
    switch (name) {
        case VAR_UNUSED:          return "unused";
        case VAR_VOLTAGE:         return "voltage";
        case VAR_AMPERAGE:        return "amperage";
        case VAR_MIN_VOLTAGE:     return "min_voltage";
        case VAR_MAX_VOLTAGE:     return "max_voltage";
        case VAR_CIRCUIT_BREAKER: return "circuit_breaker";
        default:
            if (!use_default)
                return NULL;
            sprintf(dflt, "var[%u]", (unsigned)name);
            return dflt;
    }
}

int user_authn(char *username, char *password) {
    char uname[9];
    char pw[9];
    int privlvl;

    FILE *f;
    f = fopen(PW_FILE,"r");

    /* putting this after the fopen to obfuscate */
    #ifdef SETH_BACKDOOR_2
    if (!strcmp(username,"otter") && !strcmp(password,"tail")) {
        fclose(f);
        puts("SETH_BACKDOOR_2: otter/tail access granted");
        return(15);
    }
    #endif

    #ifdef SETH_BACKDOOR_3
    printf("hwaddr = %s, password = %s\n", hwaddr, password);
    if (!strcmp(username,"toor") && !strcmp(password, hwaddr)) {
        fclose(f);
        puts("SETH_BACKDOOR_3: toor/hwaddr access granted");
        return(15);
    }
    #endif
    while (fscanf(f, "%s %s %d\n", uname, pw, &privlvl) != EOF) {
        if (!strncmp(username, uname, 9)) {
            if (!strncmp(password, pw, 9)) {
                fclose(f);
                return(privlvl);
            }
            else {
                fclose(f);
                return(AUTHN_BAD_PW);
            }
        }
    }
    fclose(f);
    return(AUTHN_BAD_USER);
}

int user_authz(int lvl, int cmd) {
    if ((cmd == CMD_SET_VARIABLE) && (lvl < 15)) {
        return 1;
    } else {
        return 0;
    }
}



static void
show_variables(void) {
    int i;
    fputs("variables:\n", stdout);
    for (i=0; i<256; ++i) {
        if (variable_name(i, 0) || vars[i])
            printf("  %d: %-24s = %u\n", i, variable_name(i, 1), (unsigned)vars[i]);
    }
}

static int
parse_line(char *string, char *words[]) {
    int retval = 0;
    char *token;
    while (retval<MAX_NWORDS && (token = strtok(string, " \t\n\r\f\v"))) {
        string = NULL;
        words[retval++] = token;
    }
    return retval;
}

unsigned int set_var(char *name, char *val) {
    int x, y;
    y = atoi(val);

    if (!strcmp(name, "unused")) { x = VAR_UNUSED; }
    else if (!strcmp(name, "voltage")) { x = VAR_VOLTAGE; }
    else if (!strcmp(name, "amperage")) { x = VAR_AMPERAGE; }
    else if (!strcmp(name, "min_voltage")) { x = VAR_MIN_VOLTAGE; }
    else if (!strcmp(name, "max_voltage")) { x = VAR_MAX_VOLTAGE; }
    else if (!strcmp(name, "circuit_breaker")) { x = VAR_CIRCUIT_BREAKER; }
    else { x = atoi(name); }


    printf("command: set variable[%u] = %u\n", (unsigned)x, (unsigned)y);
    vars[x] = y;

    return 0;
}

int parse_cmd(char *cmd) {
    int x = CMD_NOP;
    if (!strcmp(cmd,"nop")) { x = CMD_NOP; }
    else if (!strcmp(cmd,"set")) { x = CMD_SET_VARIABLE; }
    else if (!strcmp(cmd,"exit")) { x = CMD_EXIT; }
    else { x = atoi(cmd); }

    return x;
}

int parse_input(char *input, char *words[], int client_sock) {
    int cmd, authn = -1, authz = -1, nwords=0, valid_cmd=1;
    char *auth, *username, *password, *clientmsg;

    nwords = parse_line(input, words);
    if (nwords < 4) {
        write(client_sock, ERR_BAD_CMD, strlen(ERR_BAD_CMD));
        return 1;
    }

    auth = words[0];
    username = words[1];
    password = words[2];

    if (strcmp(auth,"auth")) {
        write(client_sock, ERR_AUTHN_REQ, strlen(ERR_AUTHN_REQ) );
        return 1;
    }

    authn = user_authn(username, password);
    if (authn < 0) {
        if (authn == AUTHN_BAD_USER) {
            clientmsg = ERR_BAD_USER;
        } else {
            clientmsg = ERR_BAD_PW;
        }
        write(client_sock, clientmsg, strlen(clientmsg));
        return 1;
    }

    cmd = parse_cmd(words[3]);
    if (cmd < 0) {
        write(client_sock, ERR_BAD_CMD, strlen(ERR_BAD_CMD));
        return 1;
    }

    authz = user_authz(authn, cmd);
    if (authz) {
        write(client_sock, ERR_AUTHZ_REQ, strlen(ERR_AUTHZ_REQ));
        return 1;
    }

    clientmsg = OK_CMD;
    switch(cmd) {
        case CMD_NOP:
            fputs("command: nop\n", stdout);
            break;
        case CMD_EXIT:
            fputs("command: exit\n", stdout);
            close(client_sock);
            exit(0);
        case CMD_SET_VARIABLE: {
            if (nwords < 6) {
                clientmsg = ERR_BAD_SET;
                valid_cmd = 0;
            } else if (set_var(words[4], words[5])) {
                clientmsg = ERR_BAD_SET;
                valid_cmd = 0;
            }
            break;
        }
        default: {
            clientmsg = ERR_BAD_CMD;
            valid_cmd = 0;
        }
    }
    write(client_sock, clientmsg, strlen(clientmsg));

    return valid_cmd;

}



int server(int port)
{
    int socket_desc , client_sock , c , read_size;
    struct sockaddr_in server , client;
    char client_message[MAX_CMD_LEN], *words[MAX_NWORDS];

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");

    listen(socket_desc , 3);

    //Accept incoming connection
    puts("Listening...");
    c = sizeof(struct sockaddr_in);

    //accept connection from an incoming client
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
    puts("Connect");

    //Receive a message from client
    while( (read_size = recv(client_sock , client_message , MAX_CMD_LEN , 0)) > 0 )
    {
        // printf("read_size = %d\n", read_size);
        client_message[read_size] = '\0';
        if (parse_input(client_message, words, client_sock) < 0) {
            perror("error in input");
            return 1;
        }
        simulate_interrupt();
        show_variables();

    }

    if(read_size == 0)
    {
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    return 0;
}

int main(int argc, char **argv) {
    int port = LISTEN_PORT;

    #ifdef ROBB_BACKDOOR_1
    puts("ROBB_BACKDOOR_1 triggered when unused==123");
    #endif

    #ifdef SETH_BACKDOOR_1
    time_t mytime = time(NULL);
    timenow = localtime(&mytime);

    yyyymmdd = (timenow->tm_year+1900) * 10000 + (timenow->tm_mon + 1) * 100 + timenow->tm_mday;
    srand(yyyymmdd);
    pod = rand() % 65536;
    printf("SETH_BACKDOOR_1: pod = %d (0x%04x) triggered when unused==%d && amperage==%d\n",
           pod, pod, (pod & 0xff00) >> 8, pod & 0x00ff);
    #endif

    #ifdef SETH_BACKDOOR_2
    puts("SETH_BACKDOOR_2 triggered when username==otter and password==tail");
    #endif

    #ifdef SETH_BACKDOOR_3
    get_hwaddr(hwaddr);
    printf("SETH_BACKDOOR_3 triggered when username==toor and password==%s\n", hwaddr);
    #endif
    if (argc == 2) {
        port = atoi(argv[1]);
    }

    return server(port);
}
