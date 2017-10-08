#include <arpa/inet.h>
#include <errno.h>
#include <mysql.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Setting Global parameters
const size_t BUFFERSIZE = 256;
//const char DB_USER = "database";
const int FAILURE = -1;
const char *HOST = "192.168.56.2";
const int MAXCLIENTS = 100;
const int PORT = 8080;
const int SET = 1;
const int SUCCESS = 0;
const int UNSET = 0;
pthread_mutex_t getDBConnection = PTHREAD_MUTEX_INITIALIZER;

struct threadData {
    MYSQL *DBConnect;
    char *buffer;
    size_t bufferLength;
    int socket;
    int accessLevel;
};

int printError(char *msg, int MODE) {
    /*
    IF MODE IS SET, print error message return by last fault function.
    ELSE, print msg and return -1
    */
    if(MODE == 1) {
    printf("ERROR: %s\n", strerror(errno));
    return errno;
    }
    printf("%s", msg);
    return FAILURE;
}

int createSocket(socklen_t serverLength) {
    /*
    Creates a new socket.
    RETURN:
    POSITIVE VALUE: REPRESENTING SOCKET fd
    NEGATIVE VALUE: ERROR
    */
    int OPT = 1;
    int newSocket;
    if((newSocket = socket(AF_INET, SOCK_STREAM, 0)) == FAILURE )
        return printError(NULL, SET);

    // Set socket options
    if((setsockopt(newSocket, SOL_SOCKET, SO_REUSEADDR, &OPT, sizeof(serverLength))) == FAILURE)
        return printError(NULL, SET);

    // Return new socket fd
    return newSocket;
}

int checkSocket(struct threadData *thread) {
     int error = 0;
     socklen_t len = sizeof (error);
     int retval;
     if((retval = getsockopt(thread->socket, SOL_SOCKET, SO_ERROR, &error, &len)) != SUCCESS)
        return printError(NULL, SET);

    return error;
}

int printMYSQL(MYSQL *DBConnect) {
    /*
    print error message return by last fault function.
    */
    printf("ERROR: %s\n", mysql_error(DBConnect));
    return mysql_errno(DBConnect);
}

int checkMYSQLConnection(struct threadData *thread) {
    /*
    Reconnects mysql connection if broken and sends the query.
    */
    if(mysql_ping(thread->DBConnect) != UNSET)
        printError("Reconnecting to MYSQL DB", UNSET);
    if(mysql_query(thread->DBConnect, thread->buffer) != UNSET)
        return printMYSQL(thread->DBConnect);
}

MYSQL *getMYSQLConnection() {
    // Set connection parameters
    char *server = "192.168.56.3";
    char *user = "cs744";
    char *password = "SynerG@744";
    char *database = "SynerG";
    MYSQL *DBConnect = mysql_init(NULL);
    if(DBConnect != NULL)
        DBConnect = mysql_real_connect(DBConnect, server, user, password, database,0,NULL,0);
    return DBConnect;
}

int sendMessage(struct threadData *thread) {
    char *ptr = thread->buffer;
    thread->bufferLength = strlen(thread->buffer);
    int total = 0;        // how many bytes we've sent
    int bytesleft = thread->bufferLength; // how many we have left to send
    int n;

    while(total < thread->bufferLength) {
        if((n = send(thread->socket, ptr + total, bytesleft, 0)) == FAILURE)
            return printError(NULL, SET);
        total += n;
        bytesleft -= n;
    }
    thread->bufferLength = total; // return number actually sent here
    return n==FAILURE?FAILURE:SUCCESS; // return -1 on failure, 0 on success
}

int recvMessage(struct threadData *thread) {
    memset(thread->buffer, '\0', BUFFERSIZE);

    if(recv(thread->socket, thread->buffer, BUFFERSIZE, 0) < SUCCESS)
        return printError(NULL, SET);

    thread->bufferLength = strlen(thread->buffer);
    return SUCCESS;
}

int coupledMessage(struct threadData *thread, char *msg) {
    /*
    Combines writing and reading of message from the socket.
    */
    if(checkSocket(thread) != SUCCESS)
        return printError("Error in checkSocket function", UNSET);
    if(msg != NULL) {
        memset(thread->buffer, '\0', BUFFERSIZE);
        strcpy(thread->buffer, msg);
    }
    if(sendMessage(thread) <= FAILURE)
        return printError("Error in sendMessage function!",UNSET);
    if(recvMessage(thread) <= FAILURE)
        return printError("Error in recvMessage function!", UNSET);
    if(atoi(thread->buffer) == FAILURE)
        return FAILURE;
    return SUCCESS;
}

void authenticateClient(struct threadData *thread) {
    /*
    Gets username, password and sets thread.accessLevel = -1 if invalid, else accordingly
    */
    MYSQL_RES *result;
    MYSQL_ROW rows;
    char username[50] = {'\0'};
    char password[50] = {'\0'};

    // Retrieve Username from client
    if(coupledMessage(thread, "Username: ") == FAILURE) {
        printError("Error in coupledMessage function during writing USERNAME",UNSET);
        return ;
    }
    strcpy(username, thread->buffer);

    // Retrieve Password from client
    if(coupledMessage(thread, "Password: ") == FAILURE) {
        printError("Error in coupledMessage function during writing PASSWORD",UNSET);
        return ;
    }
    strcpy(password, thread->buffer);

    // Verify User Credentials
    memset(thread->buffer, '\0', BUFFERSIZE);
    snprintf(thread->buffer, BUFFERSIZE, "SELECT * FROM UserCredentials WHERE UserID='%s' and Password='%s';", username, password);
    if(checkMYSQLConnection(thread) > SET) {
        thread->accessLevel = FAILURE;
        return ;
    }

    // Fetch results
    result = mysql_store_result(thread->DBConnect);
    rows = mysql_fetch_row(result);

    // If User Credentials are invalid
    if(rows == NULL) {
        if(coupledMessage(thread, "Invalid Credentials!!\nPlease try again.") == FAILURE)
            printError("Error in coupledMessage function during writing Invalid Credentials...",UNSET);
        else if(coupledMessage(thread, "-1") == FAILURE)
            printError("Error in coupledMessage function during writing FAILURE at fetch results",UNSET);
        thread->accessLevel = FAILURE;
        mysql_free_result(result);
        return;
    }

    // If User Credentials are valid
    if(coupledMessage(thread, "Login Success.") == FAILURE) {
        printError("Error in coupledMessage function during writing Login Success.",UNSET);
        thread->accessLevel = FAILURE;
        return ;
    }
    if(coupledMessage(thread, "0") == FAILURE) {
        printError("Error in coupledMessage function during writing SUCCESS at fetch results",UNSET);
        thread->accessLevel = FAILURE;
        return ;
    }

    thread->accessLevel = atoi(rows[2]);
    mysql_free_result(result);
    return;
}

int serveClient(struct threadData *thread) {
    /*
    Populates the client display with files as per the access level.
    */
    MYSQL_RES *result;
    MYSQL_ROW rows;
    unsigned long long int rowCount = 0;
    int index = 1;
    //char *altBuffer = (char *)malloc(BUFFERSIZE * sizeof(char));

    // Get file list that this thread can accesss
    memset(thread->buffer, '\0', BUFFERSIZE);
    snprintf(thread->buffer, BUFFERSIZE, "SELECT * FROM FileInfo WHERE FileAccess > %d;", thread->accessLevel);
    if(checkMYSQLConnection(thread) > SET)
        return FAILURE;

    result = mysql_store_result(thread->DBConnect);
    rowCount = mysql_num_rows(result);
    rows = mysql_fetch_row(result);

    // If list has no data
    if (rows == NULL) {
        if(coupledMessage(thread, "-1") == FAILURE)
            return printError("Error in coupledMessage function during writing FAILURE",UNSET);
        return printError("Error: null resultset accessing file list", UNSET);
    }

    // Print File List on client Display
    if(coupledMessage(thread, "File List:\n") == FAILURE)
        return printError("Error in coupledMessage function during writing File List",UNSET);

    // Send file count to client
    memset(thread->buffer, '\0', rowCount);
    snprintf(thread->buffer, BUFFERSIZE, "%lld\n", rowCount);
    if(coupledMessage(thread, NULL) == FAILURE)
        return printError("Error in coupledMessage function during writing File count",UNSET);

    // Set HEADER on client display
    memset(thread->buffer, '\0', BUFFERSIZE);
    snprintf(thread->buffer, BUFFERSIZE, "INDEX: %25s::SIZE(Bytes)\n","FILENAME");
    if(coupledMessage(thread, NULL) == FAILURE)
        return printError("Error in coupledMessage function during writing HEADER",UNSET);

    // Populate the file details on client screen
    do {
        memset(thread->buffer, '\0', BUFFERSIZE);
        snprintf(thread->buffer, BUFFERSIZE, "%5d: %25s::%s\n", index, rows[0], rows[2]);
        if(coupledMessage(thread, NULL) == FAILURE)
            return printError("Error in coupledMessage function during writing file details",UNSET);
        index++;
    } while((rows = mysql_fetch_row(result)));

    /*
    // Print the message and get selected index
    if(coupledMessage(thread, "Select the index to download the file(Only one at a time): ") == FAILURE)
        return printError("Error in coupledMessage function during writing OPTIONS",UNSET);
    index = atoi(thread->buffer) - 1;
    */
    // Code to send file...[will be continued]
}

void *processClient(void *socket) {
    /*
    Initializes thread specific data structure -> call authenticateClient -> call serveClient.
    */
    // Create a new struct threadData instance
    struct threadData thread;
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    // Get MySQL connection
    pthread_mutex_lock(&getDBConnection);
    thread.DBConnect = getMYSQLConnection();
    pthread_mutex_unlock(&getDBConnection);

    // Check for valid DB connection
    if(thread.DBConnect == NULL)
        pthread_exit(NULL);

    // Set thread variables
    thread.socket = *(int *)socket;
    thread.buffer = (char *)malloc(BUFFERSIZE * sizeof(char));

    if (setsockopt (thread.socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < SUCCESS)
        printError(NULL, SET);

    if (setsockopt (thread.socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        printError(NULL, SET);

    authenticateClient(&thread);

    if(thread.accessLevel == FAILURE)
        printError("Error in serveClient function", UNSET);
    else if(serveClient(&thread) == FAILURE)
        printError("Error in serveClient function", UNSET);

    // Do cleanup
    close(thread.socket);
    free(thread.buffer);
    mysql_close(thread.DBConnect);
    pthread_exit(NULL);

}

int startServer() {
    /*
    Listens for client request on server socket and spawn a new thread for each request.
    */
    struct sockaddr_in clientAddress, serverAddress;
    int clientSocket, serverSocket, *threadSocket;
    pthread_t thread;

    socklen_t clientLength = sizeof(clientAddress);

    // Prepare serverAddress for use in BIND call.
    memset(&serverAddress, '0', sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(HOST);
    serverAddress.sin_port = htons(PORT);

    // Create server socket
    if((serverSocket = createSocket(sizeof(serverAddress))) < UNSET)
        return printError("Error in createSocket function!", UNSET);

    // BIND server socket with <IP, PORT>
    if(bind(serverSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) == FAILURE)
        return printError(NULL, SET);

    // Listen for client request(s)
    if(listen(serverSocket, MAXCLIENTS) == FAILURE)
        return printError(NULL, SET);

    // Display that server is running
    printf("Server up and running at %s:%d...\n", HOST, ntohs(serverAddress.sin_port));
    long long int i =0;
    while(SET) {
        printf("%lld", i++);
        // ACCEPT incoming request, create a new thread and pass thread control to processThread function
        if((clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddress, &clientLength)) < 0)
            return printError(NULL, SET);
        printf("Connected to %s:%d\n", inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));
        threadSocket = (int * )malloc(sizeof(int));
        *threadSocket = clientSocket;
        if(pthread_create(&thread, NULL, processClient, (void *)threadSocket))
            return printError(NULL, SET);
    }

    return SUCCESS;
}

void closeServer(int sig_num) {
    /*
    Close the program after printing a message.
    */
    printf("\n**Closing Server**\n");
    exit(1);
}

int main() {
    /*
    Starts the server process and handle Ctrl+C to gracefully close program
    */

    // Set custom signal handling mechanism
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = closeServer;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    // Start server
    if(startServer() < UNSET)
        return printError("Error in startServer function!", UNSET);
    return SUCCESS;
}
