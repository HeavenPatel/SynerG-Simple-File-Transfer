#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Setting Global parameters
const size_t BUFFERSIZE = 256;
const int FAILURE = -1;
const char *DEST = "192.168.56.2";
const int MAXTHREADS = 10000;
const int PORT = 8080;
const int SET = 1;
const int SUCCESS = 0;
const int UNSET = 0;

struct threadData {
    pthread_t threadId;
    char *buffer;
    size_t bufferLength;
    int socket;
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

int recvMessage(struct threadData *thread) {   //**
    memset(thread->buffer, '\0', BUFFERSIZE);

    if(recv(thread->socket, thread->buffer, BUFFERSIZE, 0) < SUCCESS)
        return printError(NULL, SET);
    thread->bufferLength = strlen(thread->buffer);
    return SUCCESS;
}

int coupledMessage(struct threadData *thread, char *msg, int ECHO) {
    /*
    Combines writing and reading of message from the socket.
    */
    if(checkSocket(thread) != SUCCESS)
        return printError("Error in checkSocket function", UNSET);
    if(recvMessage(thread) <= FAILURE) {
        memset(thread->buffer, '\0', BUFFERSIZE);
        strcpy(thread->buffer, "-1");
        if(sendMessage(thread) <= FAILURE)
            printError("Error in sendMessage function!",UNSET);
        return printError("Error in recvMessage function!",UNSET);
    }
    if(ECHO == SET)
        printf("%s\n", thread->buffer);

    // If FILECOUNT IS SENT
    if(ECHO == FAILURE) {
        char *rc = (char *)malloc(BUFFERSIZE * sizeof(char));
        strcpy(rc, thread->buffer);
        memset(thread->buffer, '\0', BUFFERSIZE);
        strcpy(thread->buffer, msg);
        if(sendMessage(thread) <= FAILURE)
            return printError("Error in sendMessage function!",UNSET);
        strcpy(thread->buffer, rc);
        free(rc);
        return SUCCESS;
    }
    if(msg != NULL ) {
        memset(thread->buffer, '\0', BUFFERSIZE);
        strcpy(thread->buffer, msg);
    }
    if(sendMessage(thread) <= FAILURE)
        return printError("Error in sendMessage function!",UNSET);
    return SUCCESS;
}

int provideAuthentication(struct threadData *thread) {
    // Provide Username
    if(coupledMessage(thread, "173050032", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during writing USERNAME!",UNSET);

    // Provide Password
    if(coupledMessage(thread, "parth ", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during writing PASSWORD!",UNSET);


    // Get Authentication status message
    if(coupledMessage(thread, "0", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during writing USERNAME",UNSET);

    // Get Authetication status
    if(coupledMessage(thread, "0", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during writing USERNAME",UNSET);

    if(atoi(thread->buffer) == FAILURE )
        return FAILURE;
    return SUCCESS;
}

int accessFileList(struct threadData *thread) {
    unsigned long long rowCount = 0;
    //printf("\033c");
    // Get file list
    if(coupledMessage(thread, "0", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during reading FILE LIST!",UNSET);

    if(!strcmp(thread->buffer, "File List:\n"))
        return printError("Error, received empty file list!", UNSET);

    // Get file count
    if(coupledMessage(thread, "0", FAILURE) == FAILURE)
        return printError("Error in coupledMessage function during reading FILE COUNT!",UNSET);

    rowCount = atoll(thread->buffer);

    // Get Header
    if(coupledMessage(thread, "0", UNSET) == FAILURE)
        return printError("Error in coupledMessage function during reading HEADER!",UNSET);

    while(rowCount) {
        if(coupledMessage(thread, "0", UNSET) == FAILURE)
            return printError("Error in coupledMessage function during reading files",UNSET);
        rowCount--;
    }
    return rowCount;
}

int communicateWithServer(struct threadData *thread) {

    if(provideAuthentication(thread) == FAILURE)
        return printError("Error in provideAuthentication function!", UNSET);
    else if(accessFileList(thread) == FAILURE)
        return printError("Error in accessFileList function!", UNSET);

    return SUCCESS;
}

int startClient(struct threadData *thread) {
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    struct sockaddr_in clientAddress, serverAddress;
    socklen_t clientLength = sizeof(clientAddress);


    // Set server parameters
    memset(&serverAddress, '0', sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(DEST);
    serverAddress.sin_port = htons(PORT);

    // Prepare clientAddress for use in BIND call.
    memset(&clientAddress, '0', sizeof(clientAddress));
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(PORT);

    // Create client socket
    if((thread->socket = createSocket(sizeof(clientAddress))) < UNSET)
        return printError("Error in createSocket function!", UNSET);

    if(inet_pton(AF_INET, DEST, &serverAddress.sin_addr) < SET)
        return printError(NULL, SET);

    if(connect(thread->socket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < UNSET)
        return printError(NULL, SET);

    if (setsockopt (thread->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < SUCCESS)
        return printError(NULL, SET);

    if (setsockopt (thread->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
        return printError(NULL, SET);

    thread->buffer = (char *)malloc(BUFFERSIZE * sizeof(char));
    // Start communication with server
    if(communicateWithServer(thread) != SUCCESS) {
        free(thread->buffer);
        close(thread->socket);
        return printError("Error in communicateWithServer function", UNSET);
    }
    free(thread->buffer);
    close(thread->socket);
    return SUCCESS;
}

void closeClient(int sig_num) {
    /*
    Close the program after printing a message.
    */
    printf("\n**Closing Client**\n");
    exit(1);
}

void *spawnClients(void *threadPtr) {
    struct threadData *thread = threadPtr;
    while(SET) {
    //{
        if(startClient(thread) < UNSET)
            printError("Error in startClient function!", UNSET);
    }
}

int main() {
    /*
    Starts the client process and handle Ctrl+C to gracefully close program
    */

    // Set custom signal handling mechanism
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = closeClient;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    // Start client

    struct threadData threads[MAXTHREADS];
    int threadCount;

    for(threadCount=0; threadCount<MAXTHREADS; threadCount++) {
        if(pthread_create(&threads[threadCount].threadId, NULL, spawnClients, &threads[threadCount]))
            return printError(NULL, SET);
    }

    for(threadCount=0; threadCount<MAXTHREADS; threadCount++)
        if(pthread_join(threads[threadCount].threadId, NULL) != SUCCESS)
            return printError(NULL, SET);

    /*struct threadData thread;
    while(SET) {
        if(startClient(&thread) < UNSET)
            printError("Error in startClient function!", UNSET);
    }*/
    return SUCCESS;
}
