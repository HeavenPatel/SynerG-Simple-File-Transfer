# SynerG-Simple-File-Transfer
The aim of this project to understand and performance test our multi-threaded three-tier server hierarchy system.

Architecture:
1. Server code acts as a front-end to accept client requests.
2. Database is accessed to process the client requests using C mysql API.
3. Client code acts as a load generator to test performance  of the code.

Server Capability:
1. Listen for clients on server socket and spawn a new socket when request is accepted.
2. Authenticate the client identity and display the file list.
3. Initiate secure file copy program(scp) to get requested file from database system to server local machine.
4. Start the transferFile module to send the file into chunks.
5. Throw any error(if any).

Client Capability:
1. Send requests to server.
2. Selection of file from the list populated by server.
3. Start the receiveFile module to receive file into chunks.
4. Throw any error(if any).
