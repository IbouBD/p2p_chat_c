#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unistd.h>
#include <time.h>
#include "random.c"

#define DEST_IP "127.0.0.1"
#define TERMINAL '\n'
#define SIZE 512
#define BACKLOG 5
#define MAX_PEER 50
#define ALL 0
#define FIRST_NODE_NUM 3
#define HANDSHAKE 0
#define CONNECT 1
#define CHAT 2

int FIRST_NODE[FIRST_NODE_NUM] = {4001, 4002, 4003}; 
// pour l'instant il ne s'agit que des ports puisqu'on travail sur une seule machine


char *id;

void set_id(){
    id = gen_id(16);
}

typedef struct {
    char buffer[SIZE];
    int id;
    int state;
}msg_buf;

typedef struct{
    char *conn_id;
}peerID;

typedef struct {
   int socket;
   peerID id;
   struct sockaddr_in addres;
   int validated;
   char recv_buff[SIZE];
   char send_buff[SIZE];
   char out_buff[SIZE];
   int done;
   int total_bytes_recv;
   int total_bytes_sent;
   int bytes_recv;
   int bytes_sent;
}conn_info;

conn_info connection_list[MAX_PEER];

void init_peer(){
    for (int i=0; i<MAX_PEER; i++){
        connection_list[i].socket =-1;
    }
}

int is_conn(int port){
    for (int i = 0; i < MAX_PEER; i++){
        if (connection_list[i].socket != -1){ 
            int socket_port = ntohs(connection_list[i].addres.sin_port);
            if (port == socket_port){
                return 0; 
            }
        }
    }
    return -1;
}

int check_id(char *id){
    int i;
    for (i = 0; i < MAX_PEER; i++){
        if (connection_list[i].socket != -1){ 
            if (strcmp(id, connection_list[i].id.conn_id) == 0){
                return i; 
            }
        }
    }
    return -1;
}

void send_to(conn_info *c, ssize_t n, char *buffer, int total_size) {
        size_t offset = 0;
        while (offset < total_size) {
            n = send(c->socket, buffer + offset, total_size - offset, 0);
            if (n <= 0) {
                close(c->socket);
                c->socket = -1;
                break;
            }
            offset += n;
        }
    }

void send_data(uint8_t state, conn_info *target, const char *dt, size_t data_size)
{
    if (!dt || data_size == 0) return;

    size_t total_size = 1 + data_size;   // 1 octet pour state
    char *buffer = malloc(total_size);
    if (!buffer) return;

    buffer[0] = state;
    memcpy(buffer + 1, dt, data_size);

    size_t sent;
    ssize_t n;
    
    if (target) {
        if (target->socket != -1 && target->validated)
            send_to(target, n, buffer, total_size);
    } else {
        for (int i = 0; i < MAX_PEER; i++) {
            if (connection_list[i].socket != -1 && connection_list[i].validated)
                send_to(&connection_list[i], n, buffer, total_size);
        }
    }

    free(buffer);
}



void send_message(char *msg){
    int state = CHAT;
    printf("Enter a message: ");
    fgets(msg, SIZE, stdin);
    int msg_size = strlen(msg);
    
    send_data(state, NULL, msg, msg_size+1);
}


int init_peer_conn(int current_port, int dest_port){

    if (dest_port == current_port){
        return 0;
    }

    printf("Tentative de connexion au nœud %d\n", dest_port);

    int out_fd;
    out_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (out_fd==-1){
        printf("il y a un probleme avec le socket peer\n");
        return -1;
    }

    struct sockaddr_in peer;
    peer.sin_family = AF_INET;
    peer.sin_port = htons(dest_port);
    peer.sin_addr.s_addr = inet_addr(DEST_IP);
    bzero(&(peer.sin_zero), 8);


    if (connect(out_fd, (struct sockaddr*)&peer, sizeof(struct sockaddr_in)) == -1){
        printf("La connection n'a pas aboutit\n");
        return -1;
    }

    for (int i=0; i < MAX_PEER; i++){
        if (connection_list[i].socket==-1){
            connection_list[i].socket = out_fd;
            connection_list[i].addres = peer;

            // envoie du premier message, ici le peerID , préciser l'en tete, pour l'instant l'étape de connection
            send_data(HANDSHAKE, &connection_list[i], id, 1+strlen(id));
            return 0;
        }
    }

    return 0;
}

void get_sent_message(conn_info *current_socket){

    current_socket->done = 0;
    current_socket->bytes_recv = recv(current_socket->socket, current_socket->recv_buff, SIZE, 0);
    if (current_socket->bytes_recv ==-1){
            printf("erreur lors du reçoit du message \n");  
    }
    if (current_socket->bytes_recv == 0) {
        close(current_socket->socket);
        current_socket->socket = -1;
        bzero(&(current_socket->out_buff), SIZE);
        bzero(&(current_socket->send_buff), SIZE);
        bzero(&(current_socket->recv_buff), SIZE);
    }
    
    
    memcpy(current_socket->out_buff + current_socket->total_bytes_recv, current_socket->recv_buff, current_socket->bytes_recv);
    current_socket->total_bytes_recv = current_socket->total_bytes_recv + current_socket->bytes_recv;
    current_socket->out_buff[current_socket->total_bytes_recv] = '\0';
    

    if (memchr(current_socket->out_buff, TERMINAL, current_socket->total_bytes_recv) != NULL){
        current_socket->done = 1;

        if (current_socket->out_buff[0] == '0' + HANDSHAKE){
            int idx = check_id(current_socket->out_buff+1);

            if (idx != -1){ // si l'id est trouvé
                // on garde alors la connection la plus ancienne et on supprime la nouvelle
                if(strcmp(connection_list[idx].id.conn_id, current_socket->id.conn_id) > 0){
                    printf("Fermeture de la connexion avec le socket (%d)\n", current_socket->socket);
                    close(current_socket->socket);
                    current_socket->socket = -1;
                    bzero(&(current_socket->out_buff), SIZE);
                    current_socket->total_bytes_recv = 0;
                    
                }else{
                    printf("Fermeture de la connexion avec le socket (%d)\n", connection_list[idx].socket);
                    close(connection_list[idx].socket);
                    connection_list[idx].socket = -1;
                    bzero(&(connection_list[idx].out_buff), SIZE);
                    connection_list[idx].total_bytes_recv = 0;
                }
                
            }else{
                printf("enregistrement de l'id de (%d)\n", current_socket->socket);
                current_socket->id.conn_id = strdup(current_socket->out_buff+1);
                
                current_socket->validated = 1;
            }
        }
        else{ // devrait verifier le cas ou le premier caractere est CHAT
            printf("(%d) %s\n", current_socket->socket, current_socket->out_buff+1);
        
            bzero(&(current_socket->out_buff), SIZE);
            current_socket->total_bytes_recv = 0;
        }
        
        //close(current_socket->socket);
    }
    
}

void build_fdset(int socket, fd_set *readfd, fd_set *writefd){
    FD_ZERO(readfd);
    FD_ZERO(writefd);

    FD_SET(STDIN_FILENO, readfd);
    FD_SET(socket, readfd);
    for (int i = 0; i < MAX_PEER; ++i){
        if (connection_list[i].socket != -1){
            FD_SET(connection_list[i].socket, readfd);
            //FD_SET(connection_list[i].socket, writefd);
        }
    }
}

int add_conn(int socket){

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    socklen_t peer_len = sizeof(peer_addr);
    
    int new_peerfd = accept(socket, (struct sockaddr *)&peer_addr, &peer_len);
    if (new_peerfd < 0) {
        perror("accept()");
        return -1;
    }
    char client_ipv4_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, client_ipv4_str, INET_ADDRSTRLEN);
                    
    printf("Connection entrante de : %s:%d.\n", client_ipv4_str, peer_addr.sin_port);
    // récuperer l'id de la peer
            
    for (int i = 0; i <MAX_PEER; ++i) {
        if (connection_list[i].socket == -1) {
            connection_list[i].socket = new_peerfd;
            connection_list[i].addres = peer_addr;
            connection_list[i].done = 0;
            connection_list[i].validated = 1;
            send_data(HANDSHAKE, &connection_list[i], id, 1+strlen(id));

            
            printf("ajout du socket (%d) à la liste de connexion\n", new_peerfd);
            return 0;
        }
    
    }

    printf("There is too much connections. Close new connection %s:%d.\n", client_ipv4_str, peer_addr.sin_port);
    close(new_peerfd);
    return -1;
}

void shutdown_properly(int socket){

  close(socket);
  for (int i = 0; i < MAX_PEER; ++i)
    if (connection_list[i].socket != -1)
      close(connection_list[i].socket);
    
  printf("Shutdown server properly.\n");
}


int main(){
    
    int sockfd, out_fd, high_sock;  /* Écouter sur sock_fd, nouvelle connection sur new_fd, socket a la plus grande valeur */
    struct sockaddr_in my_addr;
    struct sockaddr_in dest_addr; /* Informations d'adresse du client */
    socklen_t sin_size;
    int MY_PORT;
    int DEST_PORT;
    
    init_peer();
    set_id();

    char current_msg[SIZE];
    char data[SIZE];
    char buffer[SIZE];

    fd_set readfd;
    fd_set writefd;

    printf("id: %s\n", id);
    printf("Enter your port: ");
    scanf("%d", &MY_PORT);
    int c; while ((c = getchar()) != '\n' && c != EOF);
    //printf("Enter destination port: ");
    //scanf("%d", &DEST_PORT);

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(MY_PORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;    //auto remplissage avec mon adresse ip, ancienne ligne  //inet_pton(AF_INET, DEST_IP, &my_addr.sin_addr);
    bzero(&(my_addr.sin_zero), 8);    /* zéro pour le reste de la struct */

    
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // SOCKET OUVERT
    if (sockfd==-1){
        printf("il y a un probleme avec le socket coté server\n");
        return -1;
    }


    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in))){
        printf("il y a un probleme lors du bind\n");
        return -1;
    }
    
    if (listen(sockfd, BACKLOG) == -1){
        printf("erreur lors de l'écoute");
    }

    
    while (1){
        
        build_fdset(sockfd, &readfd, &writefd);

        high_sock = sockfd;
        for (int i=0; i < MAX_PEER; i++){
            if (connection_list[i].socket > high_sock){
                high_sock = connection_list[i].socket;
            } 
        }

         // Définir le timeout
        struct timeval timeout;
        timeout.tv_sec = 5;  // Réessayer toutes les 5 secondes
        timeout.tv_usec = 0;

        int activity = select(high_sock+1, &readfd, NULL, NULL, &timeout);
        switch (activity){
            case -1:
                printf("error with select ");
                shutdown_properly(sockfd);
                break;

            case 0:
                for (int i = 0; i < FIRST_NODE_NUM; i++){
                    if (is_conn(FIRST_NODE[i]) == -1){  
                        if (init_peer_conn(MY_PORT, FIRST_NODE[i])==-1){
                            //printf("probleme d'initialisation");
                            break;
                        }
                    }
                }
                break;

            default:
                if (FD_ISSET(sockfd, &readfd)) {
                    if (add_conn(sockfd) != 0){
                        shutdown_properly(sockfd);
                        printf("hmm");
                    }
                }

                for (int i = 0; i < MAX_PEER; ++i) {
                    
                    if (connection_list[i].socket != -1 && FD_ISSET(connection_list[i].socket, &readfd)) {
                        get_sent_message(&connection_list[i]);
                        continue;
                    }  
                }

                if (FD_ISSET(STDIN_FILENO, &readfd)){
                    send_message(current_msg);
                    continue;
                }
        }
    }
}