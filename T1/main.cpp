#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void randChar(unsigned char in[], int length) {
    for (int i = 0; i < length; ++i) {
        in[i] = 'A' + (random() % 26);
    }
}

void generateKeyCBC(unsigned char enc_out[], unsigned char iv_enc[AES_BLOCK_SIZE]) {

    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

    unsigned char aes_input[25];
    randChar(aes_input, 25);
    printf("\n\nAcesta este mesajul criptat!: %s\n\n", aes_input);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, 25, &enc_key, iv_enc, AES_ENCRYPT);
}

void decriptKeyCBC(unsigned char enc_text[], unsigned char dec_text[], unsigned char iv_dec[AES_BLOCK_SIZE]) {
    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

    unsigned char dec_out[25];
    memset(dec_out, 0, sizeof(dec_out));
    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, 128, &dec_key);
    AES_cbc_encrypt(enc_text, dec_text, 25, &dec_key, iv_dec, AES_DECRYPT);

}

//a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void *pv, size_t len) {
    const unsigned char *p = (const unsigned char *) pv;
    if (NULL == pv)
        printf("NULL");
    else {
        size_t i = 0;
        for (; i < len; ++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}


int main() {
    pid_t pidA, pidB;
    int pipeA[2], pipeB[2], pipeAB[2];
    if (pipe(pipeA) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    if (pipe(pipeAB) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    pidA = fork();
    if (pidA == 0) {//A
        char msg[50] = "cbc";//mesaj spre B
        unsigned char encKey[25], knownKey[] = "Lorem Ipsum is", decriptedCode[26];
        write(pipeAB[1], msg, strlen(msg));
        read(pipeA[0], encKey, 25);
        write(pipeAB[1], encKey, sizeof(encKey));

        if (strcmp(msg, "cbc") == 0) {
            decriptKeyCBC(encKey, decriptedCode, knownKey);
            decriptedCode[25] = '\0';
            printf("\nA: %s %i\n", decriptedCode,sizeof (decriptedCode));
        }
    }//A
    else {
        if (pipe(pipeB) == -1) {
            perror("pipe");
            exit(EXIT_FAILURE);
        }
        pidB = fork();
        if (pidB == 0) {//B
            char msg[50];
            sleep(1);
            read(pipeAB[0], msg, 50);
            for (int i = 0; i < strlen(msg); i++)
                if (msg[i] >= 'A' && msg[i] <= 'Z') {
                    msg[i] -= 'A';
                    msg[i] += 'a';
                }
            if (strcmp(msg, "cbc") == 0) {
                //cbc
                write(pipeB[1], msg, strlen(msg));
            } else if (strcmp(msg, "ecb") == 0) {
                //ecb
                write(pipeB[1], msg, strlen(msg));
            } else {
                printf("Nu am idee la ce te gandesti, am sa folosesc CBC");
                write(pipeB[1], "cbc", 3);
            }
            unsigned char encKey[50], knownKey[] = "Lorem Ipsum is", decriptedCode[26];
            read(pipeAB[0], encKey, 25);
            if (strcmp(msg, "cbc") == 0) {
                decriptKeyCBC(encKey, decriptedCode, knownKey);
                decriptedCode[25] = '\0';
                printf("\nB: %s\n", decriptedCode);
            }
        }//B
        else {//KM
            char tipEnc[50];
            read(pipeB[0], tipEnc, 50);
            if (strcmp(tipEnc, "cbc") == 0) {
                unsigned char encKey[25];//k
                unsigned char inputKey[] = "Lorem Ipsum is";//k'
                generateKeyCBC(encKey, inputKey);
                write(pipeA[1], encKey, sizeof(encKey));
            }

            sleep(5);
        }//KM
    }
    return 0;
}




// main entrypoint


//gcc main.cpp -o a.out -lssl -lcrypto