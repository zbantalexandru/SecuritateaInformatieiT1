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

void generateKeyCBC(unsigned char enc_out[], unsigned char iv_enc[AES_BLOCK_SIZE]) {

    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

    unsigned char aes_input[26];
    randChar(aes_input, 25);
    aes_input[25] = '\0';
//    printf("\n\nAcesta este mesajul criptat!: %s\n\n", aes_input);
//    fflush(stdout);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, strlen(reinterpret_cast<const char *>(aes_input)), &enc_key, iv_enc,
                    AES_ENCRYPT);

//    hex_print(enc_out, strlen(reinterpret_cast<const char *>(enc_out)));
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void decryptKeyCBC(unsigned char enc_text[], unsigned char dec_text[], unsigned char iv_dec[AES_BLOCK_SIZE]) {
    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

//    hex_print(enc_text, strlen(reinterpret_cast<const char *>(enc_text)));
    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, 128, &dec_key);
    AES_cbc_encrypt(enc_text, dec_text, strlen(reinterpret_cast<const char *>(enc_text)), &dec_key, iv_dec,
                    AES_DECRYPT);
}

void generateKeyECB(unsigned char enc_out[]) {

    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

    unsigned char aes_input[26];
    randChar(aes_input, 25);
    aes_input[25] = '\0';
    printf("\n\nAcesta este mesajul criptat!: %s\n\n", aes_input);
    fflush(stdout);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_ecb_encrypt(aes_input, enc_out, &enc_key, AES_ENCRYPT);

    hex_print(enc_out, strlen(reinterpret_cast<const char *>(enc_out)));
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void decryptKeyECB(unsigned char enc_text[], unsigned char dec_text[]) {
    unsigned char aes_key[16] = "ahFjQbtZUOmNdaJ";

    hex_print(enc_text, strlen(reinterpret_cast<const char *>(enc_text)));
    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, 128, &dec_key);
    AES_ecb_encrypt(enc_text, dec_text, &dec_key, AES_ENCRYPT);

}

//gen+encrypt ECB key
//Encript text ECB
//encrypt text CBC


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
        char msg[50] = "ecb";//mesaj spre B
        unsigned char encKey[1000], knownKey[AES_BLOCK_SIZE] = "Lorem Ipsum is", decriptedCode[26];
        sleep(2);
        write(pipeAB[1], msg, strlen(msg));
        read(pipeA[0], encKey, 1000);
        write(pipeAB[1], encKey, sizeof(encKey));
        if (strcmp(msg, "cbc") == 0) {
            decryptKeyCBC(encKey, decriptedCode, knownKey);
            decriptedCode[25] = '\0';
//            printf("\nA: %s\n", decriptedCode);
//            fflush(stdout);
            sleep(1);
            char startMsg[50];
            read(pipeAB[0], startMsg, 50);
            if (strcmp(startMsg, "start") == 0) {
                //trimitere fisier criptat
                printf("trimit fisierul criptat");
            }
        } else if (strcmp(msg, "ecb") == 0) {
            decryptKeyECB(encKey, decriptedCode);
            decriptedCode[25] = '\0';
            printf("\nA: %s\n", decriptedCode);
            fflush(stdout);
            hex_print(decriptedCode, strlen(reinterpret_cast<const char *>(decriptedCode)));
            sleep(1);
            char startMsg[50];
            read(pipeAB[0], startMsg, 50);
            if (strcmp(startMsg, "start") == 0) {
                //trimitere fisier criptat
                printf("trimit fisierul criptat");
            }
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
            read(pipeAB[0], msg, 50);
            msg[3] = '\0';
            for (int i = 0; i < strlen(msg); i++)
                if (msg[i] >= 'A' && msg[i] <= 'Z') {
                    msg[i] -= 'A';
                    msg[i] += 'a';
                }
            write(pipeB[1], msg, strlen(msg));
            unsigned char encKey[1000], knownKey[AES_BLOCK_SIZE] = "Lorem Ipsum is", decriptedCode[26];
            read(pipeAB[0], encKey, 1000);
            if (strcmp(msg, "cbc") == 0) {
                decryptKeyCBC(encKey, decriptedCode, knownKey);
                decriptedCode[25] = '\0';
//                printf("\nB: %s\n", decriptedCode);
//                fflush(stdout);
            } else if (strcmp(msg, "ecb") == 0) {
                decryptKeyECB(encKey, decriptedCode);
                decriptedCode[25] = '\0';
                printf("\nB: %s\n", decriptedCode);
                fflush(stdout);
                hex_print(decriptedCode, strlen(reinterpret_cast<const char *>(decriptedCode)));
                sleep(1);
                char startMsg[50];
                read(pipeAB[0], startMsg, 50);
                if (strcmp(startMsg, "start") == 0) {
                    //trimitere fisier criptat
                    printf("trimit fisierul criptat");
                }
                write(pipeAB[1], "start", 5);
            }//B
        } else {//KM
            char tipEnc[50];
            read(pipeB[0], tipEnc, 50);
            if (strcmp(tipEnc, "cbc") == 0) {
                unsigned char encKey[1000];//k
                unsigned char inputKey[] = "Lorem Ipsum is";//k'
                generateKeyCBC(encKey, inputKey);
                write(pipeA[1], encKey, sizeof(encKey));
            } else {
                unsigned char encKey[1000];//k
                generateKeyECB(encKey);
                write(pipeA[1], encKey, sizeof(encKey));
            }
            sleep(5);
        }//KM
    }
    return 0;
}
//gcc main.cpp -o a.out -lssl -lcrypto