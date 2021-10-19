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
//static void hex_print(const void *pv, size_t len) {
//    const unsigned char *p = (const unsigned char *) pv;
//    if (NULL == pv)
//        printf("NULL");
//    else {
//        size_t i = 0;
//        for (; i < len; ++i)
//            printf("%02X ", *p++);
//    }
//    printf("\n");
//}

void generateKeyCBC(unsigned char enc_out[], unsigned char iv_enc[AES_BLOCK_SIZE]) {

    unsigned char aes_key[16] = "ahFjQbtZUOmNdz";

    unsigned char aes_input[26];
    randChar(aes_input, 25);
    aes_input[25] = '\0';
    printf("\n\nAcesta este mesajul criptat!: %s\n\n", aes_input);
    fflush(stdout);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, strlen(reinterpret_cast<const char *>(aes_input)), &enc_key, iv_enc,
                    AES_ENCRYPT);

//    hex_print(enc_out, strlen(reinterpret_cast<const char *>(enc_out)));
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void encriptTextCBC(unsigned char enc_in[],unsigned char enc_out[], unsigned char iv_enc[AES_BLOCK_SIZE]) {

    unsigned char aes_key[16] = "ahFjQbtZUOmNdz";

//    printf("\n\nAcesta este mesajul criptat!: %s\n\n", enc_in);
//    fflush(stdout);

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_cbc_encrypt(enc_in, enc_out, strlen(reinterpret_cast<const char *>(enc_in)), &enc_key, iv_enc,
                    AES_ENCRYPT);

//    hex_print(enc_out, strlen(reinterpret_cast<const char *>(enc_out)));
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void decryptTextCBC(unsigned char enc_text[], unsigned char dec_text[], unsigned char iv_dec[AES_BLOCK_SIZE]) {
    unsigned char aes_key[16] = "ahFjQbtZUOmNdz";

//    hex_print(enc_text, strlen(reinterpret_cast<const char *>(enc_text)));
    AES_KEY dec_key;

    AES_set_decrypt_key(aes_key, 128, &dec_key);
    AES_cbc_encrypt(enc_text, dec_text, strlen(reinterpret_cast<const char *>(enc_text)), &dec_key, iv_dec,
                    AES_DECRYPT);
}

void generateKeyECB(unsigned char *enc_out) {

    unsigned char aes_key[32] = "ahFjQbtZUOmNdz";

    unsigned char aes_input[26];
    randChar(aes_input, 25);
    aes_input[25] = '\0';
    printf("\n\nAcesta este mesajul criptat!: %s\n\n", aes_input);
    fflush(stdout);//input string generat random

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    AES_ecb_encrypt(aes_input, enc_out, &enc_key, AES_ENCRYPT);
//    printf("Cheia CheiaCriptata: ");
//    hex_print(enc_out, 25);
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void encryptTextECB(unsigned char *enc_in,unsigned char *enc_out,unsigned char *key) {

//    printf("\n\nAcesta este mesajul criptat!: %s\n\n", enc_in);
//    fflush(stdout);

    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_ecb_encrypt(enc_in, enc_out, &enc_key, AES_ENCRYPT);
    printf("Cheia CheiaCriptata: ");
//    hex_print(enc_out, 25);
//    printf("%i",strlen(reinterpret_cast<const char *>(enc_out)));
//    fflush(stdout);
}

void decryptTextECB(unsigned char *enc_text, unsigned char *dec_text,unsigned char *key) {

//    hex_print(enc_text, 25);
    AES_KEY dec_key;

    AES_set_decrypt_key(key, 128, &dec_key);
    AES_ecb_encrypt(enc_text, dec_text, &dec_key, AES_DECRYPT);

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
        char msg[50] = "ecb";//mesaj spre B
        unsigned char encKey[1000], knownKey[AES_BLOCK_SIZE] = "ahFjQbtZUOmNdz", decriptedCode[26];
        sleep(2);
        write(pipeAB[1], msg, strlen(msg));
        read(pipeA[0], encKey, 1000);
        printf("A Cheia primita: ");
        fflush(stdout);
//        hex_print(encKey, 25);
        write(pipeAB[1], encKey, sizeof(encKey));
        if (strcmp(msg, "cbc") == 0) {
            decryptTextCBC(encKey, decriptedCode, knownKey);
            decriptedCode[25] = '\0';
            printf("\nA: %s\n", decriptedCode);
            fflush(stdout);
            sleep(1);
            char startMsg[50];
            read(pipeAB[0], startMsg, 50);
            startMsg[5] = '\0';
            if (strcmp(startMsg, "start") == 0) {
                FILE *fp = fopen("text.txt", "r");
                if (fp == NULL) {
                    perror("Eroare deschidere fisier");
                    exit(1);
                }
                unsigned char chunk[128];
                while (fgets(reinterpret_cast<char *>(chunk), sizeof(chunk), fp) != NULL) {
                    unsigned char encryptedText[256];
                    encriptTextCBC(chunk,encryptedText,decriptedCode);
//                    printf("A Encrypted: %s",encryptedText);
//                    fflush(stdout);
                    sleep(1);
                    write(pipeAB[1],encryptedText, strlen(reinterpret_cast<const char *>(encryptedText)));
                }
                fclose(fp);
            }
        } else if (strcmp(msg, "ecb") == 0) {
            decryptTextECB(encKey, decriptedCode,knownKey);
            decriptedCode[25] = '\0';
            printf("\nA: %s\n", decriptedCode);
            fflush(stdout);
//            hex_print(decriptedCode, 25);
            sleep(1);
            char startMsg[50];
            read(pipeAB[0], startMsg, 50);
            startMsg[5] = '\0';
            if (strcmp(startMsg, "start") == 0) {
                FILE *fp = fopen("text.txt", "r");
                if (fp == NULL) {
                    perror("Eroare deschidere fisier");
                    exit(1);
                }
                unsigned char chunk[128];
                while (fgets(reinterpret_cast<char *>(chunk), sizeof(chunk), fp) != NULL) {
                    unsigned char encryptedText[256];
                    encryptTextECB(chunk,encryptedText,decriptedCode);
//                    printf("A Encrypted: %s",encryptedText);
//                    fflush(stdout);
                    sleep(1);
                    write(pipeAB[1],encryptedText, strlen(reinterpret_cast<const char *>(encryptedText)));
                }
                fclose(fp);
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
            unsigned char encKey[1000], knownKey[AES_BLOCK_SIZE] = "ahFjQbtZUOmNdz", decriptedCode[26];
            read(pipeAB[0], encKey, 1000);
            printf("B Cheia primita: ");
            fflush(stdout);
//            hex_print(encKey, 25);
            if (strcmp(msg, "cbc") == 0) {
                decryptTextCBC(encKey, decriptedCode, knownKey);
                decriptedCode[25] = '\0';
                printf("\nB: %s\n", decriptedCode);
                fflush(stdout);
                sleep(1);
                write(pipeAB[1], "start", 5);
                sleep(1);
                unsigned char encryptedText[256];
                for (int i=0;i<2;i++)
                {
                    read(pipeAB[0],encryptedText,256);
//                    printf("B Encrypted: %s",encryptedText);
//                    fflush(stdout);
                    unsigned char decryptedText[128];
                    decryptTextCBC(encryptedText,decryptedText,decriptedCode);
                    printf("B: %s\n",decryptedText);
                    sleep(1);
                }
            } else if (strcmp(msg, "ecb") == 0) {
                decryptTextECB(encKey, decriptedCode,knownKey);
                decriptedCode[25] = '\0';
                printf("\nB: %s\n", decriptedCode);
                fflush(stdout);
//                hex_print(decriptedCode, 25);
                sleep(1);
                write(pipeAB[1], "start", 5);
                sleep(1);
                unsigned char encryptedText[256];
                for (int i=0;i<2;i++)
                {
                    read(pipeAB[0],encryptedText,256);
//                    printf("B Encrypted: %s",encryptedText);
//                    fflush(stdout);
                    unsigned char decryptedText[128];
                    decryptTextECB(encryptedText,decryptedText,decriptedCode);
                    printf("B: %s\n",decryptedText);
                    sleep(1);
                }
            }//B
        } else {//KM
            char tipEnc[50];
            read(pipeB[0], tipEnc, 50);
            if (strcmp(tipEnc, "cbc") == 0) {
                unsigned char encKey[100];//k
                unsigned char inputKey[] = "ahFjQbtZUOmNdz";//k'
                generateKeyCBC(encKey, inputKey);
                write(pipeA[1], encKey, sizeof(encKey));
            } else {
                unsigned char encKey[100];//k
                generateKeyECB(encKey);
                write(pipeA[1], encKey, sizeof(encKey));
            }
            sleep(5);
        }//KM
    }
    return 0;
}
//gcc main.cpp -o a.out -lssl -lcrypto