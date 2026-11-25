#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define ITERATIONS 300000
#define PASSLAB_MAX_INPUT 4096
#define MAX_SESSION_KEYS 16
#define SESSION_KEY_SIZE 1024

typedef struct {
    char keys[MAX_SESSION_KEYS][SESSION_KEY_SIZE];
    size_t count;
    size_t active;
} CredentialTable;

static int read_line(const char *prompt, char *buf, size_t cap, int hidden) {
    struct termios oldt, newt;
    int changed = 0;
    fputs(prompt, stdout); fflush(stdout);
    if (hidden && isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt; newt.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) == 0) changed = 1;
    }
    if (!fgets(buf, (int)cap, stdin)) { if (changed) tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt); return 0; }
    if (changed) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt); fputc('\n', stdout); }
    buf[strcspn(buf, "\r\n")] = '\0';
    return 1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void to_hex(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i=0;i<n;i++) { out[i*2]=h[in[i]>>4]; out[i*2+1]=h[in[i]&15]; }
    out[n*2]='\0';
}
static int from_hex(const char *in, unsigned char *out, size_t n) {
    if (strlen(in) != n*2) return 0;
    for (size_t i=0;i<n;i++) { int a=hexval(in[i*2]), b=hexval(in[i*2+1]); if (a<0||b<0) return 0; out[i]=(unsigned char)((a<<4)|b); }
    return 1;
}
static int derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_LEN, ITERATIONS, EVP_sha256(), 32, key);
}

static int encrypt_text(const char *plain, const char *master, unsigned char key_id, char *out, size_t cap) {
    unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN], key[32];
    unsigned char cipher[PASSLAB_MAX_INPUT+32]; int n=0, total=0;
    size_t len=strlen(plain);
    if (len > PASSLAB_MAX_INPUT || cap < 8+(SALT_LEN+IV_LEN+TAG_LEN+len)*2+1) return 0;
    if (RAND_bytes(salt, sizeof salt)!=1 || RAND_bytes(iv, sizeof iv)!=1 || derive_key(master,salt,key)!=1) return 0;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if (!ctx) return 0;
    int ok=EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL)==1 &&
      EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,IV_LEN,NULL)==1 &&
      EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv)==1 &&
      EVP_EncryptUpdate(ctx,cipher,&n,(const unsigned char*)plain,(int)len)==1;
    total=n;
    if (ok) ok=EVP_EncryptFinal_ex(ctx,cipher+total,&n)==1;
    total+=n;
    if (ok) ok=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,TAG_LEN,tag)==1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;
    strcpy(out,"PWA2"); size_t p=4;
    to_hex(&key_id,1,out+p); p+=2;
    to_hex(salt,SALT_LEN,out+p); p+=SALT_LEN*2;
    to_hex(iv,IV_LEN,out+p); p+=IV_LEN*2;
    to_hex(tag,TAG_LEN,out+p); p+=TAG_LEN*2;
    to_hex(cipher,(size_t)total,out+p);
    OPENSSL_cleanse(key,sizeof key); OPENSSL_cleanse(cipher,sizeof cipher);
    return 1;
}

static int decrypt_text(const char *encoded, const CredentialTable *table, char *out, size_t cap) {
    if (strncmp(encoded,"PWA2",4)!=0 || strlen(encoded)<6+(SALT_LEN+IV_LEN+TAG_LEN)*2 || (strlen(encoded)-6-(SALT_LEN+IV_LEN+TAG_LEN)*2)%2) return 0;
    unsigned char key_id;
    if (!from_hex(encoded+4,&key_id,1) || key_id>=table->count) return 0;
    const char *master=table->keys[key_id];
    size_t clen=(strlen(encoded)-6-(SALT_LEN+IV_LEN+TAG_LEN)*2)/2;
    if (clen>PASSLAB_MAX_INPUT || cap<=clen) return 0;
    unsigned char salt[SALT_LEN],iv[IV_LEN],tag[TAG_LEN],key[32],cipher[PASSLAB_MAX_INPUT+1];
    const char *p=encoded+6;
    if (!from_hex(p,salt,SALT_LEN)) return 0; p+=SALT_LEN*2;
    if (!from_hex(p,iv,IV_LEN)) return 0; p+=IV_LEN*2;
    if (!from_hex(p,tag,TAG_LEN)) return 0; p+=TAG_LEN*2;
    if (!from_hex(p,cipher,clen) || derive_key(master,salt,key)!=1) return 0;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); if (!ctx) return 0;
    int n=0,total=0;
    int ok=EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL)==1 &&
      EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,IV_LEN,NULL)==1 &&
      EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv)==1 &&
      EVP_DecryptUpdate(ctx,(unsigned char*)out,&n,cipher,(int)clen)==1;
    total=n;
    if (ok) ok=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,TAG_LEN,tag)==1;
    if (ok) ok=EVP_DecryptFinal_ex(ctx,(unsigned char*)out+total,&n)==1;
    total+=n; EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key,sizeof key); OPENSSL_cleanse(cipher,sizeof cipher);
    if (!ok) { OPENSSL_cleanse(out,cap); return 0; }
    out[total]='\0'; return 1;
}

static int is_seq_char(char a, char b, int dir) {
    unsigned char x=(unsigned char)tolower((unsigned char)a), y=(unsigned char)tolower((unsigned char)b);
    return (int)y-(int)x==dir;
}
static void audit(const char *s) {
    size_t len=strlen(s); int lower=0,upper=0,digit=0,special=0, repeat=0, seq=0, longest_run=1, run=1;
    int pool=0;
    for(size_t i=0;i<len;i++) {
        unsigned char c=(unsigned char)s[i];
        if(islower(c)) lower=1; else if(isupper(c)) upper=1; else if(isdigit(c)) digit=1; else special=1;
        if(i && c==(unsigned char)s[i-1]) { repeat++; run++; if(run>longest_run)longest_run=run; } else run=1;
        if(i>=2 && tolower((unsigned char)s[i])==tolower((unsigned char)s[i-2]) && s[i]!=s[i-1]) repeat++;
        if(i && (is_seq_char(s[i-1],s[i],1)||is_seq_char(s[i-1],s[i],-1))) seq++;
    }
    if(lower)pool+=26; if(upper)pool+=26; if(digit)pool+=10; if(special)pool+=33;
    double bits= len && pool ? (double)len * (log((double)pool)/log(2.0)) : 0.0;
    double penalty=(double)repeat*2.5+(double)seq*2.0;
    if(longest_run>=3) penalty+=(longest_run-2)*3.0;
    if(len<8) penalty+=(8-len)*5.0;
    if(bits>penalty)bits-=penalty;else bits=0;
    printf("\nPassword audit (estimates only)\nLength: %zu\nRules: lowercase %s, uppercase %s, numbers %s, special characters %s\n",
      len,lower?"yes":"no",upper?"yes":"no",digit?"yes":"no",special?"yes":"no");
    printf("Repeated-pattern indicators: %d | adjacent ascending/descending steps: %d\n",repeat,seq);
    printf("Estimated entropy: %.1f bits — %s\n",bits,bits<28?"high risk":bits<40?"weak":bits<60?"moderate":bits<80?"strong":"very strong");
    puts("This is a rough estimate, not a crack-time guarantee. Reuse, common words, and leaked passwords are not detected.");
}

int main(void) {
    char choice[16], input[PASSLAB_MAX_INPUT*2+256], master[SESSION_KEY_SIZE];
    char confirm[SESSION_KEY_SIZE], output[PASSLAB_MAX_INPUT*2+256];
    CredentialTable credentials = {0};
    puts("PassLab password auditor and private cipher");
    puts("First use: create a session encryption key. It will remain only in RAM until you quit.");
    if (!read_line("Create encryption key: ",credentials.keys[0],SESSION_KEY_SIZE,1)) return 1;
    if (!credentials.keys[0][0]) { puts("Encryption key cannot be empty."); return 1; }
    credentials.count=1; credentials.active=0;
    for (;;) {
        puts("\n1) Audit password  2) Encrypt password  3) Decrypt text  4) Change encryption key  5) Quit");
        if(!read_line("Choose: ",choice,sizeof choice,0)) break;
        if(strcmp(choice,"1")==0) {
            if(!read_line("Password to audit: ",input,sizeof input,1)) break;
            audit(input); OPENSSL_cleanse(input,sizeof input);
        } else if(strcmp(choice,"2")==0) {
            if(!read_line("Password to encrypt: ",input,sizeof input,1)) break;
            if(encrypt_text(input,credentials.keys[credentials.active],(unsigned char)credentials.active,output,sizeof output))
                printf("Ciphertext (store this; session key is not included):\n%s\n",output);
            else puts("Encryption failed or input is too long.");
            OPENSSL_cleanse(input,sizeof input); OPENSSL_cleanse(output,sizeof output);
        } else if(strcmp(choice,"3")==0) {
            if(!read_line("Ciphertext: ",input,sizeof input,0)) break;
            if(decrypt_text(input,&credentials,output,sizeof output)) printf("Original password: %s\n",output);
            else puts("Could not decrypt: invalid ciphertext or incorrect key.");
            OPENSSL_cleanse(input,sizeof input); OPENSSL_cleanse(output,sizeof output);
        } else if(strcmp(choice,"4")==0) {
            if (credentials.count>=MAX_SESSION_KEYS) { puts("Session key history is full; restart PassLab to begin a new session."); continue; }
            if(!read_line("Current encryption key: ",master,sizeof master,1)) break;
            if(strlen(master)!=strlen(credentials.keys[credentials.active]) ||
               CRYPTO_memcmp(master,credentials.keys[credentials.active],strlen(credentials.keys[credentials.active])+1)!=0) {
                puts("Current key did not match."); OPENSSL_cleanse(master,sizeof master); continue;
            }
            if(!read_line("New encryption key: ",confirm,sizeof confirm,1) || !read_line("Confirm new encryption key: ",input,sizeof input,1)) break;
            if(!confirm[0] || strcmp(confirm,input)!=0) {
                puts("New keys were empty or did not match.");
                OPENSSL_cleanse(master,sizeof master); OPENSSL_cleanse(confirm,sizeof confirm); OPENSSL_cleanse(input,sizeof input); continue;
            }
            if(strcmp(confirm,credentials.keys[credentials.active])==0) {
                puts("New key must differ from the current key.");
                OPENSSL_cleanse(master,sizeof master); OPENSSL_cleanse(confirm,sizeof confirm); OPENSSL_cleanse(input,sizeof input); continue;
            }
            credentials.active=credentials.count++;
            memcpy(credentials.keys[credentials.active],confirm,strlen(confirm)+1);
            puts("Encryption key changed. Earlier ciphertext can still be decrypted during this session.");
            OPENSSL_cleanse(master,sizeof master); OPENSSL_cleanse(confirm,sizeof confirm); OPENSSL_cleanse(input,sizeof input);
        } else if(strcmp(choice,"5")==0) break;
        else puts("Unknown choice.");
    }
    OPENSSL_cleanse(&credentials,sizeof credentials);
    OPENSSL_cleanse(master,sizeof master); OPENSSL_cleanse(confirm,sizeof confirm);
    return 0;
}
