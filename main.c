#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "CSHA256/minimalSHA256.h"
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/*
 * SPECIAL THANKS TO Jouni Malinen FOR THE BASE64 CODE
 */

/*
 * USER STRUCT. this contain info about user
 */
struct User
{
    int id;
    char user_name[21];
    uint8_t password[32]; //is sha-256 hash
    char mobile[128]; //is ciphertext AES-256
    char dob[11];
    char email[51];
    char pincode[128]; // is ciphertext AES-256
};

//Some definations
static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
struct User* user_list = NULL;
int user_count = 0;
#define os_malloc malloc
#define os_free free
#define os_memset memset
#define WRITE_LIMIT 10000
/*
 * is_valid_char()/is_valid_str()/is_numeric. alphanumeric + some special char check, is_numeric checks for numbers in string
 */
bool is_valid_char(unsigned char c) {
    return isalnum(c) || c == '_' || c == ',' || c == '#' || c == '@' || c == '!' || c == '.';
}
bool is_valid_str(const char *string) {
    while (*string) {
        if (!is_valid_char((unsigned char)*string)) return false;
        string++;
    }
    return true;
}
bool is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char)*str)) return false;
        str++;
    }
    return true;
}
/*
 * AES256_encrypt: encrypt data using AES256 algorithm this returns the ciphertext_length
 * arguments:
 * @plaintext: the data that is going to be encrypted
 * @key: key that is going to be used to encrypt
 * @ciphertext: the encrypted text
 */

int AES256_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto err;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, 0))
        goto err;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char*)plaintext)))
        goto err;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto err;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
/*
 * AES256_decrypt: encrypt data using AES256 algorithm this returns the plaintext_length
 * arguments:
 * @ciphertext: the data that is going to be decrypted
 * @key: key that is going to be used to decrypt
 * @plaintext: the decrypted text
 */
int AES256_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) goto err;


    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, 0))
        goto err;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, strlen((char*)ciphertext)))
        goto err;
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto err;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = os_malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	os_memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = os_malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					os_free(out);
					return NULL;
				}
				break;
			}
		}
	}

	//*out_len = pos - out;
	return out;
}
/*
 * input(), gets input from user safely
 * arguments:
 * val: the input will be put into val
 * max_len: maximum length
 * type: type of info needed to be entered (ADDRESS, USERNAME etc)
 * is_space: if set true spaces will be allowed
 * alphanumeric: if set true only alphanumeric letters and some special letters will be allowed
 * hidden: will hide the input field
 * only_max_len: if this value is set to true the code will only work if the val length is equal to max_len
 */
void input(char* val, int max_len, char* type, bool is_space, bool alphanumeric, bool numeric_only, bool hidden, bool only_max_len)
{
    struct termios oldt, newt;
    bool is_alpha = true;
    bool is_number = true;
    bool rename_pls = true;
    bool is_not_zero = true;
    char format[10];
    sprintf(format, "%%%ds", max_len);

    do
    {
        printf("Enter %s (max %d chars%s%s%s): ", type, max_len, is_space ? ", spaces allowed" : ", no spaces", alphanumeric ? ", alphanumeric only" : "", numeric_only ? ", numbers only" : "");

        if (hidden) {
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
        if (is_space) {
            fgets(val, max_len + 1, stdin);
            val[strcspn(val, "\n")] = '\0';
        }
        else {
            scanf(format, val);
            int c; while ((c = getchar()) != '\n' && c != EOF);
        }
        if (hidden) {
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            printf("\n");
        }
        if (alphanumeric) {
            is_alpha = is_valid_str(val);
        }
        if (numeric_only) {
            is_number = is_numeric(val);
            if (atoi(val) < 0)
                is_not_zero = false;
        }
        if (only_max_len) {
            if (strlen(val) != max_len)
                rename_pls = false;
            else
                rename_pls = true;
        }
        if (strlen(val) > max_len || strlen(val) == 0 || !is_alpha || !is_number || !rename_pls || !is_not_zero)
            printf("ERROR\n");

    } while (strlen(val) > max_len || strlen(val) == 0 || !is_alpha || !is_number || !rename_pls || !is_not_zero);
}
/*
 * is_valid_email - check if variable "email" is valid email
 * arguments:
 * email: the email that is going to checked
 */
bool is_valid_email(const char* email) {
    if (email == NULL) return false;

    const char* at = strchr(email, '@');
    if (at == NULL) return false;

    if (strchr(at + 1, '@') != NULL) return false;

    if (at == email || *(at + 1) == '\0') return false;

    for (const char* p = email; p < at; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')) {
            return false;
        }
    }

    const char* domain = at + 1;
    const char* dot = strchr(domain, '.');
    if (dot == NULL) return false;

    if (*domain == '.' || *domain == '-' || domain[strlen(domain)-1] == '.' || domain[strlen(domain)-1] == '-') {
        return false;
    }

    for (const char* p = domain; *p != '\0'; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-')) {
            return false;
        }
    }

    return true;
}

/*
 * username_exists - checks if the username already has been taken.
 * arguments:
 * @username - the value that is going to be checked
 */
bool username_exists(const char* username) {
    for (int i = 0; i < user_count; ++i) {
        if (strcmp(user_list[i].user_name, username) == 0)
            return true;
    }
    return false;
}

/*
 * email_exists - checks if the email already has been taken.
 * arguments:
 * @email - the value that is going to be checked
 */
bool email_exists(const char* email) {
    for (int i = 0; i < user_count; ++i) {
        if (strcmp(user_list[i].email, email) == 0)
            return true;
    }
    return false;
}

/*
 * is_valid_dob_format - check if variable "dob" is a valid date of birth
 * arguments:
 * @dob: the dob that is going to checked
 */

bool is_valid_dob_format(const char *dob) {
    if (dob == NULL || strlen(dob) != 8)
        return false;

    int day = (dob[0] - '0') * 10 + (dob[1] - '0');
    int month = (dob[2] - '0') * 10 + (dob[3] - '0');
    int year = atoi(dob + 4); // last 4 chars

    if (year < 1900 || year > 2100) return false;
    if (month < 1 || month > 12) return false;

    int max_day = 31;
    if (month == 2) {
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
            max_day = 29;
        else
            max_day = 28;
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        max_day = 30;
    }

    if (day < 1 || day > max_day)
        return false;

    return true;
}

/*
 * is_valid_mobile - check if variable "mobile" is valid mobile
 * arguments:
 * @mobile: the email mobile is going to checked
 */
bool is_valid_mobile_number(const char *mobile) {
    if (strlen(mobile) != 13)
        return false;

    for (int i = 0; i < 13; ++i) {
        if (!isdigit((unsigned char)mobile[i]))
            return false;
    }

    char code[4] = {0};
    strncpy(code, mobile, 3);
    int cc = atoi(code);
    if (cc < 1)
        return false;

    char number[11] = {0};
    strncpy(number, mobile + 3, 10);
    long long num = atoll(number);
    if (num < 1)
        return false;

    return true;
}
/*
 * get_key_from_user_and_password(). will combine the first arg and secound arg and hash it using sha-256 and return it
 * arguments:
 * @user: username that is going to be combined with password
 * @password: password that is going to be combined with user
 * @key: the sha-256 hash made with password combined with user
 */
void get_key_from_user_and_password(const char* user, const char* password, uint8_t* key)
{
    char user_plus_pass[33] = {0};
    snprintf(user_plus_pass, sizeof(user_plus_pass), "%s/%s", user, password);
    sha256((const uint8_t *)user_plus_pass, strlen(user_plus_pass), key);
}
/*
 * initUser(). initalize the user and get info about the user
 */
void initnewUser(void)
{
    struct User* temp = realloc(user_list, (user_count + 1) * sizeof(struct User));
    if (!temp)
        exit(-6);
    user_list = temp;

    struct User* user = &user_list[user_count];
    uint8_t key[32];
    char username[21] = {0};
    char* password = malloc(13 * sizeof(char));
    char* mobile = malloc(15 * sizeof(char));
    char* pincode = malloc(7 * sizeof(char));
    char date[11] = {0};
    char email[51] = {0};

    if (!password || !mobile || !pincode) exit(-1);

    user->id = user_count;

    while (1) {
        input(username, 20, "USERNAME", false, true, false, false, false);
        if (!username_exists(username)) break;
        printf("This username has already been taken.\n");
    }

    while (1) {
        input(email, 50, "EMAIL", false, true, false, false, false);
        if (!email_exists(email) && is_valid_email(email)) break;
        printf("Invalid or taken email.\n");
    }

    input(password, 12, "PASSWORD", true, false, false, true, false);
    while (1) {
        input(mobile, 13, "MOBILE (format: codeNumber exp: 091234567890)", false, false, true, false, true);
        if (is_valid_mobile_number(mobile)) break;

        printf("Invalid mobile number. Must be 13 digits: 3-digit country code + 10-digit number.\n");
    }
    while (1) {
        input(date, 8, "DATE OF BIRTH (DDMMYYYY)", false, false, true, false, true);
        if(is_valid_dob_format(date)) break;
        printf("Invalid date\n");
    }
    input(pincode, 6, "PINCODE", false, false, true, false, true);

    memmove(mobile + 1, mobile, strlen(mobile) + 1);
    mobile[0] = '+';

    snprintf(user->dob, sizeof(user->dob), "%.2s/%.2s/%.4s", date, date + 2, date + 4);
    get_key_from_user_and_password(username, password, key);

    unsigned char encrypted_mobile[128];
    int mob_len = AES256_encrypt((unsigned char*)mobile, key, encrypted_mobile);
    unsigned char* mob_b64 = base64_encode(encrypted_mobile, mob_len, NULL);
    strncpy(user->mobile, (char*)mob_b64, sizeof(user->mobile) - 1);
    os_free(mob_b64);

    unsigned char encrypted_pincode[128];
    int pin_len = AES256_encrypt((unsigned char*)pincode, key, encrypted_pincode);
    unsigned char* pin_b64 = base64_encode(encrypted_pincode, pin_len, NULL);
    strncpy(user->pincode, (char*)pin_b64, sizeof(user->pincode));
    os_free(pin_b64);

    sha256((const uint8_t*)password, strlen(password), user->password);
    strncpy(user->user_name, username, sizeof(user->user_name));
    strncpy(user->email, email, sizeof(user->email));

    free(password);
    free(mobile);
    free(pincode);

    printf("User with ID %d added.\n", user->id);
    user_count++;
}
/*
 * authenticate_user - authenticate user by id and password
 * arguments:
 * @id: user id
 * @password: user password
 */
bool authenticate_user(int id, char* password)
{
    int l = check_sha256((uint8_t *)&user_list[id].password, password);
    if (l) return false;
    return true;
}

/*
 * changeInfo - changes info about the user
 * arguments:
 * @id: user id
 */
void changeInfo(int id)
{
    struct User *user = &user_list[id];
    uint8_t key[32];
    int num;
    char* password = malloc(13 * sizeof(char));
    input(password, 12, "PASSWORD", false, false, false, true, false);
    if (!authenticate_user(id, password))
        return;

    while (1)
    {
        printf("USERNAME CAN NOT BE CHANGED\nPress 1. to change mobile\nPress 2. to change email\nPress 3. to change pincode\nPress 4. to change DOB\nEnter Choice: ");
        scanf("%d", &num);
        switch (num)
        {
        case 1:
            unsigned char encrypted_mobile[128];
            get_key_from_user_and_password(user->user_name, password, key);
            char* mobile = malloc(15 * sizeof(char));
            while (1) {
                input(mobile, 13, "MOBILE (format: codeNumber exp: 091234567890)", false, false, true, true, true);
                if (is_valid_mobile_number(mobile)) break;

                printf("Invalid mobile number. Must be 13 digits: 3-digit country code + 10-digit number.\n");
            }
            memmove(mobile + 1, mobile, strlen(mobile) + 1);
            mobile[0] = '+';
            int mob_len = AES256_encrypt((unsigned char*)mobile, (unsigned char*)key, (unsigned char*)encrypted_mobile);
            free(mobile);
            unsigned char* mob_b64 = base64_encode(encrypted_mobile, mob_len, NULL);
            strncpy(user->pincode, (char*)mob_b64, sizeof(user->pincode));
            os_free(mob_b64);
            break;

        case 2:
            char email[51];
            while (1) {
                input(email, 50, "EMAIL", false, true, false, false, false);
                if (!email_exists(email)) {
                    if (is_valid_email(email))
                        break;
                    else
                        printf("Email Is not valid.\n");
                } else 
                    printf("This email has already been taken.\n");
            }
            strcpy(user->email, email);
            break;

        case 3:
            unsigned char encrypted_pincode[128];
            get_key_from_user_and_password(user->user_name, password, key);
            char* pincode = malloc(7 * sizeof(char));
            input(pincode, 6, "PINCODE", false, false, true, true, true);
            int pin_len = AES256_encrypt((unsigned char*)pincode, (unsigned char*)key, (unsigned char*)encrypted_pincode);
            free(pincode);
            unsigned char* pin_b64 = base64_encode(encrypted_pincode, pin_len, NULL);
            strncpy(user->pincode, (char*)pin_b64, sizeof(user->pincode));
            os_free(pin_b64);
            break;
        case 4:
            char date[11] = {0};
            while (1) {
                input(date, 8, "DATE OF BIRTH (DDMMYYYY)", false, false, true, false, true);
                if(is_valid_dob_format(date)) break;
                printf("Invalid date\n");
            }
            snprintf(user->dob, sizeof(user->dob), "%.2s/%.2s/%.4s", date, date + 2, date + 4);
            break;
        default:
            break;
        }
        if (num < 5 && num > 0)
            break;
    }
    printf("User with ID: %d has changed info\n", user->id);
    
}
/*
 * get_info - displays the info of the user
 * arguments:
 * @id: user id
 */
void get_info(int id) {
    struct User *user = &user_list[id]; 
    unsigned char decrypted_mobile[128] = {0};
    unsigned char decrypted_pincode[128] = {0};
    unsigned char *decoded_b64_mobile = base64_decode((unsigned char *)user->mobile, strlen(user->mobile), NULL);
    unsigned char *decoded_b64_pincode = base64_decode((unsigned char *)user->pincode, strlen(user->pincode), NULL);
    if (!decoded_b64_mobile || !decoded_b64_pincode) return;

    uint8_t key[32];
    char* password = malloc(13 * sizeof(char));
    input(password, 12, "PASSWORD", false, false, false, true, false);
    if (authenticate_user(id, password)) {
        get_key_from_user_and_password(user->user_name, password, key);
        AES256_decrypt((unsigned char*)decoded_b64_mobile, (unsigned char*)key, (unsigned char*)decrypted_mobile);
        AES256_decrypt((unsigned char*)decoded_b64_pincode, (unsigned char*)key, (unsigned char*)decrypted_pincode);
        printf("ID: %d\n", user->id);
        printf("USERNAME: %s\n", user->user_name);
        printf("DATE OF BIRTH: %s\n", user->dob);
        printf("MOBILE: %s\n", decrypted_mobile);
        printf("EMAIL: %s\n", user->email);
        printf("PINCODE: %s\n", decrypted_pincode);
    } else
        printf("INTRUDER ALERT\nPEEP PEEP PEEP\n");

    free(password);
    os_free(decoded_b64_mobile);
    os_free(decoded_b64_pincode);
}

/*
 * write_users_to_file - write all the users from memory to file
 * argument:
 * @file: the file the users will be written into
 */
void write_users_to_file(const char* file)
{
    FILE *f = fopen(file, "w");
    if (f == NULL) return;

    int written_count = 0;
    int written_ids[user_count];
    written_ids[0] = WRITE_LIMIT;

    for (int i = 0; i < user_count; ++i) {
        struct User *user = &user_list[i];
    
        bool already_written = false;
        for (int j = 0; j < written_count; ++j) {
            if (written_ids[j] == user->id) {
                already_written = true;
                break;
            }
        }

        if (already_written)
            continue;

        written_ids[written_count++] = user->id;

        if (i != 0)
            fprintf(f, "\n");

        fprintf(f, "---- START ----\n");
        fprintf(f, "ID: %d\n", user->id);
        fprintf(f, "USERNAME: %s\n", user->user_name);
        fprintf(f, "EMAIL: %s\n", user->email);
        fprintf(f, "DATE OF BIRTH: %s\n", user->dob);
        fprintf(f, "MOBILE(encrypted): %s\n", user->mobile);
        fprintf(f, "PINCODE(encrypted): %s\n", user->pincode);
        fprintf(f, "PASSWORD(HASHED): ");
        for (size_t j = 0; j < 32; ++j)
            fprintf(f, "%02x", user->password[j]);
        fprintf(f, "\n---- END ----\n");
    }

    fclose(f);
    printf("Users info written to %s. Successfully\n", file);
}
/*
 * remove_user_by_id - removes user by user id
 * arguments:
 * @id: user id
 */
bool remove_user_by_id(int id) {
    int found = -1;

    // Find user by ID
    for (int i = 0; i < user_count; ++i) {
        if (user_list[i].id == id) {
            found = i;
            break;
        }
    }

    if (found == -1) {
        printf("User with ID %d not found.\n", id);
        return false;
    }

    struct User* user = (struct User*)malloc(sizeof(struct User));
    if (!user) return false;
    *user = user_list[found];

    char* password = malloc(13 * sizeof(char));
    if (!password) {
        free(user);
        return false;
    }

    input(password, 12, "PASSWORD", false, false, false, true, false);
    if (!authenticate_user(id, password)) {
        printf("INCORRECT PASSWORD. CANNOT REMOVE USER.\n");
        free(password);
        free(user);
        return false;
    }
    free(password);
    free(user);
    for (int i = found; i < user_count - 1; ++i) {
        user_list[i] = user_list[i + 1];
        user_list[i].id -= 1;
    }
    user_count--;
    if (user_count == 0) {
        free(user_list);
        user_list = NULL;
    } else {
        struct User* temp = realloc(user_list, user_count * sizeof(struct User));
        if (temp) {
            user_list = temp;
        }
    }

    printf("User with ID %d removed. Remaining users' IDs updated.\n", id);
    return true;
}
/*
 * read_user_from_file - reads all the users from a file
 * arguments:
 * @file: the file which users will be read from
 */
void read_user_from_file(const char* file) {
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("Failed to open file");
        return;
    }

    char line[256];
    struct User temp_user;
    bool in_block = false;
    int max_id = -1;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0; // remove newline

        if (strcmp(line, "---- START ----") == 0) {
            memset(&temp_user, 0, sizeof(struct User));
            in_block = true;
            continue;
        }

        if (strcmp(line, "---- END ----") == 0 && in_block) {
            struct User* temp = realloc(user_list, (user_count + 1) * sizeof(struct User));
            if (!temp) {
                fclose(fp);
                fprintf(stderr, "Memory allocation error\n");
                exit(1);
            }
            user_list = temp;
            user_list[user_count++] = temp_user;

            if (temp_user.id > max_id)
                max_id = temp_user.id;

            in_block = false;
            continue;
        }

        if (!in_block) continue;

        if (strncmp(line, "ID:", 3) == 0) {
            sscanf(line, "ID: %d", &temp_user.id);
        } else if (strncmp(line, "USERNAME:", 9) == 0) {
            sscanf(line, "USERNAME: %20[^\n]", temp_user.user_name);
        } else if (strncmp(line, "EMAIL:", 6) == 0) {
            sscanf(line, "EMAIL: %50[^\n]", temp_user.email);
        } else if (strncmp(line, "DATE OF BIRTH:", 14) == 0) {
            sscanf(line, "DATE OF BIRTH: %10[^\n]", temp_user.dob);
        } else if (strncmp(line, "MOBILE(encrypted):", 18) == 0) {
            const char *ptr = strchr(line, ':');
            if (ptr) {
                while (isspace((unsigned char)*ptr)) ptr++;
                strncpy(temp_user.mobile, ptr + 2, sizeof(temp_user.mobile) - 1);
                temp_user.mobile[sizeof(temp_user.mobile) - 1] = '\0';
            }
        } else if (strstr(line, "PINCODE(encrypted):") != NULL) {
            const char* ptr = strstr(line, "PINCODE(encrypted):");
            ptr += strlen("PINCODE(encrypted):");

            while (isspace((unsigned char)*ptr)) ptr++;

            strncpy(temp_user.pincode, ptr, sizeof(temp_user.pincode) - 1);
            temp_user.pincode[sizeof(temp_user.pincode) - 1] = '\0';
        } else if (strncmp(line, "PASSWORD(HASHED):", 17) == 0) {
            char hash_hex[65];
            sscanf(line, "PASSWORD(HASHED): %64s", hash_hex);
            if (strlen(hash_hex) == 64) {
                for (size_t i = 0; i < 32; ++i)
                    sscanf(hash_hex + 2 * i, "%2hhx", &temp_user.password[i]);
            }
        }
    }

    fclose(fp);
    if (max_id >= user_count)
        user_count = max_id + 1;
    
    printf("Successfully read file.\n");
}
/*
 * list_all_users - lists all users
 */
void list_all_users(void)
{
    for (int i = 0; i < user_count; i++)
    {
        printf("\nID: %d\nUSERNAME: %s\n", i, user_list[i].user_name);
    }
    
}
/*
 * backup_database_file - backup the database given
 * arguments:
 * @file - the database that will be backup
 */
void backup_database_file(const char *file)
{
    char *_file = malloc(strlen(file) + 8);
    strcpy(_file, "backup_");
    strcat(_file, file);
    write_users_to_file(_file);
    free(_file);
}
/*
 * write_users_to_csv - writes users to csv file with same name as "filename"
 * arguments:
 * @filename: the file which the data will be taken from
 */
void write_users_to_csv(const char *filename) {
    char *csv_filename = malloc(strlen(filename) + 5);
    if (!csv_filename) {
        perror("Memory allocation failed");
        return;
    }
    strcpy(csv_filename, filename);

    char *dot = strrchr(csv_filename, '.');
    if (dot) {
        strcpy(dot + 1, "csv");
    } else {
        strcat(csv_filename, ".csv");
    }

    FILE *fp = fopen(csv_filename, "w");
    if (!fp) {
        perror("Unable to open file");
        free(csv_filename);
        return;
    }

    fprintf(fp, "ID,UserName,Date Of Birth,Email,Mobile(ENCRYPTED),PINCODE(ENCRYPTED),PASSWORD(HASHED BY SHA-256)\n");

    for (int i = 0; i < user_count; i++) {
        fprintf(fp, "\"%d\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"", user_list[i].id, user_list[i].user_name, user_list[i].dob, user_list[i].email, user_list[i].mobile, user_list[i].pincode);
        for (size_t j = 0; j < 32; ++j)
            fprintf(fp, "%02x", user_list[i].password[j]);
        fprintf(fp, "\"\n");
    }

    fclose(fp);
    free(csv_filename);
}
/*
 * print_menu - prints the main menu
 */
void print_menu(void)
{               
    printf("\n\n\n***************************************\n*  BYTEKICK'S DATABASE WITH ENCRYPTION *\n***************************************\n\n");
    printf("OPTIONS\n1. Check total number of users.\n");
    printf("2. Check Username by ID.\n");
    printf("3. Add Account.\n");
    printf("4. Remove Account (PASSWORD REQUIRED).\n");
    printf("5. Check Information about user (PASSWORD REQUIRED).\n");
    printf("6. Change Information about user (PASSWORD REQUIRED).\n");
    printf("7. List all users\n");
    printf("8. Backup Database\n");
    printf("9. Write ALL USERS to CSV\n");
    printf("10. Exit Program\n");
    printf("Enter Your Choice (1-10): ");
}
int main(int argc, char* argv[])
{
    int choice, id;
    if (argc != 2) {
        printf("Syntax: ./a.out DATABASE.DAT\n");
        exit(-1);
    }
    read_user_from_file(argv[1]);
    while (1) {
        print_menu();
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            printf("Total Number of user: %d\n", user_count);
            break;
        
        case 2:
            printf("Enter ID to check username: ");
            scanf("%d", &id);
            printf("USERNAME OF ID (%d): %s\n", id, user_list[id].user_name);
            break;
        
        case 3:
            initnewUser();
            break;
        
        case 4:
            printf("Enter ID to remove account: ");
            scanf("%d", &id);
            remove_user_by_id(id);
            break;
        
        case 5:
            printf("Enter ID to check information about user: ");
            scanf("%d", &id);
            get_info(id);
            break;

        case 6:
            printf("Enter ID to change information about account: ");
            scanf("%d", &id);
            changeInfo(id);
            break;
        
        case 7:
            list_all_users();
            break;

        case 8:
            write_users_to_file(argv[1]);
            backup_database_file(argv[1]);
            break;
        
        case 9:
            write_users_to_csv(argv[1]);
            break;

        case 10:
            printf("EXITING PROGRAM....\n");
            write_users_to_file(argv[1]);
            exit(0);
        default:
            break;
        }
    }
}