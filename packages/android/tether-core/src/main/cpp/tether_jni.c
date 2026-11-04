#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern char *tether_call(const unsigned char *, size_t);
extern void tether_free(char *);
static void wipe(void *value, size_t length) { volatile unsigned char *p = value; while (length--) *p++ = 0; }
static void fail(JNIEnv *env, const char *message) {
    jclass type = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (type) (*env)->ThrowNew(env, type, message);
}
JNIEXPORT jbyteArray JNICALL Java_app_fledgeling_tether_NativeBridge_call(JNIEnv *env, jobject self, jbyteArray request) {
    (void)self;
    if (!request) { fail(env, "Invalid native request"); return NULL; }
    jsize length = (*env)->GetArrayLength(env, request);
    if (length <= 0 || length > 131072) { fail(env, "Native request exceeds limit"); return NULL; }
    unsigned char *input = malloc((size_t)length);
    if (!input) { fail(env, "Native allocation refused"); return NULL; }
    (*env)->GetByteArrayRegion(env, request, 0, length, (jbyte *)input);
    if ((*env)->ExceptionCheck(env)) { wipe(input, (size_t)length); free(input); return NULL; }
    char *response = tether_call(input, (size_t)length);
    wipe(input, (size_t)length); free(input);
    if (!response) { fail(env, "Native response missing"); return NULL; }
    size_t count = strnlen(response, 262145);
    if (count > 262144) { tether_free(response); fail(env, "Native response exceeds limit"); return NULL; }
    jbyteArray output = (*env)->NewByteArray(env, (jsize)count);
    if (output) (*env)->SetByteArrayRegion(env, output, 0, (jsize)count, (const jbyte *)response);
    tether_free(response);
    return output;
}
