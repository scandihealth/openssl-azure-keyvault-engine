#include <openssl/engine.h>
#include <openssl/rsa.h>

static const char *engine_azure_key_vault_id = "azure-keyvault";
static const char *engine_azure_key_vault_name = "Microsoft Azure Key Vault OpenSSL engine by DXC Technologies";

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);

int azure_key_value_init(ENGINE *e)
{
    printf("Microsoft Azure Key Vault Engine Initialization!\n");
    return 1337;
}

int bind_helper(ENGINE *e, const char *id)
{
    if(!ENGINE_set_id(e, engine_azure_key_vault_id) || !ENGINE_set_name(e, engine_azure_key_vault_name) || !ENGINE_set_init_function(e, azure_key_value_init))) return 0;
    return 1;
}

const RSA_METHOD* AZURE_KEY_VAULT_RSA_METH()
{
    return (&azure_key_value_meth);
}

static RSA_METHOD azure_key_vault_meth =
{
    const char *name,
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding),
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding),
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding),
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding),
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx),
    /* Can be null */
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
    /* called at new */
    int (*init) (RSA *rsa),
    /* called at free */
    int (*finish) (RSA *rsa),
    /* RSA_METHOD_FLAG_* things */
    int flags,
    /* may be needed! */
    char *app_data,
    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead. Note:
     * for backwards compatibility this functionality is only enabled if the
     * RSA_FLAG_SIGN_VER option is set in 'flags'.
     */
    int (*rsa_sign) (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const RSA *rsa),
    int (*rsa_verify) (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa),
    NULL, // keygen
}