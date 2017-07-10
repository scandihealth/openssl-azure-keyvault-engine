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
    azure_key_vault_rsa_pub_enc,
    azure_key_vault_rsa_pub_dec,
    azure_key_vault_rsa_priv_enc,
    azure_key_vault_rsa_priv_dec,
    NULL, // rsa_mod_exp
    NULL, // bn_mod_exp
    azure_key_vault_init,
    azure_key_vault_finish,
    0, //RSA_METHOD_FLAGS
    NULL, // appdata
    azure_key_vault_rsa_sign,
    azure_key_valt_rsa_verify,
    NULL, // keygen
}

static int azure_key_vault_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return 0;
}

static int azure_key_vault_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return 0;
}

static int azure_key_vault_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return 0;
}

static int azure_key_vault_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return 0;
}

static int azure_key_vault_rsa_sign(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    return 0; 
}

static int azure_key_valt_rsa_verify(int dtype, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
    return 0;
}

static int azure_key_value_init(RSA *rsa)
{
    return 0;
}

static int azure_key_vault_finish(RSA *rsa)
{
    return 0;
}