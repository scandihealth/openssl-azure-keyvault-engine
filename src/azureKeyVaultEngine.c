#include <openssl/engine.h>
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
