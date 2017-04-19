/* Empty PKCS#11 implementation to be used in functional tests */

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define CK_NEED_ARG_LIST 1

#include <string.h>
#include <pkcs11.h>

CK_RV C_Initialize(void *p)
{
	return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR p)
{
	return CKR_GENERAL_ERROR;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (pSlotList != NULL) {
		pSlotList[0] = 0;
	}
	*pulCount = 1;
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR info)
{
	info->cryptokiVersion.major = 1;
	info->cryptokiVersion.minor = 2;
	strcpy((char *) info->manufacturerID, "fake manufacturer ID");
	info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
	strcpy((char *) info->libraryDescription, "fake library description");
	info->libraryVersion.major = 3;
	info->libraryVersion.minor = 4;
	return CKR_OK;
}

CK_RV C_Finalize(void *r)
{
	return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	*phSession = 1;
	return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return CKR_OK;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	*phKey = 1;
	return CKR_OK;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	*phPublicKey = 1;
	*phPrivateKey = 2;
	return CKR_OK;
}

CK_RV C_EncryptInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_OK;
}

static CK_RV copy_string(const char *str, CK_BYTE_PTR pDest, CK_ULONG_PTR pDestLen)
{
	CK_RV ret = CKR_OK;
	size_t result_size = strlen(str);
	if(pDest == NULL) {
		*pDestLen = result_size;
	} else if (*pDestLen < result_size) {
		*pDestLen = result_size;
		ret = CKR_BUFFER_TOO_SMALL;
	} else {
		*pDestLen = result_size;
		memcpy(pDest, str, result_size);
	}
	return ret;
}

CK_RV C_Encrypt (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	return copy_string("fake ciphertext", pEncryptedData, pulEncryptedDataLen);
}

CK_RV C_DecryptInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_OK;
}

CK_RV C_Decrypt (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	return copy_string("fake recovered", pData, pulDataLen);
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	*phObject = 1;
	return CKR_OK;
}

static void get_single_attribute_value (CK_ATTRIBUTE_PTR pAttribute, void *pValue, size_t len, CK_RV *ret)
{
	if(pAttribute->pValue == NULL) {
		pAttribute->ulValueLen = len;
	} else if (pAttribute->ulValueLen < len) {
		pAttribute->ulValueLen = -1;
		*ret = CKR_BUFFER_TOO_SMALL;
	} else {
		pAttribute->ulValueLen = len;
		memcpy(pAttribute->pValue, pValue, len);
	}
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV ret = CKR_OK;
	CK_ULONG i;
	for(i = 0; i < ulCount; i++) {
		CK_ATTRIBUTE_PTR pAttribute = pTemplate + i;
		switch(pAttribute->type) {
			case CKA_CLASS:
				{
					CK_OBJECT_CLASS value = CKO_SECRET_KEY;
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_TOKEN:
				{
					CK_BBOOL value = CK_FALSE;
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_WRAP:
			case CKA_UNWRAP:
			case CKA_SIGN:
			case CKA_VERIFY:
			case CKA_ENCRYPT:
			case CKA_DECRYPT:
				{
					CK_BBOOL value = CK_TRUE;
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_VALUE:
			case CKA_MODULUS:
				{
					unsigned char value[16];
					int j;
					for (j=0;j<sizeof(value);j++) {
						value[j] = j;
					}
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_VALUE_LEN:
				{
					CK_ULONG value = 16;
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_KEY_TYPE:
				{
					CK_KEY_TYPE value = CKK_AES;
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			case CKA_PUBLIC_EXPONENT:
				{
					CK_BYTE value[] = { 0x01, 0x00, 0x01 };
					get_single_attribute_value(pAttribute, &value, sizeof(value), &ret);
				}
				break;
			default:
				pAttribute->ulValueLen = -1;
				ret = CKR_ATTRIBUTE_TYPE_INVALID;
				break;
		}
	}
	return ret;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	return CKR_OK;
}

CK_RV C_DeriveKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	*phKey = 1;
	return CKR_OK;
}

CK_RV C_SignInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_OK;
}

CK_RV C_Sign (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	return copy_string("fake signature", pSignature, pulSignatureLen);
}

CK_RV C_VerifyInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	return CKR_OK;
}

CK_RV C_Verify (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV ret;
	if(strncmp("Invalid", (char *) pSignature, ulSignatureLen) == 0) {
		ret = CKR_SIGNATURE_INVALID;
	} else {
		ret = CKR_OK;;
	}
	return ret;
}

CK_RV C_WrapKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	return copy_string("fake wrapped", pWrappedKey, pulWrappedKeyLen);
}

CK_RV C_UnwrapKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	*phKey = 1;
	return CKR_OK;
}

CK_RV C_SetAttributeValue (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	return CKR_OK;
}

CK_RV C_CopyObject (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	*phNewObject = 1;
	return CKR_OK;
}
