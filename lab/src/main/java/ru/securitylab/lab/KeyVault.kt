package ru.securitylab.lab

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import ru.securitylab.common.Evidence
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

object KeyVault {
    private const val ALIAS="asl.pin.key"
    private fun store()=KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun key()=store().getKey(ALIAS,null) as SecretKey
    fun create(c:Context):JSONObject {
        val ks=store();if(ks.containsAlias(ALIAS))ks.deleteEntry(ALIAS)
        File(c.filesDir,"vault.json").delete()
        val gen=KeyGenerator.getInstance("AES","AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true).setUserAuthenticationParameters(30,KeyProperties.AUTH_DEVICE_CREDENTIAL).build())
        val k=gen.generateKey()
        val info=SecretKeyFactory.getInstance("AES","AndroidKeyStore").getKeySpec(k,KeyInfo::class.java) as KeyInfo
        return JSONObject().put("created",true).put("authentication_required",info.isUserAuthenticationRequired)
            .put("auth_type",info.userAuthenticationType).put("validity_seconds",info.userAuthenticationValidityDurationSeconds)
            .put("security_level",info.securityLevel).put("security_level_name",when(info.securityLevel){KeyProperties.SECURITY_LEVEL_SOFTWARE->"SOFTWARE";KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT->"TRUSTED_ENVIRONMENT";KeyProperties.SECURITY_LEVEL_STRONGBOX->"STRONGBOX";else->"OTHER"}).put("encoded_null",k.encoded==null)
    }
    fun hasData(c:Context)=File(c.filesDir,"vault.json").exists()
    fun seed(c:Context):JSONObject {
        val plain=("Защищённая запись · "+java.util.UUID.randomUUID()).toByteArray(Charsets.UTF_8)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key())
        val encrypted=cipher.doFinal(plain)
        val blob=JSONObject().put("iv",Base64.encodeToString(cipher.iv,Base64.NO_WRAP))
            .put("ciphertext",Base64.encodeToString(encrypted,Base64.NO_WRAP)).put("sha256",Evidence.sha(plain))
        File(c.filesDir,"vault.json").writeText(blob.toString())
        return decrypt(c).put("seeded",true)
    }
    fun decrypt(c:Context):JSONObject {
        val blob=JSONObject(File(c.filesDir,"vault.json").readText())
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,Base64.decode(blob.getString("iv"),Base64.NO_WRAP)))
        val plain=cipher.doFinal(Base64.decode(blob.getString("ciphertext"),Base64.NO_WRAP))
        return JSONObject().put("decrypted",true).put("matches",Evidence.sha(plain)==blob.getString("sha256"))
            .put("plaintext",String(plain,Charsets.UTF_8)).put("ciphertext",blob.getString("ciphertext"))
    }
    fun attempt(c:Context):JSONObject=try{decrypt(c)}catch(e:Exception){Evidence.error(e).put("decrypted",false)}
}
