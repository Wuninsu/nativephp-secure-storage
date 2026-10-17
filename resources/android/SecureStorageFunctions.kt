package com.wuninsu.securestorage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.nativephp.mobile.bridge.BridgeFunction
import com.nativephp.mobile.bridge.BridgeResponse
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secure storage bridge functions.
 * Namespace: "WuninsuSecureStorage.*"
 *
 * Values are encrypted with AES-256-GCM under a key that never leaves the Android Keystore (hardware-backed where
 * the phone has it). The ciphertext lives in noBackupFilesDir, so it is never part of a backup.
 */
object SecureStorageFunctions {

    /**
     * Parameters: key (string)
     * Returns: {status: "found", value} or {status: "not_found"}
     */
    class Get(private val context: Context) : BridgeFunction {
        override fun execute(parameters: Map<String, Any>): Map<String, Any> {
            val key = parameters["key"] as? String
                ?: return BridgeResponse.error("INVALID_PARAMETERS", "key is required")

            return try {
                val value = Vault(context).read(key)
                    ?: return BridgeResponse.success(mapOf("status" to "not_found"))

                BridgeResponse.success(mapOf("status" to "found", "value" to value))
            } catch (e: Exception) {
                Log.e(TAG, "Read failed: ${e.javaClass.simpleName}")
                BridgeResponse.error("FAILED", "The value could not be read.")
            }
        }
    }

    /**
     * Parameters: key (string), value (string)
     * Returns: {success: true}
     */
    class Set(private val context: Context) : BridgeFunction {
        override fun execute(parameters: Map<String, Any>): Map<String, Any> {
            val key = parameters["key"] as? String
                ?: return BridgeResponse.error("INVALID_PARAMETERS", "key is required")
            val value = parameters["value"] as? String
                ?: return BridgeResponse.error("INVALID_PARAMETERS", "value is required")

            return try {
                Vault(context).write(key, value)
                BridgeResponse.success(mapOf("success" to true))
            } catch (e: Exception) {
                Log.e(TAG, "Write failed: ${e.javaClass.simpleName}")
                BridgeResponse.error("FAILED", "The value could not be stored.")
            }
        }
    }

    /**
     * Parameters: key (string)
     * Returns: {success: true}, also when nothing was stored
     */
    class Delete(private val context: Context) : BridgeFunction {
        override fun execute(parameters: Map<String, Any>): Map<String, Any> {
            val key = parameters["key"] as? String
                ?: return BridgeResponse.error("INVALID_PARAMETERS", "key is required")

            Vault(context).delete(key)

            return BridgeResponse.success(mapOf("success" to true))
        }
    }

    private const val TAG = "WuninsuSecureStorage"
}

/**
 * One encrypted file per key. File names are a hash of the key, and the key is bound to its ciphertext as GCM
 * associated data, so a file copied under another name does not decrypt.
 */
private class Vault(context: Context) {
    private val dir = File(context.noBackupFilesDir, DIRECTORY)

    fun read(key: String): String? = synchronized(LOCK) {
        val file = fileFor(key)
        if (!file.exists()) return null

        val secretKey = keystore().getKey(KEYSTORE_ALIAS, null) as? SecretKey
        val blob = file.readBytes()

        // The Keystore key is gone or the file is not ours: it can never be read again.
        if (secretKey == null || blob.size <= IV_LENGTH) {
            file.delete()
            return null
        }

        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_BITS, blob, 0, IV_LENGTH))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            String(cipher.doFinal(blob, IV_LENGTH, blob.size - IV_LENGTH), Charsets.UTF_8)
        } catch (e: AEADBadTagException) {
            file.delete()
            null
        }
    }

    fun write(key: String, value: String): Unit = synchronized(LOCK) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey())
        cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
        val blob = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))

        dir.mkdirs()
        val file = fileFor(key)
        val tmp = File(dir, "${file.name}.tmp")
        tmp.writeBytes(blob)

        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IllegalStateException("Could not save the value")
        }
    }

    fun delete(key: String): Unit = synchronized(LOCK) {
        fileFor(key).delete()
    }

    private fun fileFor(key: String): File {
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(key.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        return File(dir, "$hash.bin")
    }

    private fun keystore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private fun getOrCreateSecretKey(): SecretKey {
        (keystore().getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )

        return generator.generateKey()
    }

    companion object {
        private val LOCK = Any()
        private const val DIRECTORY = "wuninsu_secure_storage"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "wuninsu_secure_storage"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val TAG_BITS = 128
    }
}
