package com.sample.wrappedkey

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.WrappedKeyEntry
import android.util.Base64
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.sample.wrappedkey.payload.DeviceInfo
import com.sample.wrappedkey.payload.WrappedKey
import com.sample.wrappedkey.services.KeyService
import kotlinx.android.synthetic.main.activity_main.*
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher


class MainActivity : AppCompatActivity(), View.OnClickListener {
    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val WRAP_KEY_ALIAS = "wrapKeyAlias"
        const val TAG = "AndroidWrappedKeyApp"
        const val BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
        const val END_CERT = "-----END CERTIFICATE-----"
        const val KEY_SERVICE_URL = "http://192.168.0.11:8080/" // TODO - Change this to your server ip
        const val IMPORTED_KEY_ALIAS = "importedAlias"
        const val WRAP_KEY_TRANSFORMATION = "RSA/ECB/OAEPPadding"
        const val IMPORTED_KEY_ALGO = "AES/ECB/PKCS7Padding"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        getWrappedKeyButton.setOnClickListener(this)
    }


    fun convertX509CertificateToPem(x509Cert : X509Certificate) : String {
        val builder = StringBuilder()
        builder.append(BEGIN_CERT)
        val b64encoded = Base64.encodeToString(x509Cert.encoded, Base64.DEFAULT)
        builder.append(b64encoded)
        builder.append(END_CERT)
        return builder.toString()
    }

    override fun onClick(view: View?) {
        when(view?.id) {
            R.id.getWrappedKeyButton -> importWrappedKey()
        }

    }

    fun importWrappedKey() {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
        var certChain = keystore.getCertificateChain(WRAP_KEY_ALIAS)
        if (certChain == null) {
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            val paramSpec = KeyGenParameterSpec.Builder(WRAP_KEY_ALIAS, KeyProperties.PURPOSE_WRAP_KEY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .build()
            keyPairGenerator.initialize(paramSpec)
            keyPairGenerator.generateKeyPair()
            certChain = keystore.getCertificateChain(WRAP_KEY_ALIAS)
        }
        val deviceInfo = DeviceInfo()
        certChain.get(0).let {
            deviceInfo.deviceCertificate = convertX509CertificateToPem(it as X509Certificate)
        }

        val retrofit = Retrofit.Builder()
            .baseUrl(KEY_SERVICE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        val service: KeyService = retrofit.create(KeyService::class.java)
        service.getWrappedKey(deviceInfo).enqueue(
            object : Callback<WrappedKey> {

                override fun onFailure(call: Call<WrappedKey>, t: Throwable) {
                    Log.d(TAG, "Fail to getWrappedKey")
                    resultMsg.text = "Failed to get wrappedKey from server"
                }

                override fun onResponse(call: Call<WrappedKey>, response: Response<WrappedKey>) {
                    Log.d(TAG, "wrappedKey = " + response.body()?.wrappedKey)
                    val b64WrappedKey = response.body()?.wrappedKey
                    val wrappedKey = Base64.decode(b64WrappedKey, Base64.DEFAULT)
                    importWrappedKey(wrappedKey, WRAP_KEY_ALIAS)
                    checkImportedKey()
                }
            }
        )
    }

    fun importWrappedKey(wrappedKey: ByteArray?, wrappingKeyAlias: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null, null)
        val spec: AlgorithmParameterSpec = KeyGenParameterSpec.Builder(
            wrappingKeyAlias,
            KeyProperties.PURPOSE_WRAP_KEY
        ).setDigests(KeyProperties.DIGEST_SHA256).build()

        val wrappedKeyEntry = WrappedKeyEntry(wrappedKey, wrappingKeyAlias,WRAP_KEY_TRANSFORMATION, spec)
        keyStore.setEntry(IMPORTED_KEY_ALIAS, wrappedKeyEntry, null)
    }

    fun checkImportedKey() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null, null)
        if (keyStore.containsAlias(IMPORTED_KEY_ALIAS)) {

            val key: Key = keyStore.getKey(IMPORTED_KEY_ALIAS, null)
            var cipher = Cipher.getInstance(IMPORTED_KEY_ALGO)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val encrypted: ByteArray = cipher.doFinal("test".toByteArray())

            cipher = Cipher.getInstance(IMPORTED_KEY_ALGO)
            cipher.init(Cipher.DECRYPT_MODE, key)
            val decrypted = cipher.doFinal(encrypted)

            if ("test".equals(String(decrypted))) {
                Log.d(TAG, "WrappedKey import SUCCESS")
                resultMsg.text = "WrappedKey import SUCCESS"
            } else {
                Log.d(TAG, "WrappedKey import FAIL")
                resultMsg.text = "WrappedKey import FAIL"
            }
        }
    }
}