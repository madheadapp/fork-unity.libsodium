using System.Collections;
using System.Collections.Generic;
using NUnit.Framework;
using UnityEngine;
using UnityEngine.TestTools;

namespace unity.libsodium.test
{
    public class TestSimple
    {
        [Test]
        public void TestChaCha20()
        {
            int x = NativeLibsodium.sodium_init();
            Assert.True(x == 0 || x == 1);

            const string MESSAGE = "Test message to encrypt";
            var nonce = StreamEncryption.GenerateNonceChaCha20();
            var key = StreamEncryption.GenerateKey();

            //encrypt it
            var encrypted = StreamEncryption.EncryptChaCha20(MESSAGE, nonce, key);
            
            var encryptedText = System.Text.Encoding.UTF8.GetString(encrypted);
            Debug.Log("Encrypted text: " + encryptedText);

            //decrypt it
            var decrypted = StreamEncryption.DecryptChaCha20(encrypted, nonce, key);

            var decryptedText = System.Text.Encoding.UTF8.GetString(decrypted);
            Debug.Log("Decrypted text: " + decryptedText);
            
            Assert.AreEqual(MESSAGE, decryptedText);
        }

    }
}
