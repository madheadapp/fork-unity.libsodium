using System;
using System.Text;

namespace unity.libsodium
{
    public static class StreamEncryption
    {
        private const int XSALSA20_KEY_BYTES = 32;
        private const int XSALSA20_NONCE_BYTES = 24;
        private const int CHACHA20_KEY_BYTES = 32;
        private const int CHACHA20_NONCEBYTES = 8;

        private const int BLOCK_SIZE = 64;
        // BUFFER_SIZE determines the chunk size for encryption/decryption operations.
        // 2MB was chosen as a compromise between memory usage and performance:
        // - Larger buffers reduce the number of calls to the native encryption function, improving throughput.
        // - Smaller buffers use less memory but increase processing overhead due to more frequent calls.
        // Adjust this value based on application requirements and platform constraints.
        private const int BUFFER_SIZE = 256 * 1024; // 256 KB buffer size
        [ThreadStatic]
        private static byte[] SharedBuffer = new byte[BUFFER_SIZE];
        
        public static byte[] GenerateNonceChaCha20()
        {
            return GetRandomBytes(CHACHA20_NONCEBYTES);
        }

        public static byte[] GenerateKey()
        {
            return GetRandomBytes(XSALSA20_KEY_BYTES);
        }

        public static byte[] EncryptChaCha20(string message, byte[] nonce, byte[] key)
        {
            return EncryptChaCha20(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        unsafe public static byte[] EncryptChaCha20(byte[] message, byte[] nonce, byte[] key)
        {
            if (key is not { Length: CHACHA20_KEY_BYTES })
                throw new ArgumentException("Invalid key length.");
            if (nonce is not { Length: CHACHA20_NONCEBYTES })
                throw new ArgumentException("Invalid nonce length.");

            var output = new byte[message.Length];
            ulong blockCounter = 0;
            var offset = 0;

            fixed (byte* outputPtr = output)
            {
                while (offset < message.Length)
                {
                    var chunkSize = Math.Min(BUFFER_SIZE, message.Length - offset);

                    // Copy the current chunk of the message into the chunk buffer
                    Buffer.BlockCopy(message, offset, SharedBuffer, 0, chunkSize);

                    var ret = NativeLibsodium.crypto_stream_chacha20_xor_ic(
                        outputPtr + offset, // Output pointer, offset for current chunk
                        SharedBuffer,        // Input: current chunk as byte array
                        (ulong)chunkSize,   // Only process the current chunk size
                        nonce,              // Nonce remains the same for all chunks
                        blockCounter,       // Initial block counter for this chunk
                        key                 // Key remains the same for all chunks
                    );

                    if (ret != 0)
                        throw new Exception("Error encrypting message using ChaCha20_xor_ic.");

                    // Increment blockCounter by the number of 64-byte blocks processed in this chunk
                    var blocksThisChunk = (ulong)((chunkSize + BLOCK_SIZE - 1) / BLOCK_SIZE);
                    blockCounter += blocksThisChunk;
                    offset += chunkSize;
                }
            }
            return output;
        }

        public static byte[] DecryptChaCha20(string cipherText, byte[] nonce, byte[] key)
        {
            return DecryptChaCha20(HexToBinary(cipherText), nonce, key);
        }

        unsafe public static byte[] DecryptChaCha20(byte[] cipherText, byte[] nonce, byte[] key)
        {
            //validate the length of the key
            if (key is not { Length: CHACHA20_KEY_BYTES })
                throw new ArgumentException("Invalid key length.");
            //throw new Exception("key", (key == null) ? 0 : key.Length,
            //	string.Format("key must be {0} bytes in length.", CHACHA20_KEY_BYTES));

            //validate the length of the nonce
            if (nonce is not { Length: CHACHA20_NONCEBYTES })
                throw new ArgumentException("Invalid nonce length.");
            //throw new Exception("nonce", (nonce == null) ? 0 : nonce.Length,
            //	string.Format("nonce must be {0} bytes in length.", CHACHA20_NONCEBYTES));

            var plainText = new byte[cipherText.Length];
            ulong blockCounter = 0;
            var offset = 0;

            fixed (byte* outputPtr = plainText)
            {
                while (offset < cipherText.Length)
                {
                    var chunkSize = Math.Min(BUFFER_SIZE, cipherText.Length - offset);

                    // Copy the current chunk of ciphertext into the chunk buffer
                    Buffer.BlockCopy(cipherText, offset, SharedBuffer, 0, chunkSize);

                    var ret = NativeLibsodium.crypto_stream_chacha20_xor_ic(
                        outputPtr + offset, // Output pointer, offset for current chunk
                        SharedBuffer,        // Input: current chunk as byte array
                        (ulong)chunkSize,   // Only process the current chunk size
                        nonce,              // Nonce remains the same for all chunks
                        blockCounter,       // Initial block counter for this chunk
                        key                 // Key remains the same for all chunks
                    );

                    if (ret != 0)
                        throw new Exception("Error decrypting message using ChaCha20_xor_ic.");

                    // Increment blockCounter by the number of 64-byte blocks processed in this chunk
                    var blocksThisChunk = (ulong)((chunkSize + BLOCK_SIZE - 1) / BLOCK_SIZE);
                    blockCounter += blocksThisChunk;
                    offset += chunkSize;
                }
            }
            return plainText;
        }

        public static unsafe byte[] GetRandomBytes(int count)
        {
            byte[] buffer = new byte[count];
            fixed (byte* bufferPtr = buffer)
            {
                NativeLibsodium.randombytes_buf(bufferPtr, (uint)count);
            }
            return buffer;
        }


        unsafe public static byte[] HexToBinary(string hex)
        {
            const string IGNORED_CHARS = ":- ";

            byte[] arr = new byte[hex.Length >> 1];
            byte[] hexBytes = Encoding.ASCII.GetBytes(hex);
            int binLength;

            fixed (byte* arrPtr = arr)
            {
                //we call sodium_hex2bin with some chars to be ignored
                int ret = NativeLibsodium.sodium_hex2bin(
                    arrPtr, (uint)arr.Length,
                    hex, (uint)hexBytes.Length,
                    IGNORED_CHARS,
                    out binLength,
                    null
                );

                if (ret != 0)
                    throw new Exception("Internal error, decoding failed.");
            }
            //remove the trailing nulls from the array, if there were some format characters in the hex string before
            if (arr.Length != binLength)
            {
                byte[] tmp = new byte[binLength];
                Array.Copy(arr, 0, tmp, 0, binLength);
                return tmp;
            }

            return arr;
        }
    }
}