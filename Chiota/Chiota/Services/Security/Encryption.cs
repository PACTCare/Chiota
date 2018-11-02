using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Chiota.Services.Security
{
    public static class Encryption
    {
        #region Methods

        #region Encrypt

        internal static string Encrypt(string data, string encryptionKey, string salt)
        {
            var algorithm = GetAlgorithm(encryptionKey, salt);

            // Anything to process?
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }

            byte[] encryptedBytes;
            using (var encrypt = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV))
            {
                var bytesToEncrypt = Encoding.UTF8.GetBytes(data);
                encryptedBytes = InMemoryCrypt(bytesToEncrypt, encrypt);
            }

            return Convert.ToBase64String(encryptedBytes);
        }

        #endregion

        #region Decrypt

        internal static string Decrypt(string data, string encryptionKey, string salt)
        {
            var algorithm = GetAlgorithm(encryptionKey, salt);

            // Anything to process?
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }

            byte[] decryptedBytes;
            using (var decrypt = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV))
            {
                var encryptedBytes = Convert.FromBase64String(data);
                decryptedBytes = InMemoryCrypt(encryptedBytes, decrypt);
            }

            return Encoding.UTF8.GetString(decryptedBytes);
        }

        #endregion

        #region GetAlgorithm

        private static RijndaelManaged GetAlgorithm(string encryptionKey, string salt)
        {
            // Create an encryption key from the encryptionPassword and salt.
            var key = new Rfc2898DeriveBytes(encryptionKey, Encoding.UTF8.GetBytes(salt));

            // Declare that we are going to use the Rijndael algorithm with the key that we've just got.
            var algorithm = new RijndaelManaged();
            var bytesForKey = algorithm.KeySize / 8;
            var bytesForIv = algorithm.BlockSize / 8;
            algorithm.Key = key.GetBytes(bytesForKey);
            algorithm.IV = key.GetBytes(bytesForIv);

            return algorithm;
        }

        #endregion

        #region InMemoryCrypt

        private static byte[] InMemoryCrypt(byte[] data, ICryptoTransform transform)
        {
            var memory = new MemoryStream();
            using (Stream stream = new CryptoStream(memory, transform, CryptoStreamMode.Write))
            {
                stream.Write(data, 0, data.Length);
            }

            return memory.ToArray();
        }

        #endregion

        #endregion
    }
}
