#region Directives
using System;
using System.Security.Cryptography;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// X923: The X.923 Padding Scheme
    /// </summary>
    public sealed class X923 : IPadding
    {
        #region Constants
        private const string ALG_NAME = "X923";
        #endregion

        #region Properties
        /// <summary>
        /// Get: The padding modes type name
        /// </summary>
        public PaddingModes Enumeral
        {
            get { return PaddingModes.X923; }
        }

        /// <summary>
        /// Get: Padding name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// 
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int AddPadding(byte[] Input, int Offset)
        {
            byte code = (byte)(Input.Length - Offset);
            int len = (Input.Length - Offset) - 1;

            if (len > 0)
            {
                byte[] data = new byte[len];
                using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
                    random.GetBytes(data);

                Buffer.BlockCopy(data, 0, Input, Offset, len);
            }

            Input[Input.Length - 1] = code;

            return code;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input)
        {
            int code = Input[Input.Length - 1] & 0xff;

            if (code > Input.Length - 1)
                code = 0;

                return code;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input, int Offset)
        {
            int code = Input[Input.Length - 1] & 0xff;

            if (code > Input.Length - 1)
                code = 0;

            return code;
        }
        #endregion
    }
}
