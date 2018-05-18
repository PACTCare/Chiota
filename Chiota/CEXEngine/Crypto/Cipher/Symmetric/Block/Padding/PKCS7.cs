#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// The PKCS7 Padding Scheme
    /// </summary>
    /// 
    /// <remarks>
    /// <description>Guiding Publications:</description>
    /// <list type="number">
    /// <item><description>RFC <a href="http://tools.ietf.org/html/rfc5652">5652</a>.</description></item>
    /// </list>
    /// </remarks>
    public sealed class PKCS7 : IPadding
    {
        #region Constants
        private const string ALG_NAME = "PKCS7";
        #endregion

        #region Properties
        /// <summary>
        /// Get: The padding modes type name
        /// </summary>
        public PaddingModes Enumeral
        {
            get { return PaddingModes.PKCS7; }
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

            while (Offset < Input.Length)
                Input[Offset++] = code;

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
            // note: even with the check, if the last decrypted byte is equal to 1,
            // pkcs will see this last data byte as indicating a single byte of padding and return 1..
            // If an input does not need padding, mark the corresponding padding flag (in ex. CipherDescription) to None
            int len = Input.Length - 1;
	        byte code = Input[len];

            if ((int)code > len)
            {
                return (code > len + 1) ? 0 : len + 1;
            }
            else
            {
                // double check
                for (int i = Input.Length - 1; i >= Input.Length - code; --i)
                {
                    if (Input[i] != code)
                    {
                        code = 0;
                        break;
                    }
                }

                return code;
            }
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
            int len = Input.Length - (Offset + 1);
	        byte code = Input[Input.Length - 1];

            if ((int)code > len)
            {
                return (code > len + 1) ? 0 : len + 1;
            }
            else
            {
                for (int i = Input.Length - 1; i >= Input.Length - code; --i)
                {
                    if (Input[i] != code)
                    {
                        code = 0;
                        break;
                    }
                }

                return code;
            }
        }
        #endregion
    }
}
