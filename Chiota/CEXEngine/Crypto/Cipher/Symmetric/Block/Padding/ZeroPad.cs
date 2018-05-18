#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// ZeroPad: The Zero Padding Scheme (Not Recommended)
    /// </summary>
    public sealed class ZeroPad : IPadding
    {
        #region Constants
        private const string ALG_NAME = "ZeroPad";
        #endregion

        #region Properties
        /// <summary>
        /// Get: The padding modes type name
        /// </summary>
        public PaddingModes Enumeral
        {
            get { return PaddingModes.None; }
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
            byte code = (byte)0;

            while (Offset < Input.Length)
            {
                Input[Offset] = code;
                Offset++;
            }

            return (Input.Length - Offset);
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
            int len = Input.Length - 1;
            byte code = (byte)0;

            for (int i = len; i > 0; i--)
            {
                if (Input[i] != code)
                    return (len - i);
            }

            return 0;
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
            int len = Input.Length - 1;
            byte code = (byte)0;

            for (int i = len; i > 0; i--)
            {
                if (Input[Offset + i] != code)
                    return (len - i);
            }

            return 0;
        }
        #endregion
    }
}
