#region Directives
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW.Arithmetic
{
    /// <summary>
    /// This class is needed for the conversions while encoding and decoding, as well as for comparison between arrays of some dimensions
    /// </summary>
    internal static class RainbowUtil
    {
        /// <summary>
        /// This function converts an one-dimensional array of bytes into a one-dimensional array of int
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>The one-dimensional int-array that corresponds the input</returns>
        public static int[] ConvertArraytoInt(byte[] Input)
        {
            int[] output = new int[Input.Length];

            for (int i = 0; i < Input.Length; i++)
                output[i] = Input[i] & GF2Field.MASK;

            return output;
        }

        /// <summary>
        /// This function converts an one-dimensional array of bytes into a one-dimensional array of type short
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>A one-dimensional short-array that corresponds the input</returns>
        public static short[] ConvertArray(byte[] Input)
        {
            short[] output = new short[Input.Length];
            for (int i = 0; i < Input.Length; i++)
            {
                output[i] = (short)(Input[i] & GF2Field.MASK);
            }
            return output;
        }

        /// <summary>
        /// This function converts a matrix of bytes into a matrix of type short
        /// </summary>
        /// 
        /// <param name="Input">The matrix to be converted</param>
        /// 
        /// <returns>A short-matrix that corresponds the input</returns>
        public static short[][] ConvertArray(byte[][] Input)
        {
            short[][] output = ArrayUtils.CreateJagged<short[][]>(Input.Length, Input[0].Length);

            for (int i = 0; i < Input.Length; i++)
            {
                for (int j = 0; j < Input[0].Length; j++)
                    output[i][j] = (short)(Input[i][j] & GF2Field.MASK);
            }

            return output;
        }

        /// <summary>
        /// This function converts a 3-dimensional array of bytes into a 3-dimensional array of type short
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>A short-array that corresponds the input</returns>
        public static short[][][] ConvertArray(byte[][][] Input)
        {
            short[][][] output = ArrayUtils.CreateJagged<short[][][]>(Input.Length, Input[0].Length, Input[0][0].Length);

            for (int i = 0; i < Input.Length; i++)
            {
                for (int j = 0; j < Input[0].Length; j++)
                {
                    for (int k = 0; k < Input[0][0].Length; k++)
                        output[i][j][k] = (short)(Input[i][j][k] & GF2Field.MASK);
                }
            }
            return output;
        }

        /// <summary>
        /// This function converts an array of type short into an array of type byte
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>The byte-array that corresponds the input</returns>
        public static byte[] ConvertArray(short[] Input)
        {
            byte[] output = new byte[Input.Length];

            for (int i = 0; i < Input.Length; i++)
                output[i] = (byte)Input[i];
            
            return output;
        }

        /// <summary>
        /// This function converts an array of type int into an array of type byte
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>The byte-array that corresponds the input</returns>
        public static byte[] ConvertIntArray(int[] Input)
        {
            byte[] output = new byte[Input.Length];

            for (int i = 0; i < Input.Length; i++)
                output[i] = (byte)Input[i];
            
            return output;
        }

        /// <summary>
        /// This function converts a matrix of type short into a matrix of type byte
        /// </summary>
        /// 
        /// <param name="Input">The matrix to be converted</param>
        /// 
        /// <returns>The byte-matrix that corresponds the input</returns>
        public static byte[][] ConvertArray(short[][] Input)
        {
            byte[][] output = ArrayUtils.CreateJagged<byte[][]>(Input.Length, Input[0].Length);

            for (int i = 0; i < Input.Length; i++)
            {
                for (int j = 0; j < Input[0].Length; j++)
                    output[i][j] = (byte)Input[i][j];
            }

            return output;
        }

        /// <summary>
        /// This function converts a 3-dimensional array of type short into a 3-dimensional array of type byte
        /// </summary>
        /// 
        /// <param name="Input">The array to be converted</param>
        /// 
        /// <returns>The byte-array that corresponds the input</returns>
        public static byte[][][] ConvertArray(short[][][] Input)
        {
            byte[][][] output = ArrayUtils.CreateJagged<byte[][][]>(Input.Length, Input[0].Length, Input[0][0].Length);

            for (int i = 0; i < Input.Length; i++)
            {
                for (int j = 0; j < Input[0].Length; j++)
                {
                    for (int k = 0; k < Input[0][0].Length; k++)
                        output[i][j][k] = (byte)Input[i][j][k];
                }
            }

            return output;
        }

        /// <summary>
        /// Compare two short arrays
        /// </summary>
        /// 
        /// <param name="A">The first short array</param>
        /// <param name="B">The second short array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(short[] A, short[] B)
        {
            if (A.Length != B.Length)
                return false;
            
            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
                result &= A[i] == B[i];
            
            return result;
        }

        /// <summary>
        /// Compare two two-dimensional short arrays
        /// </summary>
        /// 
        /// <param name="A">The first short array</param>
        /// <param name="B">The second short array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(short[][] A, short[][] B)
        {
            if (A.Length != B.Length)
                return false;
            
            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
                result &= Equals(A[i], B[i]);
            
            return result;
        }

        /// <summary>
        /// Compare two three-dimensional short arrays
        /// </summary>
        /// 
        /// <param name="A">The first short array</param>
        /// <param name="B">The second short array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(short[][][] A, short[][][] B)
        {
            if (A.Length != B.Length)
                return false;
            
            bool result = true;
            for (int i = A.Length - 1; i >= 0; i--)
                result &= Equals(A[i], B[i]);
            
            return result;
        }
    }
}
