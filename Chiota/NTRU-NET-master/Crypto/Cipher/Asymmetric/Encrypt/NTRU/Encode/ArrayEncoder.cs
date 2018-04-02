#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Exceptions;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Encode
{
    /// <summary>
    /// Converts a coefficient array to a compact byte array and vice versa.
    /// </summary>
    public class ArrayEncoder
    {
        #region Fields
        // Bit string to coefficient conversion table from P1363.1.
        private static readonly int[] COEFF1_TABLE = { 0, 0, 0, 1, 1, 1, -1, -1 };
        private static readonly int[] COEFF2_TABLE = { 0, 1, -1, 0, 1, -1, 0, 1 };
        // Coefficient to bit string conversion table from P1363.1.
        private static readonly int[] BIT1_TABLE = { 1, 1, 1, 0, 0, 0, 1, 0, 1 };
        private static readonly int[] BIT2_TABLE = { 1, 1, 1, 1, 0, 0, 0, 1, 0 };
        private static readonly int[] BIT3_TABLE = { 1, 0, 1, 0, 0, 1, 1, 1, 0 };
        private static readonly BigInteger THREE = BigInteger.ValueOf(3);
        #endregion

        #region Constructor
        private ArrayEncoder() { }
        #endregion

        #region Public Methods
        /// <summary>
        /// Decodes a <c>byte</c> array encoded with EncodeMod3Sves(int[], boolean) back to an <c>int</c> array with <c>N</c> coefficients between <c>-1</c> and <c>1</c>.
        /// <para>Ignores any excess bytes.
        /// See P1363.1 section 9.2.2.</para>
        /// </summary>
        /// 
        /// <param name="Data">Data an encoded ternary polynomial</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="SkipFirst">Whether to leave the constant coefficient zero and start populating at the linear coefficient</param>
        /// 
        /// <returns>The decoded coefficients</returns>
        public static int[] DecodeMod3Sves(byte[] Data, int N, bool SkipFirst)
        {
            int[] coeffs = new int[N];
            int coeffIndex = SkipFirst ? 1 : 0;
            int i = 0;

            while (i < Data.Length / 3 * 3 && coeffIndex < N - 1)
            {
                // process 24 bits at a time in the outer loop
                int chunk = (Data[i++] & 0xFF) | ((Data[i++] & 0xFF) << 8) | ((Data[i++] & 0xFF) << 16);
                for (int j = 0; j < 8 && coeffIndex < N - 1; j++)
                {
                    // process 3 bits at a time in the inner loop
                    int coeffTableIndex = ((chunk & 1) << 2) + (chunk & 2) + ((chunk & 4) >> 2);   // low 3 bits in reverse order
                    coeffs[coeffIndex++] = COEFF1_TABLE[coeffTableIndex];
                    coeffs[coeffIndex++] = COEFF2_TABLE[coeffTableIndex];
                    chunk >>= 3;
                }
            }

            return coeffs;
        }

        /// <summary>
        /// Converts a byte array produced by EncodeMod3Tight(int[]) back to an <c>int</c> array
        /// </summary>
        /// 
        /// <param name="Data">The byte array</param>
        /// <param name="N">The number of coefficients</param>
        /// 
        /// <returns>The decoded array</returns>
        public static int[] DecodeMod3Tight(byte[] Data, int N)
        {
            BigInteger sum = new BigInteger(1, Data);
            int[] coeffs = new int[N];

            for (int i = 0; i < N; i++)
            {
                coeffs[i] = sum.Mod(THREE).ToInt32() - 1;
                if (coeffs[i] > 1)
                    coeffs[i] -= 3;
                sum = sum.Divide(THREE);
            }

            return coeffs;
        }

        /// <summary>
        /// Converts data produced by EncodeMod3Tight(int[]) back to an <c>int</c> array
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream containing the data to decode</param>
        /// <param name="N">The number of coefficients</param>
        /// 
        /// <returns>The decoded array</returns>
        public static int[] DecodeMod3Tight(MemoryStream InputStream, int N)
        {
            int size = (int)Math.Ceiling(N * Math.Log(3) / Math.Log(2) / 8);
            byte[] arr = ArrayEncoder.ReadFullLength(InputStream, size);

            return DecodeMod3Tight(arr, N);
        }

        /// <summary>
        /// Decodes a <c>byte</c> array encoded with EncodeModQ(int[], int)} back to an <c>int</c> array.
        /// <para><c>N</c> is the number of coefficients. <c>Q</c> must be a power of <c>2</c>.
        /// Ignores any excess bytes.</para>
        /// </summary>
        /// 
        /// <param name="Data">Data an encoded ternary polynomial</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Q">The modulus</param>
        /// 
        /// <returns>Returns an array containing <c>N</c> coefficients between <c>0</c> and <c>q-1</c></returns>
        public static int[] DecodeModQ(byte[] Data, int N, int Q)
        {
            int[] coeffs = new int[N];
            int bitsPerCoeff = 31 - IntUtils.NumberOfLeadingZeros(Q);
            int mask = IntUtils.URShift(-1, (32 - bitsPerCoeff));   // for truncating values to bitsPerCoeff bits
            int byteIndex = 0;
            int bitIndex = 0;       // next bit in data[byteIndex]
            int coeffBuf = 0;       // contains (bitIndex) bits
            int coeffBits = 0;      // length of coeffBuf
            int coeffIndex = 0;     // index into coeffs

            while (coeffIndex < N)
            {
                // copy bitsPerCoeff or more into coeffBuf
                while (coeffBits < bitsPerCoeff)
                {
                    coeffBuf += (Data[byteIndex] & 0xFF) << coeffBits;
                    coeffBits += 8 - bitIndex;
                    byteIndex++;
                    bitIndex = 0;
                }

                // low bitsPerCoeff bits = next coefficient
                coeffs[coeffIndex] = coeffBuf & mask;
                coeffIndex++;
                coeffBuf = IntUtils.URShift(coeffBuf, bitsPerCoeff);
                coeffBits -= bitsPerCoeff;
            }

            return coeffs;
        }

        /// <summary>
        /// Decodes data encoded with encodeModQ(int[], int) back to an <c>int</c> array.
        /// <para><c>N</c> is the number of coefficients. <c>q</c> must be a power of <c>2</c>.
        /// Ignores any excess bytes.</para>
        /// </summary>
        /// 
        /// <param name="InputStream">An encoded ternary polynomial</param>
        /// <param name="N">The number of coefficients</param>
        /// <param name="Q">The modulus</param>
        /// 
        /// <returns>The decoded polynomial</returns>
        public static int[] DecodeModQ(Stream InputStream, int N, int Q)
        {
            int qBits = 31 - IntUtils.NumberOfLeadingZeros(Q);
            int size = (N * qBits + 7) / 8;
            byte[] arr = ArrayEncoder.ReadFullLength(InputStream, size);

            return DecodeModQ(arr, N, Q);
        }

        /// <summary>
        /// Encodes an <c>int</c> array whose elements are between <c>-1</c> and <c>1</c>, to a byte array.
        /// <para><c>coeffs[2*i]</c> and <c>coeffs[2*i+1]</c> must not both equal -1 for any integer <c>i</c>,
        /// so this method is only safe to use with arrays produced by {@link #decodeMod3Sves(byte[], int, boolean)}.
        /// See P1363.1 section 9.2.3.</para>
        /// </summary>
        /// 
        /// <param name="Data">The input array</param>
        /// <param name="SkipFirst">Whether to skip the constant coefficient</param>
        /// 
        /// <returns>The encoded array</returns>
        public static byte[] EncodeMod3Sves(int[] Data, bool SkipFirst)
        {
            int numBits = (Data.Length * 3 + 1) / 2;
            int numBytes = (numBits + 7) / 8;
            byte[] data = new byte[numBytes];
            int byteIndex = 0;
            int start = SkipFirst ? 1 : 0;
            int end = SkipFirst ? (Data.Length - 1) | 1 : Data.Length / 2 * 2;   // if there is an odd number of coeffs, throw away the highest one
            int i = start;

            while (i < end)
            {
                // process 24 bits at a time in the outer loop
                int chunk = 0;
                // number of bits in the chunk
                int chunkBits = 0;

                while (chunkBits < 24 && i < end)
                {
                    int coeff1 = Data[i++] + 1;
                    int coeff2 = Data[i++] + 1;

                    if (coeff1 == 0 && coeff2 == 0)
                        throw new CryptoAsymmetricException("ArrayEncoder:EncodeMod3Sves", "Illegal encoding!", new InvalidDataException());

                    int bitTableIndex = coeff1 * 3 + coeff2;
                    chunk |= BIT1_TABLE[bitTableIndex] << chunkBits++;
                    chunk |= BIT2_TABLE[bitTableIndex] << chunkBits++;
                    chunk |= BIT3_TABLE[bitTableIndex] << chunkBits++;
                }

                data[byteIndex++] = (byte)(chunk & 0xFF);

                if (byteIndex < data.Length)
                    data[byteIndex++] = (byte)((chunk >> 8) & 0xFF);
                if (byteIndex < data.Length)
                    data[byteIndex++] = (byte)((chunk >> 16) & 0xFF);
            }

            return data;
        }

        /// <summary>
        /// Encodes an <c>int</c> array whose elements are between <c>-1</c> and <c>1</c>, to a byte array
        /// </summary>
        /// 
        /// <param name="Data">The input array</param>
        /// 
        /// <returns>he encoded array</returns>
        public static byte[] EncodeMod3Tight(int[] Data)
        {
            BigInteger sum = BigInteger.Zero;

            for (int i = Data.Length - 1; i >= 0; i--)
            {
                sum = sum.Multiply(THREE);
                sum = sum.Add(BigInteger.ValueOf(Data[i] + 1));
            }

            int size = (THREE.Pow(Data.Length).BitLength + 7) / 8;
            byte[] arr = sum.ToByteArray();

            if (arr.Length < size)
            {
                // pad with leading zeros so arr.Length==size
                byte[] arr2 = new byte[size];
                Array.Copy(arr, 0, arr2, size - arr.Length, arr.Length);
                return arr2;
            }

            if (arr.Length > size)
                // drop sign bit
                arr = arr.CopyOfRange(1, arr.Length);

            return arr;
        }

        /// <summary>
        /// Encodes an int array whose elements are between 0 and <c>Q</c>, to a byte array leaving no gaps between bits.
        /// <para><c>Q</c> must be a power of 2.</para>
        /// </summary>
        /// 
        /// <param name="A">The input array</param>
        /// <param name="Q">The modulus</param>
        /// 
        /// <returns>The encoded array</returns>
        public static byte[] EncodeModQ(int[] A, int Q)
        {
            int bitsPerCoeff = 31 - IntUtils.NumberOfLeadingZeros(Q);
            int numBits = A.Length * bitsPerCoeff;
            int numBytes = (numBits + 7) / 8;
            byte[] data = new byte[numBytes];
            int bitIndex = 0;
            int byteIndex = 0;

            for (int i = 0; i < A.Length; i++)
            {
                for (int j = 0; j < bitsPerCoeff; j++)
                {
                    int currentBit = (A[i] >> j) & 1;
                    data[byteIndex] |= (byte)(currentBit << bitIndex);

                    if (bitIndex == 7)
                    {
                        bitIndex = 0;
                        byteIndex++;
                    }
                    else
                    {
                        bitIndex++;
                    }
                }
            }

            return data;
        }

        /// <summary>
        /// Like EncodeModQ(int[], int) but only returns the first <c>NumBytes</c> bytes of the encoding
        /// </summary>
        /// 
        /// <param name="Data">The input array</param>
        /// <param name="Q">The modulus</param>
        /// <param name="NumBytes">The encoded array</param>
        /// 
        /// <returns>Returns T</returns>
        public static byte[] EncodeModQTrunc(int[] Data, int Q, int NumBytes)
        {
            int bitsPerCoeff = 31 - IntUtils.NumberOfLeadingZeros(Q);
            byte[] data = new byte[NumBytes];
            int bitIndex = 0;
            int byteIndex = 0;

            for (int i = 0; i < Data.Length; i++)
            {
                for (int j = 0; j < bitsPerCoeff; j++)
                {
                    int currentBit = (Data[i] >> j) & 1;
                    data[byteIndex] |= (byte)(currentBit << bitIndex);

                    if (bitIndex == 7)
                    {
                        bitIndex = 0;
                        byteIndex++;

                        if (byteIndex >= NumBytes)
                            return data;
                    }
                    else
                    {
                        bitIndex++;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Reads a given number of bytes from an <c>InputStream</c>.
        /// <para>If there are not enough bytes in the stream, an <c>IOException</c> is thrown.</para>
        /// </summary>
        /// 
        /// <param name="InputStream">The input stream containing the data to read</param>
        /// <param name="Length">The length of the input stream </param>
        /// 
        /// <returns>An array of length <c>Length</c></returns>
        public static byte[] ReadFullLength(Stream InputStream, int Length)
        {
            byte[] arr = new byte[Length];

            if (InputStream.Read(arr, 0, arr.Length) != arr.Length)
                throw new IOException("Not enough bytes to read.");

            return arr;
        }

        /// <summary>
        /// Convert an integer value to a two byte array
        /// </summary>
        /// 
        /// <param name="Value">The integer to convert</param>
        /// 
        /// <returns>The byte array value</returns>
        public static byte[] ToByteArray(int Value)
        {
            byte[] arr = new byte[2];

            arr[0] = (byte)(IntUtils.URShift(Value, 8));
            arr[1] = (byte)(Value & 0xFF);

            return arr;
        }
        #endregion
    }
}