#region Directives
using System;
using System.Collections.Generic;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Arithmetic;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS.Utility
{
    /// <summary>
    /// This class provides several methods that are required by the GMSS classes
    /// </summary>
    internal static class GMSSUtil
    {
        public static GMSSLeaf[] Clone(GMSSLeaf[] Data)
        {
            if (Data == null)
                return null;

            GMSSLeaf[] copy = new GMSSLeaf[Data.Length];
            Array.Copy(Data, 0, copy, 0, Data.Length);

            return copy;
        }

        public static GMSSRootCalc[] Clone(GMSSRootCalc[] Data)
        {
            if (Data == null)
                return null;

            GMSSRootCalc[] copy = new GMSSRootCalc[Data.Length];
            Array.Copy(Data, 0, copy, 0, Data.Length);

            return copy;
        }

        public static GMSSRootSig[] Clone(GMSSRootSig[] Data)
        {
            if (Data == null)
                return null;

            GMSSRootSig[] copy = new GMSSRootSig[Data.Length];
            Array.Copy(Data, 0, copy, 0, Data.Length);

            return copy;
        }

        public static byte[][] Clone(byte[][] Data)
        {
            if (Data == null)
                return null;

            byte[][] copy = new byte[Data.Length][];

            for (int i = 0; i != Data.Length; i++)
                copy[i] = ArrayUtils.Clone(Data[i]);

            return copy;
        }

        public static byte[][][] Clone(byte[][][] Data)
        {
            if (Data == null)
                return null;

            byte[][][] copy = new byte[Data.Length][][];

            for (int i = 0; i != Data.Length; i++)
                copy[i] = Clone(Data[i]);

            return copy;
        }

        public static Treehash[] Clone(Treehash[] Data)
        {
            if (Data == null)
                return null;

            Treehash[] copy = new Treehash[Data.Length];
            Array.Copy(Data, 0, copy, 0, Data.Length);

            return copy;
        }

        public static Treehash[][] Clone(Treehash[][] Data)
        {
            if (Data == null)
                return null;

            Treehash[][] copy = new Treehash[Data.Length][];

            for (int i = 0; i != Data.Length; i++)
                copy[i] = Clone(Data[i]);

            return copy;
        }

        public static List<byte[]>[] Clone(List<byte[]>[] Data)
        {
            if (Data == null)
                return null;

            List<byte[]>[] copy = new List<byte[]>[Data.Length];

            for (int i = 0; i != Data.Length; i++)
            {
                copy[i] = new List<byte[]>();
                for (int j = 0; j < Data[i].Count; j++)
                    copy[j].Add(Data[i][j]);
            }

            return copy;
        }

        public static List<byte[]>[][] Clone(List<byte[]>[][] data)
        {
            if (data == null)
                return null;

            List<byte[]>[][] copy = new List<byte[]>[data.Length][];

            for (int i = 0; i != data.Length; i++)
                copy[i] = Clone(data[i]);

            return copy;
        }

        /// <summary>
        /// Converts a 32 bit integer into a byte array beginning at <c>offset</c> (little-endian representation)
        /// </summary>
        /// 
        /// <param name="Value">The value the integer to convert</param>
        /// 
        /// <returns>Converted value</returns>
        public static byte[] IntToBytesLittleEndian(int Value)
        {
            byte[] bytes = new byte[4];

            bytes[0] = (byte)((Value) & 0xff);
            bytes[1] = (byte)((Value >> 8) & 0xff);
            bytes[2] = (byte)((Value >> 16) & 0xff);
            bytes[3] = (byte)((Value >> 24) & 0xff);

            return bytes;
        }

        /// <summary>
        /// Converts a byte array beginning at <c>offset</c> into a 32 bit integer (little-endian representation)
        /// </summary>
        /// 
        /// <param name="Bytes">The byte array</param>
        /// 
        /// <returns>The resulting integer</returns>
        public static int BytesToIntLittleEndian(byte[] Bytes)
        {

            return ((Bytes[0] & 0xff)) | ((Bytes[1] & 0xff) << 8)
                | ((Bytes[2] & 0xff) << 16) | ((Bytes[3] & 0xff)) << 24;
        }

        /// <summary>
        /// Converts a byte array beginning at <c>offset</c> into a 32 bit integer (little-endian representation)
        /// </summary>
        /// 
        /// <param name="Bytes">The byte array</param>
        /// <param name="Offset">The integer offset into the byte array</param>
        /// 
        /// <returns>The resulting integer</returns>
        public static int BytesToIntLittleEndian(byte[] Bytes, int Offset)
        {
            return ((Bytes[Offset++] & 0xff)) | ((Bytes[Offset++] & 0xff) << 8)
                | ((Bytes[Offset++] & 0xff) << 16)
                | ((Bytes[Offset] & 0xff)) << 24;
        }

        /// <summary>
        /// This method concatenates a 2-dimensional byte array into a 1-dimensional byte array
        /// </summary>
        /// 
        /// <param name="Arraycp">A 2-dimensional byte array.</param>
        /// 
        /// <returns>Returns 1-dimensional byte array with concatenated input array</returns>
        public static byte[] ConcatenateArray(byte[][] Arraycp)
        {
            byte[] dest = new byte[Arraycp.Length * Arraycp[0].Length];
            int indx = 0;
            for (int i = 0; i < Arraycp.Length; i++)
            {
                Array.Copy(Arraycp[i], 0, dest, indx, Arraycp[i].Length);
                indx = indx + Arraycp[i].Length;
            }
            return dest;
        }

        /// <summary>
        /// This method tests if an integer is a power of 2
        /// </summary>
        /// 
        /// <param name="Value">An integer</param>
        /// 
        /// <returns>Return <c>true</c> if <c>testValue</c> is a power of 2, <c>false</c> otherwise</returns>
        public static bool TestPowerOfTwo(int Value)
        {
            int a = 1;
            while (a < Value)
            {
                a <<= 1;
            }

            if (Value == a)
                return true;

            return false;
        }

        /// <summary>
        /// This method returns the least integer that is greater or equal to the logarithm to the base 2 of an integer <c>intValue</c>.
        /// </summary>
        /// 
        /// <param name="Value">an integer</param>
        /// 
        /// <returns>return The least integer greater or equal to the logarithm to the base 2 of <c>Value</c></returns>
        public static int GetLog(int Value)
        {
            int log = 1;
            int i = 2;
            while (i < Value)
            {
                i <<= 1;
                log++;
            }
            return log;
        }
    }
}
