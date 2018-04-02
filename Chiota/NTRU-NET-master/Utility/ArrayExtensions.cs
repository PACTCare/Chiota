#region Directives
using System;
using System.Diagnostics;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// Array extension and static methods
    /// </summary>
    [DebuggerStepThrough]
    public static class ArrayExtensions
    {
        #region Static Methods
        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        public static byte[] Concat(params byte[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            byte[] rv = new byte[len];
            int offset = 0;
            foreach (byte[] array in Arrays)
            {
                Array.Copy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        [CLSCompliant(false)]
        public static int[] Concat(params int[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            int[] rv = new int[len];
            int offset = 0;

            foreach (int[] array in Arrays)
            {
                Array.Copy(array, 0, rv, offset, array.Length);
                offset += array.Length * 4;
            }
            return rv;
        }

        /// <summary>
        /// Concatenate 2 arrays
        /// </summary>
        /// 
        /// <param name="Arrays">Arrays to be joined</param>
        /// 
        /// <returns>Joined array</returns>
        [CLSCompliant(false)]
        public static long[] Concat(params long[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            long[] rv = new long[len];
            int offset = 0;

            foreach (long[] array in Arrays)
            {
                Array.Copy(array, 0, rv, offset, array.Length);
                offset += array.Length * 4;
            }
            return rv;
        }

        /// <summary>
        /// Create and initialize a jagged array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Lengths">The arrays lengths</param>
        /// 
        /// <returns>Initialized jagged array</returns>
        public static T CreateJagged<T>(params int[] Lengths)
        {
            return (T)InitializeJagged(typeof(T).GetElementType(), 0, Lengths);
        }

        /// <summary>
        /// Initialize a jagged array
        /// </summary>
        /// 
        /// <param name="Type">Type of array</param>
        /// <param name="Index">The first row index of the array outer array</param>
        /// <param name="Lengths">The arrays lengths</param>
        /// 
        /// <returns></returns>
        public static object InitializeJagged(Type Type, int Index, int[] Lengths)
        {
            Array arr = Array.CreateInstance(Type, Lengths[Index]);
            Type ele = Type.GetElementType();

            if (ele != null)
            {
                for (int i = 0; i < Lengths[Index]; i++)
                    arr.SetValue(InitializeJagged(ele, Index + 1, Lengths), i);
            }

            return arr;
        }

        /// <summary>
        /// Copy an sbyte array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Sbyte array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(sbyte[] Data)
        {
            byte[] data = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, data, 0, Data.Length);
            return data;
        }

        /// <summary>
        /// Copy a string to an ASCII byte array
        /// </summary>
        /// 
        /// <param name="Value">String to copy</param>
        /// 
        /// <returns>The byte array representation</returns>
        public static byte[] ToBytes(string Value)
        {
            return System.Text.Encoding.ASCII.GetBytes(Value);
        }

        #endregion

        #region Extensions
        /// <summary>
        /// Create a copy of an array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">Array source</param>
        /// <param name="Length">Number of elements to copy</param>
        /// 
        /// <returns>A copy of the source array</returns>
        public static T[] CopyOf<T>(this T[] Source, int Length)
        {
            T[] copy = new T[Length];
            Array.Copy(Source, copy, Math.Min(Source.Length, Length));

            return copy;
        }

        /// <summary>
        /// Create a ranged copy of a byte array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">Byte source array</param>
        /// <param name="From">First element to copy</param>
        /// <param name="To">Last element to copy</param>
        /// 
        /// <returns>Byte array copy</returns>
        public static T[] CopyOfRange<T>(this T[] Source, int From, int To)
        {
            int newLen = To - From;
            T[] copy = new T[newLen];

            if (newLen < 0)
                throw new Exception(From + " > " + To);

            Array.Copy(Source, From, copy, 0, Math.Min(Source.Length - From, newLen));

            return copy;
        }

        /// <summary>
        /// Fill an array with a value; defaults to zeroes
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">Array to fill</param>
        /// <param name="Value">Value used to fill array</param>
        public static void Fill<T>(this T[] Source, T Value = default(T))
        {
            for (int i = 0; i < Source.Length; i++)
                Source[i] = Value;
        }

        /// <summary>
        /// Fill an array with a value; defaults to zeroes
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">Array to fill</param>
        /// <param name="Value">Value used to fill array</param>
        public static void Fill<T>(this T[,] Source, T Value = default(T))
        {
            for (int x = 0; x < Source.GetLength(0); x++)
            {
                for (int y = 0; y < Source.GetLength(1); y++)
                    Source[x, y] = Value;
            }
        }

        /// <summary>
        /// Shuffle an array using the SecureRandom class
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">The list instance</param>
        public static void Shuffle<T>(this T[] Source)
        {
            using (SecureRandom rnd = new SecureRandom())
            {
                for (int i = 0; i < Source.Length - 1; i++)
                {
                    int index = (int)rnd.NextInt32(i, Source.Length - 1);

                    if (i != index)
                    {
                        T temp = Source[i];
                        Source[i] = Source[index];
                        Source[index] = temp;
                    }
                }
            }
        }

        /// <summary>
        /// Shuffle an array with a specific Prng class
        /// </summary>
        /// 
        /// <typeparam name="T">Type of list</typeparam>
        /// <param name="Source">The list instance</param>
        /// <param name="Rng">The pseudo random generator</param>
        public static void Shuffle<T>(this T[] Source, IRandom Rng)
        {
            for (int i = 0; i < Source.Length - 1; i++)
            {
                int index = (int)Rng.Next(i, Source.Length - 1);

                if (i != index)
                {
                    T temp = Source[i];
                    Source[i] = Source[index];
                    Source[index] = temp;
                }
            }
        }

        /// <summary>
        /// Return a sub array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">The source array</param>
        /// <param name="Index">The starting position within the source array</param>
        /// <param name="Count">The number of bytes to copy</param>
        /// 
        /// <returns>The sub array</returns>
        public static T[] SubArray<T>(this T[] Source, int Index, int Count)
        {
            T[] result = new T[Count];
            Array.Copy(Source, Index, result, 0, Count);

            return result;
        }
        #endregion
    }
}
