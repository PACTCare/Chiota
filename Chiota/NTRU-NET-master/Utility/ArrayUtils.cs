#region Directives
using System;
using System.IO;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// Extended array methods
    /// </summary>
    public static class ArrayUtils
    {
        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Value">The new value</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddAt(ref byte[] Source, byte Value, int Index)
        {
            byte[] copy = new byte[Source.Length + 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            copy[Index] = Value;

            if (Index < copy.Length - 1)
                Array.Copy(Source, Index, copy, Index + 1, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Value">The new value</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddAt(ref int[] Source, int Value, int Index)
        {
            int[] copy = new int[Source.Length + 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            copy[Index] = Value;

            if (Index < copy.Length - 1)
                Array.Copy(Source, Index, copy, Index + 1, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Value">The new value</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddAt(ref long[] Source, long Value, int Index)
        {
            long[] copy = new long[Source.Length + 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            copy[Index] = Value;

            if (Index < copy.Length - 1)
                Array.Copy(Source, Index, copy, Index + 1, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Data">The new value members</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddRange(ref byte[] Source, byte[] Data, int Index)
        {
            byte[] copy = new byte[Source.Length + Data.Length];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);

            Array.Copy(Data, 0, copy, Index, Data.Length);

            if (Index < Source.Length - 1)
                Array.Copy(Source, Index, copy, Index + Data.Length, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Data">The new value members</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddRange(ref int[] Source, int[] Data, int Index)
        {
            int[] copy = new int[Source.Length + Data.Length];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);

            Array.Copy(Data, 0, copy, Index, Data.Length);

            if (Index < Source.Length - 1)
                Array.Copy(Source, Index, copy, Index + Data.Length, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Data">The new value members</param>
        /// <param name="Index">The insertion point within the source array</param>
        public static void AddRange(ref long[] Source, long[] Data, int Index)
        {
            long[] copy = new long[Source.Length + Data.Length];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);

            Array.Copy(Data, 0, copy, Index, Data.Length);

            if (Index < Source.Length - 1)
                Array.Copy(Source, Index, copy, Index + Data.Length, Source.Length - Index);

            Source = copy;
        }

        /// <summary>
        /// Create a deep copy of a byte array
        /// </summary>
        /// <param name="A">The array to copy</param>
        /// 
        /// <returns>Returns the array copy</returns>
        internal static byte[] Clone(byte[] A)
        {
            byte[] result = new byte[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Create a deep copy of a Int16 array
        /// </summary>
        /// <param name="A">The array to copy</param>
        /// 
        /// <returns>Returns the array copy</returns>
        internal static short[] Clone(short[] A)
        {
            short[] result = new short[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Create a deep copy of a Int32 array
        /// </summary>
        /// <param name="A">The array to copy</param>
        /// 
        /// <returns>Returns the array copy</returns>
        internal static int[] Clone(int[] A)
        {
            int[] result = new int[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Create a deep copy of a Int64 array
        /// </summary>
        /// <param name="A">The array to copy</param>
        /// 
        /// <returns>Returns the array copy</returns>
        internal static long[] Clone(long[] A)
        {
            long[] result = new long[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

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
        public static uint[] Concat(params uint[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            uint[] rv = new uint[len];
            int offset = 0;

            foreach (uint[] array in Arrays)
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
        public static ulong[] Concat(params ulong[][] Arrays)
        {
            int len = 0;
            for (int i = 0; i < Arrays.Length; i++)
                len += Arrays[i].Length;

            ulong[] rv = new ulong[len];
            int offset = 0;

            foreach (ulong[] array in Arrays)
            {
                Array.Copy(array, 0, rv, offset, array.Length);
                offset += array.Length;
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
        /// <returns>The initialized array</returns>
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
        /// Remove an element from the array
        /// </summary>
        /// 
        /// <param name="Source">The source array</param>
        /// <param name="Index">The index of the element to remove</param>
        public static void RemoveAt(ref byte[] Source, int Index)
        {
            byte[] copy = new byte[Source.Length - 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            if (Index < Source.Length - 1)
                Array.Copy(Source, Index + 1, copy, Index, Source.Length - Index - 1);

            Source = copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// 
        /// <param name="Source">The source array</param>
        /// <param name="Index">The index of the element to remove</param>
        public static void RemoveAt(ref int[] Source, int Index)
        {
            int[] copy = new int[Source.Length - 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            if (Index < Source.Length - 1)
                Array.Copy(Source, Index + 1, copy, Index, Source.Length - Index - 1);

            Source = copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// 
        /// <param name="Source">The source array</param>
        /// <param name="Index">The index of the element to remove</param>
        public static void RemoveAt(ref long[] Source, int Index)
        {
            long[] copy = new long[Source.Length - 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            if (Index < Source.Length - 1)
                Array.Copy(Source, Index + 1, copy, Index, Source.Length - Index - 1);

            Source = copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// <param name="Source">The source array</param>
        /// <param name="From">First element to remove</param>
        /// <param name="To">Last element to remove</param>
        public static void RemoveRange(ref byte[] Source, int From, int To)
        {
            int len = Source.Length - To - From - 1;
            byte[] copy = new byte[len];

            if (From > 0)
                Array.Copy(Source, 0, copy, 0, From);
            if (To < Source.Length - 1)
                Array.Copy(Source, To + 1, copy, From, Source.Length - To - 1);

            Source = copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// <param name="Source">The source array</param>
        /// <param name="From">First element to remove</param>
        /// <param name="To">Last element to remove</param>
        public static void RemoveRange(ref int[] Source, int From, int To)
        {
            int len = Source.Length - To - From - 1;
            int[] copy = new int[len];

            if (From > 0)
                Array.Copy(Source, 0, copy, 0, From);
            if (To < Source.Length - 1)
                Array.Copy(Source, To + 1, copy, From, Source.Length - To - 1);

            Source = copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// <param name="Source">The source array</param>
        /// <param name="From">First element to remove</param>
        /// <param name="To">Last element to remove</param>
        public static void RemoveRange(ref long[] Source, long From, long To)
        {
            long len = Source.Length - To - From - 1;
            long[] copy = new long[len];

            if (From > 0)
                Array.Copy(Source, 0, copy, 0, From);
            if (To < Source.Length - 1)
                Array.Copy(Source, To + 1, copy, From, Source.Length - To - 1);

            Source = copy;
        }

        /// <summary>
        /// Split an array
        /// </summary>
        /// 
        /// <param name="Data">The array to be split</param>
        /// <param name="Index">The starting position of the second array</param>
        /// 
        /// <returns>A jagged array containing the split array</returns>
        [CLSCompliant(false)]
        public static byte[][] Split(byte[] Data, int Index)
        {
            byte[] rd1 = new byte[Index];
            byte[] rd2 = new byte[Data.Length - Index];
            Array.Copy(Data, 0, rd1, 0, rd1.Length);
            Array.Copy(Data, Index, rd2, 0, rd2.Length);

            return new byte[][] { rd1, rd2 };
        }

        /// <summary>
        /// Split an array
        /// </summary>
        /// 
        /// <param name="Data">The array to be split</param>
        /// <param name="Index">The starting position of the second array</param>
        /// 
        /// <returns>A jagged array containing the split array</returns>
        [CLSCompliant(false)]
        public static int[][] Split(int[] Data, int Index)
        {
            int[] rd1 = new int[Index];
            int[] rd2 = new int[Data.Length - Index];
            Array.Copy(Data, 0, rd1, 0, rd1.Length);
            Array.Copy(Data, Index, rd2, 0, rd2.Length);

            return new int[][] { rd1, rd2 };
        }

        /// <summary>
        /// Split an array
        /// </summary>
        /// 
        /// <param name="Data">The array to be split</param>
        /// <param name="Index">The starting position of the second array</param>
        /// 
        /// <returns>A jagged array containing the split array</returns>
        [CLSCompliant(false)]
        public static uint[][] Split(uint[] Data, int Index)
        {
            uint[] rd1 = new uint[Index];
            uint[] rd2 = new uint[Data.Length - Index];
            Array.Copy(Data, 0, rd1, 0, rd1.Length);
            Array.Copy(Data, Index, rd2, 0, rd2.Length);

            return new uint[][] { rd1, rd2 };
        }

        /// <summary>
        /// Split an array
        /// </summary>
        /// 
        /// <param name="Data">The array to be split</param>
        /// <param name="Index">The starting position of the second array</param>
        /// 
        /// <returns>A jagged array containing the split array</returns>
        [CLSCompliant(false)]
        public static long[][] Split(long[] Data, int Index)
        {
            long[] rd1 = new long[Index];
            long[] rd2 = new long[Data.Length - Index];
            Array.Copy(Data, 0, rd1, 0, rd1.Length);
            Array.Copy(Data, Index, rd2, 0, rd2.Length);

            return new long[][] { rd1, rd2 };
        }

        /// <summary>
        /// Split an array
        /// </summary>
        /// 
        /// <param name="Data">The array to be split</param>
        /// <param name="Index">The starting position of the second array</param>
        /// 
        /// <returns>A jagged array containing the split array</returns>
        [CLSCompliant(false)]
        public static ulong[][] Split(ulong[] Data, int Index)
        {
            ulong[] rd1 = new ulong[Index];
            ulong[] rd2 = new ulong[Data.Length - Index];
            Array.Copy(Data, 0, rd1, 0, rd1.Length);
            Array.Copy(Data, Index, rd2, 0, rd2.Length);

            return new ulong[][] { rd1, rd2 };
        }

        /// <summary>
        /// Copy a byte array to a short array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to short</returns>
        [CLSCompliant(false)]
        public static short[] ToArray16(byte[] Data)
        {
            short[] rd = new short[Data.Length / 2];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a byte array to a ushort array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to ushort</returns>
        [CLSCompliant(false)]
        public static ushort[] ToUArray16(byte[] Data)
        {
            ushort[] rd = new ushort[Data.Length / 2];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a byte array to a int array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to int</returns>
        [CLSCompliant(false)]
        public static int[] ToArray32(byte[] Data)
        {
            int[] rd = new int[Data.Length / 4];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a byte array to a uint array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to uint</returns>
        [CLSCompliant(false)]
        public static uint[] ToUArray32(byte[] Data)
        {
            uint[] rd = new uint[Data.Length / 4];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a byte array to a long array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to long</returns>
        [CLSCompliant(false)]
        public static long[] ToArray64(byte[] Data)
        {
            long[] rd = new long[Data.Length / 8];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a byte array to a ulong array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Byte array converted to ulong</returns>
        [CLSCompliant(false)]
        public static ulong[] ToUArray64(byte[] Data)
        {
            ulong[] rd = new ulong[Data.Length / 8];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a sbyte array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Sbyte array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(sbyte[] Data)
        {
            byte[] rd = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, rd, 0, Data.Length);
            return rd;
        }

        /// <summary>
        /// Copy a int array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Int array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(short[] Data)
        {
            byte[] rd = new byte[Data.Length * 2];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
        }

        /// <summary>
        /// Copy a int array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Int array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(ushort[] Data)
        {
            byte[] rd = new byte[Data.Length * 2];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
        }

        /// <summary>
        /// Copy a int array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Int array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(int[] Data)
        {
            byte[] rd = new byte[Data.Length * 4];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
        }

        /// <summary>
        /// Copy a uint array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Uint array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(uint[] Data)
        {
            byte[] rd = new byte[Data.Length * 4];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
        }

        /// <summary>
        /// Copy a long array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Long array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(long[] Data)
        {
            byte[] rd = new byte[Data.Length * 8];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
        }

        /// <summary>
        /// Copy a long array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>Long array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(ulong[] Data)
        {
            byte[] rd = new byte[Data.Length * 8];
            Buffer.BlockCopy(Data, 0, rd, 0, rd.Length);
            return rd;
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

        /// <summary>
        /// Copy a 2 dimensional jagged byte array to a one dimensional byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional byte jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(byte[][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            if (Data.Length == 0)
                return null;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                nd = new byte[Data[i].Length];
                Buffer.BlockCopy(Data[i], 0, nd, 0, nd.Length);
                writer.Write(nd);
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 3 dimensional jagged byte array to a one dimensional byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional byte jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(byte[][][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);
            writer.Write(Data[0][0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                for (int j = 0; j < Data[i].Length; j++)
                {
                    nd = new byte[Data[i][j].Length];
                    Buffer.BlockCopy(Data[i][j], 0, nd, 0, nd.Length);
                    writer.Write(nd);
                }
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 2 dimensional Int16 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int16 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(short[][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                nd = new byte[Data[i].Length * 2];
                Buffer.BlockCopy(Data[i], 0, nd, 0, nd.Length);
                writer.Write(nd);
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 2 dimensional Int32 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int32 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(int[][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                nd = new byte[Data[i].Length * 4];
                Buffer.BlockCopy(Data[i], 0, nd, 0, nd.Length);
                writer.Write(nd);
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 2 dimensional Int64 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int64 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(long[][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                nd = new byte[Data[i].Length * 8];
                Buffer.BlockCopy(Data[i], 0, nd, 0, nd.Length);
                writer.Write(nd);
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 3 dimensional Int16 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int16 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(short[][][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);
            writer.Write(Data[0][0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                for (int j = 0; j < Data[i].Length; j++)
                {
                    nd = new byte[Data[i][j].Length * 2];
                    Buffer.BlockCopy(Data[i][j], 0, nd, 0, nd.Length);
                    writer.Write(nd);
                }
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 3 dimensional Int32 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int16 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(int[][][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);
            writer.Write(Data[0][0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                for (int j = 0; j < Data[i].Length; j++)
                {
                    nd = new byte[Data[i][j].Length * 4];
                    Buffer.BlockCopy(Data[i][j], 0, nd, 0, nd.Length);
                    writer.Write(nd);
                }
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Copy a 3 dimensional Int64 jagged array to a byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int64 jagged array converted to bytes</returns>
        [CLSCompliant(false)]
        public static byte[] ToBytes(long[][][] Data)
        {
            BinaryWriter writer = new BinaryWriter(new MemoryStream());
            byte[] nd;

            // write the lengths
            writer.Write(Data.Length);
            writer.Write(Data[0].Length);
            writer.Write(Data[0][0].Length);

            // write the data
            for (int i = 0; i < Data.Length; i++)
            {
                for (int j = 0; j < Data[i].Length; j++)
                {
                    nd = new byte[Data[i][j].Length * 8];
                    Buffer.BlockCopy(Data[i][j], 0, nd, 0, nd.Length);
                    writer.Write(nd);
                }
            }

            return ((MemoryStream)writer.BaseStream).ToArray();
        }

        /// <summary>
        /// Convert a byte array to a 2 dimensional jagged byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional byte jagged array</returns>
        [CLSCompliant(false)]
        public static byte[][] ToArray2x8(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[2];
            byte[] db;
            byte[][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();

            // init array
            ra = CreateJagged<byte[][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                db = new byte[ra[i].Length];
                db = reader.ReadBytes(db.Length);
                Buffer.BlockCopy(db, 0, ra[i], 0, db.Length);
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 2 dimensional Int16 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int16 jagged array</returns>
        [CLSCompliant(false)]
        public static short[][] ToArray2x16(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[2];
            byte[] db;
            short[][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();

            // init array
            ra = CreateJagged<short[][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                db = new byte[ra[i].Length * 2];
                db = reader.ReadBytes(db.Length);
                Buffer.BlockCopy(db, 0, ra[i], 0, db.Length);
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 2 dimensional Int32 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int32 jagged array</returns>
        [CLSCompliant(false)]
        public static int[][] ToArray2x32(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[2];
            byte[] db;
            int[][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();

            // init array
            ra = CreateJagged<int[][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                db = new byte[ra[i].Length * 4];
                db = reader.ReadBytes(db.Length);
                Buffer.BlockCopy(db, 0, ra[i], 0, db.Length);
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 2 dimensional Int64 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>2 dimensional Int64 jagged array</returns>
        [CLSCompliant(false)]
        public static long[][] ToArray2x64(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[2];
            byte[] db;
            long[][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();

            // init array
            ra = CreateJagged<long[][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                db = new byte[ra[i].Length * 8];
                db = reader.ReadBytes(db.Length);
                Buffer.BlockCopy(db, 0, ra[i], 0, db.Length);
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 3 dimensional jagged byte array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional byte jagged array</returns>
        [CLSCompliant(false)]
        public static byte[][][] ToArray3x8(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[3];
            byte[] db;
            byte[][][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();
            alen[2] = reader.ReadInt32();

            // init array
            ra = CreateJagged<byte[][][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                for (int j = 0; j < alen[1]; j++)
                {
                    db = new byte[ra[i][j].Length];
                    db = reader.ReadBytes(db.Length);
                    Buffer.BlockCopy(db, 0, ra[i][j], 0, db.Length);
                }
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 3 dimensional Int16 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int16 jagged array</returns>
        [CLSCompliant(false)]
        public static short[][][] ToArray3x16(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[3];
            byte[] db;
            short[][][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();
            alen[2] = reader.ReadInt32();

            // init array
            ra = CreateJagged<short[][][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                for (int j = 0; j < alen[1]; j++)
                {
                    db = new byte[ra[i][j].Length * 2];
                    db = reader.ReadBytes(db.Length);
                    Buffer.BlockCopy(db, 0, ra[i][j], 0, db.Length);
                }
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 3 dimensional Int32 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int32 jagged array</returns>
        [CLSCompliant(false)]
        public static int[][][] ToArray3x32(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[3];
            byte[] db;
            int[][][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();
            alen[2] = reader.ReadInt32();

            // init array
            ra = CreateJagged<int[][][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                for (int j = 0; j < alen[1]; j++)
                {
                    db = new byte[ra[i][j].Length * 4];
                    db = reader.ReadBytes(db.Length);
                    Buffer.BlockCopy(db, 0, ra[i][j], 0, db.Length);
                }
            }

            return ra;
        }

        /// <summary>
        /// Convert a byte array to a 3 dimensional Int64 jagged array
        /// </summary>
        /// 
        /// <param name="Data">Array to convert</param>
        /// 
        /// <returns>3 dimensional Int64 jagged array</returns>
        [CLSCompliant(false)]
        public static long[][][] ToArray3x64(byte[] Data)
        {
            BinaryReader reader = new BinaryReader(new MemoryStream(Data));
            int[] alen = new int[3];
            byte[] db;
            long[][][] ra;

            // get the lengths
            alen[0] = reader.ReadInt32();
            alen[1] = reader.ReadInt32();
            alen[2] = reader.ReadInt32();

            // init array
            ra = CreateJagged<long[][][]>(alen);

            // get the data
            for (int i = 0; i < alen[0]; i++)
            {
                for (int j = 0; j < alen[1]; j++)
                {
                    db = new byte[ra[i][j].Length * 8];
                    db = reader.ReadBytes(db.Length);
                    Buffer.BlockCopy(db, 0, ra[i][j], 0, db.Length);
                }
            }

            return ra;
        }
    }
}
