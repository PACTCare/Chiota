#region Directives
using System;
using System.IO;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using System.Threading.Tasks;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// Array type extensions
    /// </summary>
    public static class ArrayEx
    {
        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Index">The insertion point within the source array</param>
        /// <param name="Value">The new value</param>
        /// 
        /// <returns>Resized array</returns>
        public static T[] AddAt<T>(this int[] Source, int Index, T Value = default(T))
        {
            T[] copy = new T[Source.Length + 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            copy[Index] = Value;

            if (Index < copy.Length - 1)
                Array.Copy(Source, Index, copy, Index + 1, Source.Length - Index);

            return copy;
        }

        /// <summary>
        /// Add a new value member to an array
        /// </summary>
        /// 
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="Source">The source array to be expanded</param>
        /// <param name="Data">The new value members</param>
        /// <param name="Index">The insertion point within the source array</param>
        /// 
        /// <returns>Resized array</returns>
        public static T[] AddRange<T>(this T[] Source, T[] Data, int Index)
        {
            T[] copy = new T[Source.Length + Data.Length];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);

            Array.Copy(Data, 0, copy, Index, Data.Length);

            if (Index < Source.Length - 1)
                Array.Copy(Source, Index, copy, Index + Data.Length, Source.Length - Index);

            return copy;
        }

        /// <summary>
        /// Convert a byte array to a class objct
        /// </summary>
        /// 
        /// <typeparam name="T">Return object type</typeparam>
        /// <param name="Data">The byte array containing the class</param>
        /// 
        /// <returns>The class object</returns>
        public static T Deserialize<T>(this byte[] Data) where T : class
        {
            if (Data == null)
                return null;

            using (var memStream = new MemoryStream())
            {
                var format = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                memStream.Write(Data, 0, Data.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                var obj = (T)format.Deserialize(memStream);
                return obj;
            }
        }

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
        /// Remove an element from the array
        /// </summary>
        /// 
        /// <typeparam name="T">The type of array</typeparam>
        /// <param name="Source">The source array</param>
        /// <param name="Index">The index of the element to remove</param>
        /// 
        /// <returns>Resized array</returns>
        public static T[] RemoveAt<T>(this T[] Source, int Index)
        {
            T[] copy = new T[Source.Length - 1];

            if (Index > 0)
                Array.Copy(Source, 0, copy, 0, Index);
            if (Index < Source.Length - 1)
                Array.Copy(Source, Index + 1, copy, Index, Source.Length - Index - 1);

            return copy;
        }

        /// <summary>
        /// Remove an element from the array
        /// </summary>
        /// 
        /// <param name="Source">The source array</param>
        /// <param name="From">First element to remove</param>
        /// <param name="To">Last element to remove</param>
        /// 
        /// /// <returns>Resized array</returns>
        public static T[] RemoveRange<T>(this T[] Source, int From, int To)
        {
            long len = Source.Length - To - From - 1;
            T[] copy = new T[len];

            if (From > 0)
                Array.Copy(Source, 0, copy, 0, From);
            if (To < Source.Length - 1)
                Array.Copy(Source, To + 1, copy, From, Source.Length - To - 1);

            return copy;
        }

        /// <summary>
        /// Serialize an object to a byte array
        /// </summary>
        /// 
        /// <param name="Obj">The object to serialize</param>
        /// 
        /// <returns>The object as a serialized byte array</returns>
        public static byte[] Serialize(this object Obj)
        {
            if (Obj == null)
                return null;

            var format = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                format.Serialize(ms, Obj);
                return ms.ToArray();
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
                if (ParallelUtils.IsParallel)
                {
                    Parallel.For(0, Source.Length, i =>
                    {
                        int index = rnd.NextInt32(0, Source.Length - 1);
                        T temp = Source[i];
                        Source[i] = Source[index];
                        lock (temp)
                            Source[index] = temp;
                    });
                }
                else
                {
                    for (int i = 0; i < Source.Length; i++)
                    {
                        int index = rnd.NextInt32(0, Source.Length - 1);
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
            for (int i = 0; i < Source.Length; i++)
            {
                int index = Rng.Next(0, Source.Length - 1);
                T temp = Source[i];
                Source[i] = Source[index];
                Source[index] = temp;
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
    }
}
