#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for manipulating char arrays
    /// </summary>
    public static class CharUtils
    {
        #region Constants
        /// <summary>
        /// Min radix
        /// </summary>
        public const int MIN_RADIX = 2;

        /// <summary>
        /// Max radix
        /// </summary>
        public const int MAX_RADIX = 36;
        #endregion

        #region Methods
        /// <summary>
        /// Get the char value at a specified index within a string
        /// </summary>
        /// 
        /// <param name="Value">String to parse</param>
        /// <param name="Index">Index of value</param>
        /// 
        /// <returns>Char value</returns>
        public static char CharAt(string Value, int Index)
        {
            char[] ca = Value.ToCharArray();
            return ca[Index];
        }

        /// <summary>
        /// Return a clone of the given char array. No null checks are performed.
        /// </summary>
        /// 
        /// <param name="A">The array to clone</param>
        /// 
        /// <returns>The clone of the given array</returns>
        public static char[] Clone(char[] A)
        {
            char[] result = new char[A.Length];
            Array.Copy(A, 0, result, 0, A.Length);

            return result;
        }

        /// <summary>
        /// Compare two char arrays. No null checks are performed.
        /// </summary>
        /// 
        /// <param name="A">The char byte array</param>
        /// <param name="B">The second char array</param>
        /// 
        /// <returns>The result of the comparison</returns>
        public static bool Equals(char[] A, char[] B)
        {
            if (A.Length != B.Length)
                return false;

            for (int i = A.Length - 1; i >= 0; i--)
            {
                if (A[i] != B[i])
                    return false;
            }
            
            return true;
        }

        /// <summary>
        /// Get the char representation of an iteger
        /// </summary>
        /// 
        /// <param name="Digit">The digit to convert</param>
        /// <param name="Radix">The radix</param>
        /// 
        /// <returns>New char value</returns>
        public static char ForDigit(int Digit, int Radix)
        {
            if (Radix < MIN_RADIX || Radix > MAX_RADIX)
                throw new ArgumentOutOfRangeException("Bad Radix!");
            if (Digit < 0 || Digit >= Radix)
                throw new ArgumentOutOfRangeException("Bad Digit!");
            if (Digit < 10)
                return (char)(Digit + (int)'0');

            return (char)(Digit - 10 + (int)'a');
        }

        /// <summary>
        /// Convert the given char array into a byte array.
        /// </summary>
        /// 
        /// <param name="A">The char array</param>
        /// 
        /// <returns>The converted array</returns>
        public static byte[] ToByteArray(char[] A)
        {
            byte[] result = new byte[A.Length];
            for (int i = A.Length - 1; i >= 0; i--)
                result[i] = (byte)A[i];

            return result;
        }

        /// <summary>
        /// Convert the given char array into a byte array for use with PBE encryption
        /// </summary>
        /// 
        /// <param name="A">The char array</param>
        /// 
        /// <returns>The converted array</returns>
        public static byte[] ToByteArrayForPBE(char[] A)
        {

            byte[] bout = new byte[A.Length];

            for (int i = 0; i < A.Length; i++)
                bout[i] = (byte)A[i];

            int length = bout.Length * 2;
            byte[] ret = new byte[length + 2];
            int j = 0;

            for (int i = 0; i < bout.Length; i++)
            {
                j = i * 2;
                ret[j] = 0;
                ret[j + 1] = bout[i];
            }

            ret[length] = 0;
            ret[length + 1] = 0;

            return ret;
        }

        /// <summary>
        /// Convert a char to an integer
        /// </summary>
        /// 
        /// <param name="Value">Char to convert</param>
        /// 
        /// <returns>Integer representation</returns>
        public static int ToDigit(char Value)
        {
            return (int)Char.GetNumericValue(Value);
        }

        /// <summary>
        /// Convert a char to an integer
        /// </summary>
        /// 
        /// <param name="Value">Char to convert</param>
        /// <param name="Radix">The radix</param>
        /// 
        /// <returns>New integer value</returns>
        public static int ToDigit(char Value, int Radix)
        {
            if (Radix < MIN_RADIX || Radix > MAX_RADIX)
                return -1;

            int digit = -1;
            Value = Char.ToLowerInvariant(Value);

            if ((Value >= '0') && (Value <= '9'))
            {
                digit = ((int)Value - (int)'0');
            }
            else
            {
                if ((Value >= 'a') && (Value <= 'z'))
                    digit = ((int)Value - (int)'a') + 10;
            }

            return digit < Radix ? digit : -1;
        }

        /// <summary>
        /// Convert a string to an integer
        /// </summary>
        /// 
        /// <param name="Value">String to convert</param>
        /// 
        /// <returns>Integer representation</returns>
        public static int ToDigit(string Value)
        {
            char[] ch = Value.ToCharArray();
            return (int)Char.GetNumericValue(ch[0]);
        }
        #endregion
    }
}
