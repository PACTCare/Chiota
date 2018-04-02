#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Numeric
{
    /// <summary>
    /// Char helper class
    /// </summary>
    internal static class CharUtils
    {
        #region Constants
        internal const int MIN_RADIX = 2;
        internal const int MAX_RADIX = 36;
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
        internal static char CharAt(string Value, int Index)
        {
            char[] ca = Value.ToCharArray();
            return ca[Index];
        }

        /// <summary>
        /// Get the char representation of an iteger
        /// </summary>
        /// 
        /// <param name="Digit">The digit to convert</param>
        /// <param name="Radix">The radix</param>
        /// 
        /// <returns>New char value</returns>
        internal static char ForDigit(int Digit, int Radix)
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
        /// Convert a char to an integer
        /// </summary>
        /// 
        /// <param name="Value">Char to convert</param>
        /// 
        /// <returns>Integer representation</returns>
        internal static int ToDigit(char Value)
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
        internal static int ToDigit(char Value, int Radix)
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
        internal static int ToDigit(string Value)
        {
            char[] ch = Value.ToCharArray();
            return (int)Char.GetNumericValue(ch[0]);
        }
        #endregion
    }
}