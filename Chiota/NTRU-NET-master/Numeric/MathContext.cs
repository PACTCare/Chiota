#region Directives
using System;
using System.Text;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace VTDev.Libraries.CEXEngine.Numeric 
{
    /// <summary>
	/// Immutable objects describing settings such as rounding mode and digit precision for the numerical operations 
	/// provided by class <see cref="BigDecimal"/>.
	/// </summary>
    [Serializable]
    public sealed class MathContext
    {
        #region Private Fields
        private static readonly char[] _chPrecision = { 'p', 'r', 'e', 'c', 'i', 's', 'i', 'o', 'n', '=' };
        private static readonly char[] _chRoundingMode = { 'r', 'o', 'u', 'n', 'd', 'i', 'n', 'g', 'M', 'o', 'd', 'e', '=' };
        private readonly int _precision;
        private readonly RoundingModes _roundingMode;
        #endregion

        #region Public Fields
        /// <summary>
        /// A MathContext which corresponds to the IEEE 754r quadruple decimal precision format: 34 digit precision and RoundingMode.HalfEven rounding
        /// </summary>
        public static readonly MathContext Decimal128 = new MathContext(34, RoundingModes.HalfEven);

        /// <summary>
        /// A MathContext which corresponds to the IEEE 754r single decimal precision format: 7 digit precision and RoundingMode.HalfEven rounding
        /// </summary>
        public static readonly MathContext Decimal32 = new MathContext(7, RoundingModes.HalfEven);

        /// <summary>
        /// A MathContext which corresponds to the IEEE 754r double decimal precision format: 16 digit precision and RoundingMode.HalfEven rounding
        /// </summary>
        public static readonly MathContext Decimal64 = new MathContext(16, RoundingModes.HalfEven);

        /// <summary>
        /// A MathContext for unlimited precision with RoundingMode.HalfUp rounding
        /// </summary>
        public static readonly MathContext Unlimited = new MathContext(0, RoundingModes.HalfUp);
        #endregion

        #region Properties
        /// <summary>
        /// Returns the precision.
        /// <para>The precision is the number of digits used for an operation.</para>
        /// </summary>
        /// 
        /// <remarks>
        /// <para>Results are rounded to this precision.
        /// The precision is guaranteed to be non negative.
        /// If the precision is zero, then the computations have to be performed exact,
        /// results are not rounded in this case.</para></remarks>
        public int Precision
        {
            get { return _precision; }
        }

        /// <summary>
        /// Returns the rounding mode.
        /// <para>The rounding mode is the strategy to be used to round results.</para>
        /// </summary>
        public RoundingModes RoundingMode
        {
            get { return _roundingMode; }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Constructs a new MathContext with the specified precision and with the rounding mode RoundingMode.HalfUp.
        /// <para>If the precision passed is zero, then this implies that the computations have to be performed exact, the rounding mode in this case is irrelevant.</para>
        /// </summary>
        /// 
        /// <param name="Precision">The precision for the new MathContext</param>
        public MathContext(int Precision)
            : this(Precision, RoundingModes.HalfUp)
        {
        }

        /// <summary>
        /// Constructs a new MathContext with the specified precision and with the specified rounding mode.
        /// <para>If the precision passed is zero, then this implies that the computations have to be performed exact, the rounding mode in this case is irrelevant.</para>
        /// </summary>
        /// 
        /// <param name="Precision">The precision for the new MathContext</param>
        /// <param name="RoundingMode">The rounding mode for the new MathContext</param>
        /// 
        /// <exception cref="ArgumentException">Thrown if the Precision is less than zero</exception>
        public MathContext(int Precision, RoundingModes RoundingMode)
        {
            if (Precision < 0)
                throw new ArgumentException("Digits < 0!");

            this._precision = Precision;
            this._roundingMode = RoundingMode;
        }

        /// <summary>
        /// Constructs a new MathContext from a string.
        /// <para>The string has to specify the precision and the rounding mode to be used and has to follow the following syntax:
        /// "Precision=&lt;Precision&gt; RoundingMode=&lt;RoundingMode&gt;"
        /// This is the same form as the one returned by the ToString method.</para>
        /// </summary>
        /// 
        /// <param name="Value">A string describing the precision and rounding mode for the new MathContext</param>
        /// 
        /// <exception cref="ArgumentException">Thrown if the string is not in the correct format or if the Precision specified is &lt; 0</exception>
        public MathContext(String Value)
        {
            char[] charVal = Value.ToCharArray();
            int i; // Index of charVal
            int j; // Index of chRoundingMode
            int digit; // It will contain the digit parsed

            if ((charVal.Length < 27) || (charVal.Length > 45))
                throw new ArgumentException("Bad string format!");
            
            // Parsing "precision=" String
            for (i = 0; (i < _chPrecision.Length) && (charVal[i] == _chPrecision[i]); i++)
            {
                ;
            }

            if (i < _chPrecision.Length)
                throw new ArgumentException("bad string format!");
            
            // Parsing the value for "precision="...
            digit = CharUtils.ToDigit(charVal[i], 10);

            if (digit == -1)
                throw new ArgumentException("bad string format!");
            
            this._precision = this._precision * 10 + digit;
            i++;

            do
            {
                digit = CharUtils.ToDigit(charVal[i], 10);
                if (digit == -1)
                {
                    if (charVal[i] == ' ')
                    {
                        // It parsed all the digits
                        i++;
                        break;
                    }
                    // It isn't  a valid digit, and isn't a white space
                    throw new ArgumentException("Bad string format!");
                }
                // Accumulating the value parsed
                this._precision = this._precision * 10 + digit;

                if (this._precision < 0)
                    throw new ArgumentException("Bad string format!");
                
                i++;
            } while (true);
            // Parsing "roundingMode="
            for (j = 0; (j < _chRoundingMode.Length) && (charVal[i] == _chRoundingMode[j]); i++, j++)
            {
                ;
            }

            if (j < _chRoundingMode.Length)
                throw new ArgumentException("Bad string format!");
            // Parsing the value for "roundingMode"...
            this._roundingMode = (RoundingModes)Enum.Parse(typeof(RoundingModes), new string(charVal, i, charVal.Length - i), true);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Returns true if Obj is a MathContext with the same precision setting and the same rounding mode as this MathContext instance.
        /// </summary>
        /// 
        /// <param name="Obj">bject to be compared</param>
        /// 
        /// <returns>Returns true if this MathContext instance is equal to the Obj argument, false otherwise</returns>
        public override bool Equals(Object Obj)
        {
            return ((Obj is MathContext) &&
                    (((MathContext)Obj).Precision == _precision) &&
                    (((MathContext)Obj).RoundingMode == _roundingMode));
        }

        /// <summary>
        /// Returns the hash code for this MathContext instance
        /// </summary>
        /// 
        /// <returns>Returns the hash code for this MathContext</returns>
        public override int GetHashCode()
        {
            // Make place for the necessary bits to represent 8 rounding modes
            return ((_precision << 3) | (int)_roundingMode);
        }

        /// <summary>
        /// Returns the string representation for this MathContext instance
        /// <para>The string has the form "Precision=&lt;Precision&gt; RoundingMode=&lt;RoundingMode&gt;" 
        /// where &lt;Precision&gt; is an integer describing the number of digits used for operations and
        /// &lt;RoundingMode&gt; is the string representation of the rounding mode.</para>
        /// </summary>
        /// 
        /// <returns>Returns a string representation for this MathContext instance</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder(45);

            sb.Append(_chPrecision);
            sb.Append(_precision);
            sb.Append(' ');
            sb.Append(_chRoundingMode);
            sb.Append(_roundingMode);

            return sb.ToString();
        }
        #endregion
    }
}