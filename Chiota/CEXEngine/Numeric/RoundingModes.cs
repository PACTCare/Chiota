namespace VTDev.Libraries.CEXEngine.Numeric 
{
    /// <summary>
    /// MathContext RoundingModes used by BigInteger and BigDecimal
    /// </summary>
    public enum RoundingModes
    {
        /// <summary>
        /// Rounding mode where positive values are rounded towards positive infinity
        /// and negative values towards negative infinity.
        /// <para>Rule: <c>x.Round().Abs() >= x.Abs()</c></para>
        /// </summary>
        Up = 0,
        /// <summary>
        /// Rounding mode where the values are rounded towards zero.
        /// <para>Rule: x.Round().Abs() &lt;= x.Abs()</para>
        /// </summary>
        Down = 1,
        /// <summary>
        /// Rounding mode to round towards positive infinity.
        /// <para>For positive values this rounding mode behaves as Up, for negative values as Down.
        /// Rule: x.Round() >= x</para>
        /// </summary>
        Ceiling = 2,
        /// <summary>
        /// Rounding mode to round towards negative infinity.
        /// <para>For positive values this rounding mode behaves as Down, for negative values as Up.
        /// Rule: x.Round() &lt;= x</para>
        /// </summary>
        Floor = 3,
        /// <summary>
        /// Rounding mode where values are rounded towards the nearest neighbor.
        /// <para>Ties are broken by rounding up.</para>
        /// </summary>
        HalfUp = 4,
        /// <summary>
        /// Rounding mode where values are rounded towards the nearest neighbor.
        /// <para>Ties are broken by rounding down.</para>
        /// </summary>
        HalfDown = 5,
        /// <summary>
        /// Rounding mode where values are rounded towards the nearest neighbor.
        /// <para>Ties are broken by rounding to the even neighbor.</para>
        /// </summary>
        HalfEven = 6,
        /// <summary>
        /// Rounding mode where the rounding operations throws an ArithmeticException for 
        /// the case that rounding is necessary, i.e. for the case that the value cannot be represented exactly.
        /// </summary>
        Unnecessary = 7
    }
}