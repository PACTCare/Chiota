using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Chiota.Controls.Validations
{
    public class SeedValidationEntry : ValidationEntry
    {
        #region Methods

        #region Validate

        protected override bool Validate(string text)
        {
            IsValid = false;
            if (string.IsNullOrEmpty(text))
                return false;

            // Return true if strIn is in valid email format.
            try
            {
                return Regex.IsMatch(text,
                    @"([A-Z,9]{81})",
                    RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        #endregion

        #endregion
    }
}
