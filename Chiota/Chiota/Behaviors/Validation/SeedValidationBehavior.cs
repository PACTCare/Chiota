using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows.Input;
using Tangle.Net.Utils;
using Xamarin.Forms;

namespace Chiota.Behaviors.Validation
{
    public class SeedValidationBehavior : ValidationBehavior
    {
        #region Methods

        protected override bool Validate(string text)
        {
            if (!string.IsNullOrEmpty(text) && InputValidator.IsTrytes(text) && text.Length == 81)
                return true;

            return false;
        }

        #endregion
    }
}
