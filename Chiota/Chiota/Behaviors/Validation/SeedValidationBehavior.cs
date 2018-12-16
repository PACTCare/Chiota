#region References

using Tangle.Net.Utils;

#endregion

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
