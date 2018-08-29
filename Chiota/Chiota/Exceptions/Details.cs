using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Exceptions
{
    public static class Details
    {
        #region Base exceptions

        public static string Unknown = "Please restart the app and try it again, or contact our support.";
        public static string InvalidUserInput = "Invalid user input was expected.";
        public static string MissingUserInput = "Missing user input was expected.";
        public static string FailedLoadingFile = "You can only load images to use them as profile image.";

        #endregion

        #region Authentication exceptions

        public static string AuthFailedPasswordConfirmation = "Please verify if you have insert the correct password and try it again.";

        #endregion

        #region Back up exceptions

        public const string BackUpFailedSeedConfirmation = "Please verify if you have insert the correct seed and try it again.";

        #endregion
    }
}
