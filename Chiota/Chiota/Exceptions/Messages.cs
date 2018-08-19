using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Exceptions
{
    public static class Messages
    {
        #region Base exceptions

        public static string Unknown = "Unknown exception was thrown.";
        public static string InvalidUserInput = "Invalid user input exception was thrown.";
        public static string MissingUserInput = "Missing user input exception was thrown.";

        #endregion

        #region Authentication exceptions

        public static string AuthFailedPasswordConfirmation = "Failed password confirmation exception was thrown.";

        #endregion
    }
}
