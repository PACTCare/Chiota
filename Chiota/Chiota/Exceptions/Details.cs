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
        public static string AuthMissingSeed = "Please generate a new seed until the next step.";
        public static string AuthInvalidUserInputPassword = "Invalid user input of the argument 'password' expected.";
        public static string AuthMissingUserInputName = "Missing user input of the argument 'name' expected.";
        public static string AuthMissingUserInputPasswordRepeat = "Missing user input of the argument 'password' or 'repeat password' expected.";

        #endregion

        #region Back up exceptions

        public static string BackUpFailedSeedConfirmation = "Please verify if you have insert the correct seed and try it again.";
        public static string BackUpInvalidUserInputSeed = "Invalid user input of the argument 'seed' expected.";

        #endregion

        #region Contact

        public static string ContactMissingContactAddress = "Missing user input of the argument 'contact address' expected.";
        public static string ContactInvalidUserInputContactAddress = "Invalid user input of the argument 'contact address' expected.";

        #endregion
    }
}
