#region References

using System;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

#endregion

namespace Chiota.Exceptions
{
    public class ExcInfo
    {
        #region Attributes

        [JsonProperty("filepath")]
        public string FilePath { get; }

        [JsonProperty("methodname")]
        public string MethodName { get; }

        [JsonProperty("linenumber")]
        public int LineNumber { get; }

        #endregion

        #region Constructors

        public ExcInfo([CallerFilePath] string filePath = "", [CallerMemberName] string methodName = "", [CallerLineNumber] int lineNumber = 0)
        {
            FilePath = filePath;
            MethodName = methodName;
            LineNumber = lineNumber;
        }

        #endregion
    }

    public abstract class BaseException : Exception
    {
        #region Properties

        [JsonProperty("excinfo")]
        public ExcInfo ExcInfo { get; }

        [JsonProperty("errorcode")]
        public int ErrorCode { get; }

        [JsonProperty("title")]
        public string Title { get; }

        [JsonProperty("detail")]
        public string Detail { get; set; }

        #endregion

        #region Constructors

        protected BaseException(ExcInfo excInfo, int errorCode, string title, string detail = "")
        {
            ExcInfo = excInfo;
            ErrorCode = errorCode;
            Title = title;
            Detail = detail;
        }

        #endregion
    }

    #region Base exceptions

    public class UnknownException : BaseException
    {
        #region Constructors

        public UnknownException(ExcInfo excInfo) : base(excInfo, ErrorCodes.Unknown, Titles.Unknown, Details.Unknown)
        {
        }

        #endregion
    }

    public class InvalidUserInputException : BaseException
    {
        #region Constructors

        public InvalidUserInputException(ExcInfo excInfo, string detail) : base(excInfo, ErrorCodes.InvalidUserInput, Titles.InvalidUserInput, Details.InvalidUserInput)
        {
            Detail = detail;
        }

        #endregion
    }

    public class MissingUserInputException : BaseException
    {
        /*#region Attributes

        private readonly string[] _detail = { "Missing user input of the argument", "expected." };

        #endregion*/

        #region Constructors

        public MissingUserInputException(ExcInfo excInfo, string detail) : base(excInfo, ErrorCodes.MissingUserInput, Titles.MissingUserInput, Details.MissingUserInput)
        {
            Detail = detail;
        }

        #endregion
    }

    public class FailedLoadingFileException : BaseException
    {
        #region Constructors

        public FailedLoadingFileException(ExcInfo excInfo) : base(excInfo, ErrorCodes.MissingUserInput, Titles.MissingUserInput, Details.MissingUserInput)
        {
        }

        #endregion
    }

    #endregion

    #region Authentication exceptions

    public class AuthFailedPasswordConfirmationException : BaseException
    {
        #region Constructors

        public AuthFailedPasswordConfirmationException(ExcInfo excInfo) : base(excInfo, ErrorCodes.AuthFailedPasswordConfirmation, Titles.AuthFailedPasswordConfirmation, Details.AuthFailedPasswordConfirmation)
        {
        }

        #endregion
    }

    public class AuthMissingSeedException : BaseException
    {
        #region Constructors

        public AuthMissingSeedException(ExcInfo excInfo) : base(excInfo, ErrorCodes.AuthMissingSeed, Titles.AuthMissingSeed, Details.AuthMissingSeed)
        {
        }

        #endregion
    }

    #endregion

    #region Back up exceptions

    public class BackUpFailedSeedConfirmationException : BaseException
    {
        #region Constructors

        public BackUpFailedSeedConfirmationException(ExcInfo excInfo) : base(excInfo, ErrorCodes.BackUpFailedSeedConfirmation, Titles.BackUpFailedSeedConfirmation, Details.BackUpFailedSeedConfirmation)
        {
        }

        #endregion
    }

    #endregion
}
