using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using Newtonsoft.Json;

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
            this.FilePath = filePath;
            this.MethodName = methodName;
            this.LineNumber = lineNumber;
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

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("detail")]
        public string Detail { get; set; }

        #endregion

        #region Constructors

        protected BaseException(ExcInfo excInfo, int errorCode, string title, string description, string detail = "")
        {
            ExcInfo = excInfo;
            ErrorCode = errorCode;
            Title = title;
            Description = description;
            Detail = detail;
        }

        #endregion
    }

    #region Base exceptions

    public class UnknownException : BaseException
    {
        #region Constructors

        public UnknownException(ExcInfo excInfo) : base(excInfo, ErrorCodes.Unknown, Titles.Unknown, Descriptions.Unknown, Details.Unknown)
        {
        }

        #endregion
    }

    public class InvalidUserInputException : BaseException
    {
        #region Attributes

        private readonly string[] _detail = { "Invalid user input of the argument", "expected." };

        #endregion

        #region Constructors

        public InvalidUserInputException(ExcInfo excInfo, string argument) : base(excInfo, ErrorCodes.InvalidUserInput, Titles.InvalidUserInput, Descriptions.InvalidUserInput)
        {
            Detail = _detail[0] + " " + argument + " " + _detail[1];
        }

        #endregion
    }

    public class MissingUserInputException : BaseException
    {
        #region Attributes

        private readonly string[] _detail = { "Missing user input of the argument", "expected." };

        #endregion

        #region Constructors

        public MissingUserInputException(ExcInfo excInfo, string argument) : base(excInfo, ErrorCodes.MissingUserInput, Titles.MissingUserInput, Descriptions.MissingUserInput)
        {
            Detail = _detail[0] + " " + argument + " " + _detail[1];
        }

        #endregion
    }

    #endregion

    #region Authentication exceptions

    public class AuthFailedPasswordConfirmationException : BaseException
    {
        #region Constructors

        public AuthFailedPasswordConfirmationException(ExcInfo excInfo) : base(excInfo, ErrorCodes.AuthFailedPasswordConfirmation, Titles.AuthFailedPasswordConfirmation, Descriptions.AuthFailedPasswordConfirmation, Details.AuthFailedPasswordConfirmation)
        {
        }

        #endregion
    }

    #endregion

    #region Back up exceptions

    public class BackUpFailedSeedConfirmationException : BaseException
    {
        #region Constructors

        public BackUpFailedSeedConfirmationException(ExcInfo excInfo) : base(excInfo, ErrorCodes.BackUpFailedSeedConfirmation, Titles.BackUpFailedSeedConfirmation, Descriptions.BackUpFailedSeedConfirmation, Details.BackUpFailedSeedConfirmation)
        {
        }

        #endregion
    }

    #endregion
}
