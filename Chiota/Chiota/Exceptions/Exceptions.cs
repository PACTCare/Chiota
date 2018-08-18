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

        [JsonProperty("detail")]
        public string Detail { get; }

        #endregion

        #region Constructors

        protected BaseException(ExcInfo excInfo, int errorCode, string title, string message, string detail) : base(message)
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
        #region MyRegion

        public UnknownException(ExcInfo excInfo) : base(excInfo, ErrorCodes.Unknown, Titles.Unknown, Messages.Unknown, Details.Unknown)
        {
        }

        #endregion

        public class InvalidArgumentException : BaseException
        {
            #region Attributes

            private string[] _detail = {"Invalid argument ", " expected."};

            #endregion

            #region MyRegion

            public InvalidArgumentException(ExcInfo excInfo, int errorCode, string title, string message, string detail) : base(excInfo, errorCode, title, message, detail)
            {
            }

            #endregion
        }
    }


    #endregion

    #region Authentication exceptions



    #endregion
}
