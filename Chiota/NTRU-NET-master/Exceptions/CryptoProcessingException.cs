#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Exceptions
{
    /// <summary>
    /// Wraps exceptions thrown within a Processing operational context.
    /// <para>This exception is used throughout the CompressionCipher, PacketCipher, StreamCipher, StreamDigest, StreamMac, and VolumeCipher classes.</para>
    /// </summary>
    public sealed class CryptoProcessingException : Exception
    {
        /// <summary>
        /// The origin of the exception in the format Class:Method
        /// </summary>
        public string Origin { get; set; }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        public CryptoProcessingException(String Message) :
            base(Message)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoProcessingException(String Message, Exception InnerException) :
            base(Message, InnerException)
        {
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        public CryptoProcessingException(String Origin, String Message) :
            base(Message)
        {
            this.Origin = Origin;
        }

        /// <summary>
        /// Exception constructor
        /// </summary>
        /// 
        /// <param name="Origin">The origin of the exception</param>
        /// <param name="Message">A custom message or error data</param>
        /// <param name="InnerException">The underlying exception</param>
        public CryptoProcessingException(String Origin, String Message, Exception InnerException) :
            base(Message, InnerException)
        {
            this.Origin = Origin;
        }
    }
}
