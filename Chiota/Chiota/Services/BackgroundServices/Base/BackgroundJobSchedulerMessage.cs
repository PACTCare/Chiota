#region References

using System;
using System.Collections.Generic;
using System.Text;

#endregion

namespace Chiota.Services.BackgroundServices.Base
{
    public class BackgroundJobSchedulerMessage
    {
        #region Properties

        public string Type { get; }

        public object[] Data { get; }

        #endregion

        #region Constructors

        public BackgroundJobSchedulerMessage(string type, params object[] data)
        {
            Type = type;
            Data = data;
        }

        #endregion
    }
}
