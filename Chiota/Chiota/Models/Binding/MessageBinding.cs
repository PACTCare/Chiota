#region References

using System;
using Chiota.Models.Database;
using Chiota.Models.Database.Base;

#endregion

namespace Chiota.Models.Binding
{
    public class MessageBinding : BaseModel
    {
        #region Properties

        public string Value { get; }

        public DateTime DateTime { get; }

        public int Status { get; } 
            
        public bool IsOwner { get; }

        #endregion

        #region Constructors

        public MessageBinding(string value, DateTime dateTime, MessageStatus status, bool isOwner)
        {
            Value = value;
            DateTime = dateTime;
            Status = (int) status;
            IsOwner = isOwner;
        }

        #endregion
    }
}
