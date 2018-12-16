#region References

using System;
using Chiota.Models.Database.Base;

#endregion

namespace Chiota.Models.Binding
{
    public class MessageBinding : BaseModel
    {
        #region Properties

        public string Value { get; }

        public DateTime DateTime { get; }

        public bool IsOwner { get; }

        #endregion

        #region Constructors

        public MessageBinding(string value, bool isOwner, DateTime dateTime)
        {
            Value = value;
            IsOwner = isOwner;
            DateTime = dateTime;
        }

        #endregion
    }
}
