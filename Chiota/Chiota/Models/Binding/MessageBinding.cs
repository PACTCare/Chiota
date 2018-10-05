using System;
using Chiota.Models.Base;

namespace Chiota.Models.Binding
{
    public class MessageBinding : BaseModel
    {
        #region Properties

        public string Value { get; }

        public DateTime DateTime { get; }

        public bool IsOwner { get; }

        public bool IsVisible { get; }

        #endregion

        #region Constructors

        public MessageBinding(string value, bool isOwner, bool isVisible, DateTime dateTime)
        {
            Value = value;
            IsOwner = isOwner;
            IsVisible = isVisible;
            DateTime = dateTime;
        }

        public MessageBinding(string value, bool isOwner = true, bool isVisible = false) : this(value, isOwner, isVisible, DateTime.Now)
        {
        }

        #endregion
    }
}
