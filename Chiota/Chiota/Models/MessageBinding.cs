using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
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

        public MessageBinding(string value, bool isOwner, bool isVisible) : this(value, isOwner, isVisible, DateTime.Now)
        {
        }

        #endregion
    }
}
