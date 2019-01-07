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

        public DateTime Date { get; }

        public int Status { get; } 
            
        public bool IsOwner { get; }

        public bool IsDateVisible { get; set; }

        #endregion

        #region Constructors

        public MessageBinding(string value, DateTime date, MessageStatus status, bool isOwner, bool isDateVisible = false)
        {
            Value = value;
            Date = date;
            Status = (int) status;
            IsOwner = isOwner;
            IsDateVisible = isDateVisible;
        }

        #endregion
    }
}
