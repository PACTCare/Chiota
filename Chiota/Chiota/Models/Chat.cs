using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
{
    public class Chat : BaseModel
    {
        #region Properties

        public string Name { get; set; }

        public string LastMessage { get; set; }

        public string LastMessageTime { get; set; }

        public ImageSource ImageSource { get; set; }

        public ICommand TapCommand { get; set; }

        #endregion
    }
}
