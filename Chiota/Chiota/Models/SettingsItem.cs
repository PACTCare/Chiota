using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
{
    public class SettingsItem : BaseModel
    {
        #region Properties

        public string Name { get; set; }

        public ImageSource Icon { get; set; }

        public ICommand TapCommand { get; set; }

        #endregion
    }
}
