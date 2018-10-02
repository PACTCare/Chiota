using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models.Classes;
using Xamarin.Forms;

namespace Chiota.Models
{
    public enum SettingsItemType
    {
        Profile,
        InviteFriends,
        About
    }

    public class SettingsItem : BaseModel
    {
        #region Properties

        public SettingsItemType Type { get; }

        public string Name { get; }

        public ImageSource Icon { get; }

        #endregion

        #region Constructors

        public SettingsItem(SettingsItemType type, string name, ImageSource imageSource)
        {
            Type = type;
            Name = name;
            Icon = imageSource;
        }

        #endregion
    }
}
