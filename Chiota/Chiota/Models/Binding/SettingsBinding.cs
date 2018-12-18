﻿#region References

using Xamarin.Forms;

#endregion

namespace Chiota.Models.Binding
{
    public enum SettingsItemType
    {
        Profile,
        Security,
        InviteFriends,
        About
    }

    public class SettingsBinding
    {
        #region Properties

        public SettingsItemType Type { get; }

        public string Name { get; }

        public ImageSource Icon { get; }

        #endregion

        #region Constructors

        public SettingsBinding(SettingsItemType type, string name, ImageSource imageSource)
        {
            Type = type;
            Name = name;
            Icon = imageSource;
        }

        #endregion
    }
}
