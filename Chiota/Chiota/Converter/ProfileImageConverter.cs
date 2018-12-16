#region References

using System;
using System.Globalization;
using Xamarin.Forms;

#endregion

namespace Chiota.Converter
{
    #region ProfileImageSourceConverter

    public class ProfileImageSourceConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!(value is ImageSource))
                return ImageSource.FromFile("account.png");

            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion

    #region ProfileImageSourceOpacityConverter

    public class ProfileImageSourceOpacityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!(value is ImageSource))
                return 0.6;

            return 1.0;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion
}
