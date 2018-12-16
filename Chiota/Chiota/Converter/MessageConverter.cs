#region References

using System;
using System.Globalization;
using Chiota.Services.Localization;
using Xamarin.Forms;

#endregion

namespace Chiota.Converter
{
    #region MessageIsOwnerToColorConverter

    public class MessageIsOwnerToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!(value is bool))
                return null;

            if ((bool)value)
                return Color.FromHex("#80d8ff");

            return Color.FromHex("#e0e0e0");
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion

    #region MessageIsOwnerToLayoutOptionConverter

    public class MessageIsOwnerToLayoutOptionConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!(value is bool))
                return null;

            if ((bool)value)
                return LayoutOptions.EndAndExpand;

            return LayoutOptions.StartAndExpand;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion

    #region MessageDateTimeToDateStringConverter

    public class MessageDateTimeToDateStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value as DateTime?)?.ToString("d", Multilingual.Current.CurrentCultureInfo);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion

    #region MessageDateTimeToTimeStringConverter

    public class MessageDateTimeToTimeStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value as DateTime?)?.ToString("t", Multilingual.Current.CurrentCultureInfo);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    #endregion
}
