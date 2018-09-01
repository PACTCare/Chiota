using System;
using System.Collections.ObjectModel;
using Xamarin.Forms;

namespace Chiota.Controls.Validations
{
    public abstract class ValidationEntry : StackLayout
    {
        #region Attributes

        protected Frame _frame;
        protected Entry _entry;
        protected Image _image;

        #endregion

        #region Properties

        #region IsValid

        /// <summary>
        /// Get or set, if the status for the validation.
        /// </summary>
        public bool IsValid
        {
            get => (bool)GetValue(IsValidProperty);
            set => SetValue(IsValidProperty, value);
        }

        /// <summary>
        /// IsValid property of the elment.
        /// </summary>
        public static readonly BindableProperty IsValidProperty = BindableProperty.Create(
            nameof(IsValid), typeof(bool), typeof(bool), false);

        #endregion

        #region Text

        /// <summary>
        /// Get or set, if the status for the validation.
        /// </summary>
        public string Text
        {
            get => (string)GetValue(TextProperty);
            set => SetValue(TextProperty, value);
        }

        /// <summary>
        /// IsValid property of the elment.
        /// </summary>
        public static readonly BindableProperty TextProperty = BindableProperty.Create(
            nameof(Text), typeof(string), typeof(string), "", propertyChanged: OnTextChanged);

        private static void OnTextChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnTextChanged(newvalue as string);
        }

        #endregion

        #region Placeholder

        /// <summary>
        /// Get or set, if the status for the validation.
        /// </summary>
        public string Placeholder
        {
            get => (string)GetValue(PlaceholderProperty);
            set => SetValue(PlaceholderProperty, value);
        }

        /// <summary>
        /// IsValid property of the elment.
        /// </summary>
        public static readonly BindableProperty PlaceholderProperty = BindableProperty.Create(
            nameof(Placeholder), typeof(string), typeof(string), "", propertyChanged: OnPlaceholderChanged);

        private static void OnPlaceholderChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnPlaceholderChanged(newvalue as string);
        }

        #endregion

        #region IsPassword

        /// <summary>
        /// Get or set, if the status for the validation.
        /// </summary>
        public bool IsPassword
        {
            get => (bool)GetValue(IsPasswordProperty);
            set => SetValue(IsPasswordProperty, value);
        }

        /// <summary>
        /// IsValid property of the elment.
        /// </summary>
        public static readonly BindableProperty IsPasswordProperty = BindableProperty.Create(
            nameof(IsPassword), typeof(bool), typeof(bool), false, propertyChanged: OnIsPasswordChanged);

        private static void OnIsPasswordChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnIsPasswordChanged((bool) newvalue);
        }

        #endregion

        #endregion

        #region Constructors

        protected ValidationEntry()
        {
            _entry = new Entry()
            {
                Style = (Style)Application.Current.Resources["Entry16"]
            };
            _entry.TextChanged += TextChanged;
            _frame = new Frame()
            {
                Style = (Style)Application.Current.Resources["RoundedFrame8"],
                WidthRequest = 256,
                BackgroundColor = (Color)Application.Current.Resources["EntryColor"],
                Content = _entry
            };

            _image = new Image()
            {
                WidthRequest = 24,
                HeightRequest = 24,
                IsVisible = false
            };

            this.Children.Add(_frame);
            this.Children.Add(_image);
            this.Spacing = 8;
            this.Orientation = StackOrientation.Horizontal;
            this.HorizontalOptions = LayoutOptions.Center;
            this.VerticalOptions = LayoutOptions.Center;
        }

        #endregion

        #region Methods

        #region Validate

        protected abstract bool Validate(string text);

        #endregion

        #region TextChanged

        private void TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_entry.Text))
            {
                var result = Validate(_entry.Text);
                UpdateValidationImage(result, true);
            }
            else
                UpdateValidationImage(false);
        }

        #endregion

        #region UpdateImage

        private void UpdateValidationImage(bool valid, bool visible = false)
        {
            if (valid)
                _image.Source = "done.png";
            else
                _image.Source = "clear.png";

            _image.IsVisible = visible;
        }

        #endregion

        #region OnTextChanged

        private void OnTextChanged(string text)
        {
            _entry.Text = text;
        }

        #endregion

        #region OnPlaceholderChanged

        private void OnPlaceholderChanged(string placeholder)
        {
            _entry.Placeholder = placeholder;
        }

        #endregion

        #region OnIsPasswordChanged

        private void OnIsPasswordChanged(bool isPassword)
        {
            _entry.IsPassword = isPassword;
        }

        #endregion

        #endregion
    }
}
