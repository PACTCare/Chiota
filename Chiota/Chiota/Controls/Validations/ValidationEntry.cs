namespace Chiota.Controls.Validations
{
    using Xamarin.Forms;

    /// <summary>
    /// The validation entry.
    /// </summary>
    public abstract class ValidationEntry : StackLayout
    {
        public static readonly BindableProperty IsValidProperty = BindableProperty.Create(nameof(IsValid), typeof(bool), typeof(bool), false);

        public static readonly BindableProperty TextProperty = BindableProperty.Create(
          nameof(Text),
          typeof(string),
          typeof(string),
          string.Empty,
          propertyChanged: OnTextChanged);

        public static readonly BindableProperty PlaceholderProperty = BindableProperty.Create(
          nameof(Placeholder),
          typeof(string),
          typeof(string),
          string.Empty,
          propertyChanged: OnPlaceholderChanged);

        public static readonly BindableProperty IsPasswordProperty = BindableProperty.Create(
          nameof(IsPassword),
          typeof(bool),
          typeof(bool),
          false,
          propertyChanged: OnIsPasswordChanged);

        protected Entry entry;

        protected Frame frame;

        protected Image image;

        /// <summary>
        /// Initializes a new instance of the <see cref="ValidationEntry"/> class.
        /// </summary>
        protected ValidationEntry()
        {
            entry = new Entry { Style = (Style)Application.Current.Resources["Entry16"] };
            entry.TextChanged += TextChanged;
            frame = new Frame
            {
                Style = (Style)Application.Current.Resources["RoundedFrame8"],
                WidthRequest = 256,
                BackgroundColor = (Color)Application.Current.Resources["EntryColor"],
                Content = entry
            };
            frame.Margin = new Thickness(0, 0, 32, 0);

            image = new Image() { WidthRequest = 24, HeightRequest = 24, IsVisible = false };

            Children.Add(frame);
            Children.Add(image);
            Spacing = 8;
            Orientation = StackOrientation.Horizontal;
            HorizontalOptions = LayoutOptions.Center;
            VerticalOptions = LayoutOptions.Center;
        }

        public bool IsPassword
        {
            get => (bool)GetValue(IsPasswordProperty);
            set => SetValue(IsPasswordProperty, value);
        }

        public bool IsValid
        {
            get => (bool)GetValue(IsValidProperty);
            set => SetValue(IsValidProperty, value);
        }

        public string Placeholder
        {
            get => (string)GetValue(PlaceholderProperty);
            set => SetValue(PlaceholderProperty, value);
        }

        public string Text
        {
            get => (string)GetValue(TextProperty);
            set => SetValue(TextProperty, value);
        }

        protected abstract bool Validate(string text);

        private static void OnIsPasswordChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnIsPasswordChanged((bool)newvalue);
        }

        private static void OnPlaceholderChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnPlaceholderChanged(newvalue as string);
        }

        private static void OnTextChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var entry = bindable as ValidationEntry;
            entry?.OnTextChanged(newvalue as string);
        }

        private void OnIsPasswordChanged(bool isPassword)
        {
            entry.IsPassword = isPassword;
        }

        private void OnPlaceholderChanged(string placeholder)
        {
            entry.Placeholder = placeholder;
        }

        private void OnTextChanged(string text)
        {
            entry.Text = text;
        }

        private void TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!string.IsNullOrEmpty(entry.Text))
            {
                var result = Validate(entry.Text);
                UpdateValidationImage(result, true);
            }
            else
            {
                UpdateValidationImage(false);
            }
        }

        /// <summary>
        /// The update validation image.
        /// </summary>
        /// <param name="valid">
        /// The valid.
        /// </param>
        /// <param name="visible">
        /// The visible.
        /// </param>
        private void UpdateValidationImage(bool valid, bool visible = false)
        {
            if (visible)
                frame.Margin = new Thickness(0);
            else
                frame.Margin = new Thickness(0, 0, 32, 0);

            image.Source = valid ? "done.png" : "clear.png";
            image.IsVisible = visible;
        }
    }
}