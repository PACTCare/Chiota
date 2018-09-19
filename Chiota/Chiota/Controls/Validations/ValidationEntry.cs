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
            this.entry = new Entry { Style = (Style)Application.Current.Resources["Entry16"] };
            this.entry.TextChanged += this.TextChanged;
            this.frame = new Frame
            {
                Style = (Style)Application.Current.Resources["RoundedFrame8"],
                WidthRequest = 256,
                BackgroundColor = (Color)Application.Current.Resources["EntryColor"],
                Content = this.entry
            };
            this.frame.Margin = new Thickness(0, 0, 32, 0);

            this.image = new Image() { WidthRequest = 24, HeightRequest = 24, IsVisible = false };

            this.Children.Add(this.frame);
            this.Children.Add(this.image);
            this.Spacing = 8;
            this.Orientation = StackOrientation.Horizontal;
            this.HorizontalOptions = LayoutOptions.Center;
            this.VerticalOptions = LayoutOptions.Center;
        }

        public bool IsPassword
        {
            get => (bool)this.GetValue(IsPasswordProperty);
            set => this.SetValue(IsPasswordProperty, value);
        }

        public bool IsValid
        {
            get => (bool)this.GetValue(IsValidProperty);
            set => this.SetValue(IsValidProperty, value);
        }

        public string Placeholder
        {
            get => (string)this.GetValue(PlaceholderProperty);
            set => this.SetValue(PlaceholderProperty, value);
        }

        public string Text
        {
            get => (string)this.GetValue(TextProperty);
            set => this.SetValue(TextProperty, value);
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
            this.entry.IsPassword = isPassword;
        }

        private void OnPlaceholderChanged(string placeholder)
        {
            this.entry.Placeholder = placeholder;
        }

        private void OnTextChanged(string text)
        {
            this.entry.Text = text;
        }

        private void TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!string.IsNullOrEmpty(this.entry.Text))
            {
                var result = this.Validate(this.entry.Text);
                this.UpdateValidationImage(result, true);
            }
            else
            {
                this.UpdateValidationImage(false);
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
                this.frame.Margin = new Thickness(0);
            else
                this.frame.Margin = new Thickness(0, 0, 32, 0);

            this.image.Source = valid ? "done.png" : "clear.png";
            this.image.IsVisible = visible;
        }
    }
}