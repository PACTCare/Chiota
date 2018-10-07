using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Tangle.Net.Utils;
using Xamarin.Forms;

namespace Chiota.Behaviors.Validation
{
    public abstract class ValidationBehavior : Behavior<Entry>
    {
        #region Properties

        public ICommand Command
        {
            get => (ICommand)GetValue(CommandProperty);
            set => SetValue(CommandProperty, value);
        }

        public static readonly BindableProperty CommandProperty =
            BindableProperty.Create(nameof(Command), typeof(ICommand), typeof(ValidationBehavior));

        #endregion

        #region OnAttachedTo

        protected override void OnAttachedTo(Entry bindable)
        {
            base.OnAttachedTo(bindable);
            bindable.BindingContextChanged += BindableContextChanged;
            bindable.TextChanged += BindableTextChanged;
        }

        #endregion

        #region OnDetachingFrom

        protected override void OnDetachingFrom(Entry bindable)
        {
            base.OnDetachingFrom(bindable);
            bindable.BindingContextChanged -= BindableContextChanged;
            bindable.TextChanged -= BindableTextChanged;
        }

        #endregion

        #region Events

        private void BindableContextChanged(object sender, EventArgs e)
        {
            var bindable = sender as Entry;
            BindingContext = bindable?.BindingContext;
        }

        private void BindableTextChanged(object sender, TextChangedEventArgs e)
        {
            var result = Validate(e.NewTextValue);

            //Execute the command.
            Command.Execute(result);
        }

        #endregion

        #region Methods

        protected abstract bool Validate(string text);

        #endregion
    }
}
