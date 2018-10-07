using System;
using System.Collections.Generic;
using System.Text;
using Xamarin.Forms;

namespace Chiota.Behaviors
{
    public class FocusBehavior : Behavior<InputView>
    {
        #region Attributes

        private InputView _inputView;

        #endregion

        #region Properties

        public bool IsFocused
        {
            get => (bool)GetValue(IsFocusedProperty);
            set => SetValue(IsFocusedProperty, value);
        }

        public static readonly BindableProperty IsFocusedProperty =
            BindableProperty.Create(nameof(IsFocused), typeof(bool), typeof(FocusBehavior), false, propertyChanged: IsFocusChanged);

        private static void IsFocusChanged(BindableObject bindable, object oldvalue, object newvalue)
        {
            var behavior = bindable as FocusBehavior;
            behavior?.FocusChanged((bool)newvalue);
        }

        #endregion

        #region OnAttachedTo

        protected override void OnAttachedTo(InputView bindable)
        {
            base.OnAttachedTo(bindable);
            bindable.BindingContextChanged += BindableContextChanged;

            _inputView = bindable;
        }

        #endregion

        #region OnDetachingFrom

        protected override void OnDetachingFrom(InputView bindable)
        {
            base.OnDetachingFrom(bindable);
            bindable.BindingContextChanged -= BindableContextChanged;

            _inputView = null;
        }

        #endregion

        #region Methods

        private void BindableContextChanged(object sender, EventArgs e)
        {
            var bindable = sender as InputView;
            BindingContext = bindable?.BindingContext;
        }

        public void FocusChanged(bool value)
        {
            if (value)
                _inputView?.Focus();
            else
                _inputView?.Unfocus();
        }

        #endregion
    }
}
