#region References

using System;
using Xamarin.Forms;

#endregion

namespace Chiota.Behaviors
{
    public class FocusBehavior : Behavior<View>
    {
        #region Attributes

        private View _view;

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

        protected override void OnAttachedTo(View bindable)
        {
            base.OnAttachedTo(bindable);
            bindable.BindingContextChanged += BindableContextChanged;

            _view = bindable;
        }

        #endregion

        #region OnDetachingFrom

        protected override void OnDetachingFrom(View bindable)
        {
            base.OnDetachingFrom(bindable);
            bindable.BindingContextChanged -= BindableContextChanged;

            _view = null;
        }

        #endregion

        #region Methods

        private void BindableContextChanged(object sender, EventArgs e)
        {
            var bindable = sender as View;
            BindingContext = bindable?.BindingContext;
        }

        public void FocusChanged(bool value)
        {
            if (value)
                _view?.Focus();
            else
                _view?.Unfocus();
        }

        #endregion
    }
}
