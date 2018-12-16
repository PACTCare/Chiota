#region References

using System;
using Xamarin.Forms;

#endregion

namespace Chiota.Behaviors
{
    public class EntryBehaviors : Behavior<Entry>
    {
        #region Attributes

        private Entry _entry;

        #endregion

        #region IsFocused

        /// <summary>
        /// Get or set the animation of the element.
        /// </summary>
        public bool IsFocused
        {
            get => (bool)GetValue(IsFocusedProperty);
            set => SetValue(IsFocusedProperty, value);
        }

        /// <summary>
        /// IsAnimated property of the elment.
        /// </summary>
        public static readonly BindableProperty IsFocusedProperty = BindableProperty.Create(
            nameof(IsFocused), typeof(bool), typeof(EntryBehaviors), false, propertyChanged: OnFocusChanged);

        private static void OnFocusChanged(BindableObject bindable, object oldValue, object newValue)
        {
            var entry = bindable as EntryBehaviors;
            entry?.FocusChanged((bool) newValue);
        }

        public void FocusChanged(bool value)
        {
            if (value)
                _entry.Focus();
            else
                _entry.Unfocus();
        }

        #endregion

        #region OnAttachedTo

        protected override void OnAttachedTo(Entry bindable)
        {
            base.OnAttachedTo(bindable);
            bindable.BindingContextChanged += BindableContextChanged;
            bindable.Focused += BindableFocused;
            bindable.Unfocused += BindableUnfocused;

            _entry = bindable;
        }

        #endregion

        #region OnDetachingFrom

        protected override void OnDetachingFrom(Entry bindable)
        {
            base.OnDetachingFrom(bindable);
            bindable.BindingContextChanged -= BindableContextChanged;
            bindable.Focused -= BindableFocused;
            bindable.Unfocused -= BindableUnfocused;

            _entry = null;
        }

        #endregion

        #region Methods

        #region BindableContextChanged

        private void BindableContextChanged(object sender, EventArgs e)
        {
            var bindable = sender as Entry;
            BindingContext = bindable?.BindingContext;
        }

        #endregion

        #region BindableFocused

        private void BindableFocused(object sender, FocusEventArgs e)
        {
            IsFocused = true;
        }

        #endregion

        #region BindableUnfocused

        private void BindableUnfocused(object sender, FocusEventArgs e)
        {
            IsFocused = false;
        }

        #endregion

        #endregion
    }
}
