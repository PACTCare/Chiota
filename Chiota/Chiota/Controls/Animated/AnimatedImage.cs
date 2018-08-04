using System;
using System.Collections.Generic;
using System.Text;
using Xamarin.Forms;

namespace Chiota.Controls.Animated
{
    public class AnimatedImage : Image
    {
        #region IsAnimated

        /// <summary>
        /// Get or set the animation of the element.
        /// </summary>
        public bool IsAnimated
        {
            get => (bool)GetValue(IsAnimatedProperty);
            set => SetValue(IsAnimatedProperty, value);
        }

        /// <summary>
        /// IsAnimated property of the elment.
        /// </summary>
        public static readonly BindableProperty IsAnimatedProperty = BindableProperty.Create(
            nameof(IsAnimated), typeof(bool), typeof(AnimatedImage), false, propertyChanged: OnAnimated);

        #endregion

        #region Animation

        /// <summary>
        /// Get or set the art of the animation for the element.
        /// </summary>
        public Animations Animation
        {
            get => (Animations)GetValue(AnimationProperty);
            set => SetValue(AnimationProperty, value);
        }

        /// <summary>
        /// Animation property of the elment.
        /// </summary>
        public static readonly BindableProperty AnimationProperty = BindableProperty.Create(
            nameof(Animation), typeof(Animations), typeof(AnimatedImage), Animations.Undefined, propertyChanged: OnAnimated);

        #endregion

        #region RotationValue

        /// <summary>
        /// Get or set the rotation value of the animation for the element.
        /// </summary>
        public double RotationValue
        {
            get => (double)GetValue(RotationValueProperty);
            set => SetValue(RotationValueProperty, value);
        }

        /// <summary>
        /// Rotation property of the elment.
        /// </summary>
        public static readonly BindableProperty RotationValueProperty = BindableProperty.Create(
            nameof(RotationValue), typeof(double), typeof(AnimatedImage), 1.0, propertyChanged: OnAnimated);

        #endregion

        #region Interval

        /// <summary>
        /// Get or set the interval of the animation for the element.
        /// </summary>
        public int Interval
        {
            get => (int)GetValue(IntervalProperty);
            set => SetValue(IntervalProperty, value);
        }

        /// <summary>
        /// Interval property of the element.
        /// </summary>
        public static readonly BindableProperty IntervalProperty = BindableProperty.Create(
            nameof(Interval), typeof(int), typeof(AnimatedImage), 250);

        #endregion

        #region Methods

        /// <summary>
        /// IsAnimation changed status.
        /// </summary>
        /// <param name="bindable"></param>
        /// <param name="oldvalue"></param>
        /// <param name="newvalue"></param>
        private static void OnAnimated(BindableObject bindable, object oldvalue, object newvalue)
        {
            var image = bindable as AnimatedImage;
            image?.OnAnimated();
        }

        /// <summary>
        /// IsAnimation changed status.
        /// </summary>
        protected void OnAnimated()
        {
            if (!IsAnimated || Animation == Animations.Undefined) return;

            Device.StartTimer(TimeSpan.FromMilliseconds(Interval), () =>
            {
                switch (Animation)
                {
                    case Animations.Rotation:
                        Rotation += RotationValue;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                return IsAnimated;
            });
        }

        #endregion
    }
}
