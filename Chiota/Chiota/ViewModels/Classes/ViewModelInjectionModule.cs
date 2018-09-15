namespace Chiota.ViewModels.Classes
{
  using Autofac;

  using Chiota.ViewModels.Authentication;
  using Chiota.ViewModels.BackUp;
  using Chiota.ViewModels.Help;

  public class ViewModelInjectionModule : Module
  {
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<LogInViewModel>().PropertiesAutowired();
      builder.RegisterType<NewSeedViewModel>().PropertiesAutowired();
      builder.RegisterType<SetPasswordViewModel>().PropertiesAutowired();
      builder.RegisterType<SetSeedViewModel>().PropertiesAutowired();
      builder.RegisterType<SetUserViewModel>().PropertiesAutowired();
      builder.RegisterType<WelcomeViewModel>().PropertiesAutowired();

      builder.RegisterType<BackUpViewModel>().PropertiesAutowired();
      builder.RegisterType<ConfirmSeedViewModel>().PropertiesAutowired();
      builder.RegisterType<PaperCopyViewModel>().PropertiesAutowired();
      builder.RegisterType<QrCodeViewModel>().PropertiesAutowired();
      builder.RegisterType<WriteSeedViewModel>().PropertiesAutowired();

      builder.RegisterType<SeedHelpViewModel>().PropertiesAutowired();

      builder.RegisterType<AddContactViewModel>().PropertiesAutowired();
      builder.RegisterType<ContactViewModel>().PropertiesAutowired();
      builder.RegisterType<SettingsViewModel>().PropertiesAutowired();
    }
  }
}