namespace Chiota.ViewModels.Classes
{
  using Autofac;

  using Chiota.ViewModels.Authentication;

  public class ViewModelInjectionModule : Module
  {
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<SetUserViewModel>().As<SetUserViewModel>().PropertiesAutowired();
    }
  }
}