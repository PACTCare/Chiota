namespace Chiota.Droid
{
  using Autofac;

  using Chiota.Droid.Persistence;
  using Chiota.Droid.Services;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.Services.Iota.Repository;
  using Chiota.ViewModels;

  using Tangle.Net.Repository;

  /// <inheritdoc />
  public class InjectionModule : Module
  {
    /// <inheritdoc />
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterInstance(new RepositoryFactory().Create()).As<IIotaRepository>();
      builder.RegisterType<ClipboardService>().As<IClipboardService>();

      // This lines will be merged soon
      builder.RegisterType<SqlLiteContactRepository>().As<IContactRepository>().PropertiesAutowired();
      builder.RegisterType<SqlLiteContactRepository>().As<AbstractSqlLiteContactRepository>().PropertiesAutowired();

      builder.RegisterType<TangleMessenger>().As<IMessenger>().PropertiesAutowired();

      builder.RegisterType<AddContactInteractor>().As<IUsecaseInteractor<AddContactRequest, AddContactResponse>>().PropertiesAutowired();
      builder.RegisterType<AddContactViewModel>().As<AddContactViewModel>().PropertiesAutowired();
    }
  }
}
