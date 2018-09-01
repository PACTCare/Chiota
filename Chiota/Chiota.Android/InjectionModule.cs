namespace Chiota.Droid
{
  using Autofac;

  using Chiota.Droid.Persistence;
  using Chiota.Droid.Services;
  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Repository;
  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.Services.Iota.Repository;

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
      builder.RegisterType<SqlLiteTransactionCache>().As<ITransactionCache>();
      builder.RegisterType<SqlLiteTransactionCache>().As<AbstractSqlLiteTransactionCache>();

      // This lines will be merged soon
      builder.RegisterType<SqlLiteContactRepository>().As<IContactRepository>().PropertiesAutowired();
      builder.RegisterType<SqlLiteContactRepository>().As<AbstractSqlLiteContactRepository>().PropertiesAutowired();
    }
  }
}
