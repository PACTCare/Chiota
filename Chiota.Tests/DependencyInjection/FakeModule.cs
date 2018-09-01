namespace Chiota.Tests.DependencyInjection
{
  using Autofac;

  using Chiota.Persistence;
  using Chiota.Tests.Repository;

  using Tangle.Net.Repository;

  internal class FakeModule : Module
  {
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<InMemoryIotaRepository>().As<IIotaRepository>();
      builder.RegisterType<SqlLiteContactRepositoryStub>().As<AbstractSqlLiteContactRepository>().PropertiesAutowired();
    }
  }
}
