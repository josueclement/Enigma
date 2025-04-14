using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Enigma.PublicKey;
using Enigma.WpfApp.Services;
using Enigma.WpfApp.ViewModels;
using Enigma.WpfApp.ViewModels.Pages;
using Enigma.WpfApp.Views.Pages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;
using Wpf.Ui;
using Wpf.Ui.DependencyInjection;

namespace Enigma.WpfApp;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App
{
    private static readonly IHost Host = Microsoft.Extensions.Hosting.Host.CreateDefaultBuilder()
        .ConfigureServices((_1, services) =>
        {
            _ = services.AddLogging(builder =>
            {
                builder.ClearProviders();
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddNLog();
            });
            
            _ = services.AddNavigationViewPageProvider();
            
            // Theme manipulation
            _ = services.AddSingleton<IThemeService, ThemeService>();
            
            // Service containing navigation, same as INavigationWindow... but without window
            _ = services.AddSingleton<INavigationService, NavigationService>();
            _ = services.AddSingleton<NavigationHelperService>();
            
            _ = services.AddSingleton<MainWindow>();
            _ = services.AddSingleton<MainWindowViewModel>();
            
            _ = services.AddSingleton<HomePage>();
            _ = services.AddSingleton<HomePageViewModel>();
            _ = services.AddSingleton<RsaPage>();
            _ = services.AddSingleton<RsaPageViewModel>();
            _ = services.AddSingleton<MlDsaPage>();
            _ = services.AddSingleton<MlDsaPageViewModel>();
            _ = services.AddSingleton<MlKemPage>();
            _ = services.AddSingleton<MlKemPageViewModel>();
            _ = services.AddSingleton<BlockCiphersPage>();
            _ = services.AddSingleton<BlockCiphersPageViewModel>();
            _ = services.AddSingleton<StreamCiphersPage>();
            _ = services.AddSingleton<StreamCiphersPageViewModel>();
            _ = services.AddSingleton<KdfPage>();
            _ = services.AddSingleton<KdfPageViewModel>();
            _ = services.AddSingleton<HashPage>();
            _ = services.AddSingleton<HashPageViewModel>();
            _ = services.AddSingleton<SettingsPage>();
            _ = services.AddSingleton<SettingsPageViewModel>();
            
            _ = services.AddSingleton<IPublicKeyServiceFactory, PublicKeyServiceFactory>();
            
            _ = services.AddSingleton<IContentDialogService, ContentDialogService>();
        })
        .Build();
    
    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += CurrentDomainOnUnhandledException;
        TaskScheduler.UnobservedTaskException += TaskSchedulerOnUnobservedTaskException;
        Current.DispatcherUnhandledException += CurrentOnDispatcherUnhandledException;
        Host.Start();
        
        Services.GetRequiredService<MainWindow>().Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException -= CurrentDomainOnUnhandledException;
        TaskScheduler.UnobservedTaskException -= TaskSchedulerOnUnobservedTaskException;
        Current.DispatcherUnhandledException -= CurrentOnDispatcherUnhandledException;
        
        Host.StopAsync().Wait();
        Host.Dispose();
    }
    
    /// <summary>
    /// Get services
    /// </summary>
    public static IServiceProvider Services => Host.Services;

    private void CurrentDomainOnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var logger = Services.GetRequiredService<ILogger<App>>();
        if (e.ExceptionObject is Exception ex)
            logger.LogError(ex, "Unhandled exception");
        else
            logger.LogError("Unhandled exception");
        
        MessageBox.Show(e.ExceptionObject.ToString());
    }

    private void TaskSchedulerOnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Services.GetRequiredService<ILogger<App>>().LogError(e.Exception, "Unobserved task exception");
        MessageBox.Show(e.Exception.ToString());
    }

    private void CurrentOnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Services.GetRequiredService<ILogger<App>>().LogError(e.Exception, "Dispatcher unhandled exception");
        MessageBox.Show(e.Exception.ToString());
        e.Handled = true;
    }
}